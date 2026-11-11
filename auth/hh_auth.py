"""Check a persistent Chromium profile and recover it with an hh.ru email code."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from getpass import getpass
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import imaplib
import fcntl
import json
import os
from pathlib import Path
import re
import ssl
from tempfile import NamedTemporaryFile
from threading import Event, Thread
import time
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from playwright.sync_api import Error as BrowserError, sync_playwright


AUTH_DIR = Path(os.getenv("HH_AUTH_DIR", "/auth"))
HH = "https://hh.ru"
PROBE = f"{HH}/applicant/resumes"
LOGIN = f"{HH}/account/login?role=applicant"
CDP = "http://127.0.0.1:9222"
CHECK_INTERVAL = 600
RETRY_DELAY = 3600
MAIL_TIMEOUT = 180
SENDERS = ("noreply@hh.ru", "info@site.hh.ru")
CODE_TEXT = re.compile(r"(?:код[^\n]{0,70}(?:вход|письм|почт|подтвержд)|введите\s+код)", re.I)
CHALLENGE_TEXT = re.compile(r"(?:я\s+не\s+робот|вы\s+не\s+робот|введите\s+(?:символы|текст)\s+с\s+картинки|подтвердите,?\s+что\s+вы\s+человек|проверка\s+безопасности|подозрительн\w+\s+активност)", re.I)


class Halt(Exception):
    def __init__(self, state):
        self.state = state


def write_json(path, value):
    with NamedTemporaryFile(mode="w", dir=path.parent, encoding="utf-8", delete=False) as output:
        json.dump(value, output)
    os.replace(output.name, path)


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def config_cipher():
    return Fernet(Path(os.environ["HH_KEY_FILE"]).read_bytes().strip())


@contextmanager
def config_lock(path):
    descriptor = os.open(path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def save_config(path, config):
    payload = config_cipher().encrypt(json.dumps(config).encode())
    with NamedTemporaryFile(dir=path.parent, delete=False) as output:
        output.write(payload)
    os.replace(output.name, path)


def write_config(path, config):
    with config_lock(path):
        save_config(path, config)


def read_config(path):
    with config_lock(path):
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return {}
        if raw.lstrip().startswith(b"{"):
            config = json.loads(raw)
            save_config(path, config)
            return config
        return json.loads(config_cipher().decrypt(raw))


class PlainHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def authentic_hh(message):
    domain = r"(?:[a-z0-9-]+\.)*hh\.ru"
    for header in message.get_all("Authentication-Results", []):
        if not re.match(r"^\s*mx\.google\.com\s*;", header, re.I):
            continue
        for field in str(header).split(";")[1:]:
            dmarc = re.match(r"\s*dmarc=pass\b", field, re.I)
            dkim = re.match(r"\s*dkim=pass\b", field, re.I)
            if dmarc and re.search(rf"\bheader\.from={domain}(?:\s|$)", field, re.I):
                return True
            if dkim and re.search(rf"\bheader\.(?:i=[^\s]*@|d=){domain}(?:\s|$)", field, re.I):
                return True
        # Trust the first result Gmail prepended, not older results inside the message.
        return False
    return False


def extract_code(raw, sender):
    message = BytesParser(policy=policy.default).parsebytes(raw)
    if parseaddr(str(message.get("From", "")))[1].lower() != sender or not authentic_hh(message):
        return None
    subject = str(message.get("Subject", ""))
    part = message.get_body(preferencelist=("plain", "html"))
    body = part.get_content() if part else ""
    if not isinstance(body, str):
        return None
    if part and part.get_content_type() == "text/html":
        parser = PlainHTML()
        body = re.sub(r"<(head|style|script|template)\b[^>]*>.*?</\1\s*>", " ", body, flags=re.I | re.S)
        parser.feed(body)
        body = " ".join(parser.parts)
    body = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u2800]", "", body)
    body = re.sub(r"\s+", " ", body).strip()
    if not CODE_TEXT.search(subject + "\n" + body[:1800]):
        return None
    code = r"(?<![0-9])([0-9]{4,8})(?![0-9])"
    if CODE_TEXT.search(subject):
        from_subject = set(re.findall(code, subject))
        if len(from_subject) == 1:
            return from_subject.pop()
    nearby = set()
    for context in CODE_TEXT.finditer(body[:2500]):
        window = body[max(0, context.start() - 25):context.end() + 95]
        nearby.update(re.findall(code, window))
    return nearby.pop() if len(nearby) == 1 else None


class Gmail:
    def __init__(self, config):
        self.config = config
        self.client = None

    def __enter__(self):
        try:
            self.client = imaplib.IMAP4_SSL("imap.gmail.com", timeout=12, ssl_context=ssl.create_default_context())
            self.client.login(self.config["mailbox"], self.config["app_password"])
            if self.client.select("INBOX", readonly=True)[0] != "OK":
                raise Halt("mail")
            self.first_uid = int(self.client.response("UIDNEXT")[1][0])
            return self
        except (Halt, imaplib.IMAP4.error, OSError, TypeError, ValueError):
            self.__exit__()
            raise Halt("mail") from None

    def __exit__(self, *_args):
        if self.client:
            try:
                self.client.logout()
            except (imaplib.IMAP4.error, OSError):
                pass

    def next_code(self):
        try:
            self.client.noop()
            matches = []
            for sender in SENDERS:
                kind, rows = self.client.uid("search", None, "UID", f"{self.first_uid}:*", "FROM", sender)
                if kind != "OK":
                    raise Halt("mail")
                ids = [int(raw_uid) for raw_uid in rows[0].split() if int(raw_uid) >= self.first_uid]
                for uid in sorted(ids, reverse=True)[:5]:
                    kind, data = self.client.uid("fetch", str(uid), "(BODY.PEEK[]<0.98304>)")
                    if kind != "OK":
                        continue
                    raw = next((item[1] for item in data if isinstance(item, tuple)), b"")
                    code = extract_code(raw, sender)
                    if code:
                        matches.append((uid, code))
            return max(matches)[1] if matches else None
        except (imaplib.IMAP4.error, OSError, ValueError):
            raise Halt("mail") from None


def hh_path(url):
    result = urlsplit(url)
    if result.scheme != "https" or result.netloc != "hh.ru":
        raise Halt("manual")
    return result.path.rstrip("/")


def checked_probe(page):
    response = page.goto(PROBE, wait_until="domcontentloaded", timeout=20000)
    path = hh_path(page.url)
    if challenge(page):
        raise Halt("manual")
    if response is None or response.status >= 500:
        raise Halt("network")
    if path == "/account/login" and response.ok:
        return False
    if path in ("/applicant/resumes", "/applicant/profile/me"):
        logged_out = page.locator('[data-qa="expand-login-by-password"]:visible')
        logged_in = page.get_by_role("heading", name=re.compile(r"^(Мои резюме|Резюме|Профиль(?: соискателя)?)$", re.I))
        try:
            logged_out.or_(logged_in).first.wait_for(state="visible", timeout=8000)
        except BrowserError:
            raise Halt("manual") from None
        if logged_out.count():
            return False
        if response.ok and logged_in.first.is_visible():
            return True
    raise Halt("manual")


def challenge(page):
    text = page.get_by_text(CHALLENGE_TEXT)
    for element in text.all()[:5]:
        if element.is_visible():
            return True
    return page.locator('iframe[src*="captcha" i]:visible, input[name*="captcha" i]:visible').count() > 0


def email_form(page, login):
    if hh_path(page.url) != "/account/login" or challenge(page):
        raise Halt("manual")
    try:
        email_field = page.locator('input[data-qa="applicant-login-input-email"]')
        if not email_field.is_visible():
            email_label = page.locator('input[data-qa~="credential-type-email"]').locator("xpath=ancestor::label[1]").filter(visible=True)
            if not email_label.is_visible():
                page.get_by_role("button", name="Войти", exact=True).click(timeout=10000)
            email_label.click(timeout=10000)
        email_field.wait_for(state="visible", timeout=10000)
        email_field.fill(login, timeout=5000)
        submit = page.get_by_role("button", name="Дальше", exact=True)
        submit.wait_for(state="visible", timeout=5000)
        return submit
    except BrowserError:
        raise Halt("manual") from None


def code_fields(page):
    if hh_path(page.url) != "/account/login" or challenge(page):
        raise Halt("manual")
    if page.get_by_role("heading", name=re.compile("регистрац|созда(ть|ние) аккаунт", re.I)).count():
        raise Halt("manual")
    return page.locator(
        'input[data-qa="magritte-pincode-input-field"]:visible, '
        'input[autocomplete="one-time-code"]:visible, input[name="code"]:visible, '
        'input[name="otp"]:visible, input[data-qa*="otp" i]:visible, '
        'input[data-qa*="code-input" i]:visible, input[inputmode="numeric"]:visible'
    )


def submit_code(page, fields, code):
    if not any(item.is_visible() for item in page.get_by_text(CODE_TEXT).all()[:8]):
        raise Halt("manual")
    count = fields.count()
    if count == 1:
        fields.fill(code, timeout=4000)
    elif count == len(code) and all(item.get_attribute("maxlength") == "1" for item in fields.all()):
        for index, digit in enumerate(code):
            fields.nth(index).fill(digit, timeout=4000)
    else:
        raise Halt("manual")
    try:
        fields.first.wait_for(state="hidden", timeout=15000)
    except BrowserError:
        if hh_path(page.url) != "/account/login" or challenge(page):
            return
        button = page.get_by_role("button", name=re.compile(r"^(Подтвердить|Войти|Дальше)$"))
        if button.count() == 1 and button.is_enabled():
            button.click(timeout=4000)
            try:
                fields.first.wait_for(state="hidden", timeout=8000)
            except BrowserError:
                raise Halt("manual") from None
        else:
            raise Halt("manual")


class Worker:
    def __init__(self):
        self.wake = Event()
        self.status = {"state": "off", "busy": False, "updated_at": None}
        self.config_path = AUTH_DIR / "config.json"
        self.cooldown_path = AUTH_DIR / "last-request.json"
        self.paused_path = AUTH_DIR / "paused"
        self.block_path = AUTH_DIR / "manual"

    def show(self, state, busy=False):
        previous = self.status["state"]
        self.status = {"state": state, "busy": busy, "updated_at": datetime.now(timezone.utc).isoformat()}
        if not busy and state != previous:
            print(f"hh.ru: {state}", flush=True)

    def check(self, browser, context, config):
        self.show("checking")
        cdp = browser.new_browser_cdp_session()
        try:
            with context.expect_page(timeout=5000) as target:
                cdp.send("Target.createTarget", {"url": "about:blank", "background": True})
            page = target.value
        finally:
            cdp.detach()
        try:
            if checked_probe(page):
                return "signed_in"
            if time.time() - read_json(self.cooldown_path).get("at", 0) < RETRY_DELAY:
                return "cooldown"
            self.show("requested", busy=True)
            # Existing noVNC sockets revalidate access every second. Close those
            # sockets before entering the address or the code in Chromium.
            time.sleep(3)
            if self.paused_path.exists():
                return "paused"
            page.bring_to_front()
            with Gmail(config) as mail:
                page.goto(LOGIN, wait_until="domcontentloaded", timeout=20000)
                button = email_form(page, config["hh_login"])
                write_json(self.cooldown_path, {"at": int(time.time())})
                button.click(timeout=6000)
                print("hh.ru: waiting_code_form", flush=True)
                fields = code_fields(page)
                try:
                    fields.first.wait_for(state="visible", timeout=60000)
                except BrowserError:
                    raise Halt("manual") from None
                print("hh.ru: waiting_email_code", flush=True)
                deadline = time.monotonic() + MAIL_TIMEOUT
                while time.monotonic() < deadline:
                    if self.paused_path.exists():
                        return "paused"
                    if challenge(page):
                        raise Halt("manual")
                    code = mail.next_code()
                    if code:
                        print("hh.ru: code_received", flush=True)
                        submit_code(page, code_fields(page), code)
                        if challenge(page):
                            raise Halt("manual")
                        if checked_probe(page):
                            return "restored"
                        raise Halt("manual")
                    time.sleep(4)
                return "mail"
        finally:
            page.close()

    def run(self):
        while True:
            try:
                config = read_config(self.config_path)
                if not config:
                    self.show("off")
                elif self.paused_path.exists():
                    self.show("paused")
                elif self.block_path.exists():
                    self.show("manual")
                else:
                    with sync_playwright() as playwright:
                        browser = playwright.chromium.connect_over_cdp(CDP, timeout=8000)
                        if not browser.contexts:
                            raise Halt("network")
                        self.show(self.check(browser, browser.contexts[0], config))
            except Halt as exc:
                if exc.state == "manual":
                    self.block_path.touch(mode=0o600)
                self.show(exc.state)
            except (BrowserError, OSError, ValueError, KeyError, InvalidToken):
                # Playwright exceptions may include form arguments. Only log states.
                self.show("network")
            self.wake.wait(CHECK_INTERVAL)
            self.wake.clear()


def serve(worker):
    class Handler(BaseHTTPRequestHandler):
        def send_state(self):
            body = json.dumps(worker.status).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/status":
                self.send_state()
            else:
                self.send_error(404)

        def do_POST(self):
            if self.path == "/check":
                if not worker.status["busy"]:
                    worker.wake.set()
                self.send_state()
            else:
                self.send_error(404)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("0.0.0.0", 8780), Handler)
    Thread(target=server.serve_forever, daemon=True).start()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("run", "configure", "pause", "resume"))
    args = parser.parse_args()
    AUTH_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    worker = Worker()
    if args.command == "run":
        serve(worker)
        worker.run()
    elif args.command == "configure":
        login = input("Подтверждённая почта текущего аккаунта hh.ru: ").strip()
        mailbox = input("Gmail, который получает письма с кодами hh.ru: ").strip()
        password = getpass("Пароль приложения Gmail: ").replace(" ", "")
        if not login.isascii() or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", login):
            raise SystemExit("Нужна почта, привязанная к существующему аккаунту hh.ru.")
        if not mailbox.isascii() or not re.fullmatch(r"[^\s@]+@(?:gmail|googlemail)\.com", mailbox, re.I) or not re.fullmatch(r"[a-zA-Z0-9]{16}", password):
            raise SystemExit("Проверь Gmail и пароль приложения из 16 символов.")
        config = {"hh_login": login, "mailbox": mailbox, "app_password": password}
        try:
            with Gmail(config):
                pass
        except Halt:
            raise SystemExit("Gmail отклонил IMAP-вход. Проверь адрес и пароль приложения.") from None
        write_config(worker.config_path, config)
        worker.block_path.unlink(missing_ok=True)
        print("Автовход настроен. Нажми «Проверить вход» в панели или дождись следующей проверки.")
    elif args.command == "pause":
        worker.paused_path.touch(mode=0o600)
        print("Автовход приостановлен.")
    else:
        worker.paused_path.unlink(missing_ok=True)
        worker.block_path.unlink(missing_ok=True)
        print("Автовход возобновлён. Пауза после запроса кода сохранена.")


if __name__ == "__main__":
    main()
