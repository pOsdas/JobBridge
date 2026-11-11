import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from email.message import EmailMessage
import json
import os
from pathlib import Path
import re
import shutil
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet
from playwright.sync_api import sync_playwright
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from telethon import functions, types
from telethon.types import Message, PeerUser, User

from auth import hh_auth
from bridge import telegram, web
from bridge.store import Rejected, Store


class PortalTests(unittest.TestCase):
    def test_websocket_rejects_missing_cookie_wrong_origin_and_unshared_agent(self):
        with patch.object(web, "connect") as upstream:
            with self.assertRaises(WebSocketDisconnect):
                with self.client.websocket_connect('/hh-screen/websockify', headers={'Origin': self.origin}):
                    pass
            self.post('/login', {'code': self.store.issue('agent')})
            with self.assertRaises(WebSocketDisconnect):
                with self.client.websocket_connect('/hh-screen/websockify', headers={'Origin': self.origin}):
                    pass
            self.store.set('hh_shared', '1')
            with self.assertRaises(WebSocketDisconnect):
                with self.client.websocket_connect('/hh-screen/websockify', headers={'Origin': 'https://attacker.invalid'}):
                    pass
            upstream.assert_not_called()

    def test_static_assets_do_not_expose_code_or_secrets(self):
        for path in ['/assets/%2e%2e/web.py', '/assets/.env', '/assets/../config.py', '/.env', '/secrets/hh.key', '/data/resume.pdf']:
            self.assertEqual(self.client.get(path).status_code, 404, path)
        self.assertEqual(self.client.get('/assets/favicon.svg').status_code, 200)

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Store(Path(tmp.name), Fernet.generate_key(), daily_limit=8)
        self.origin = "https://jobs.example.test"
        mock = patch.object(web, "hh_request", return_value={"state": "off", "busy": False})
        mock.start()
        self.addCleanup(mock.stop)
        self.client = TestClient(web.create_app(self.store, "jobs.example.test"), base_url=self.origin)
        self.addCleanup(self.client.close)

    def post(self, path, data=None):
        return self.client.post(path, headers={"Origin": self.origin, "Content-Type": "application/x-www-form-urlencoded"}, data=data or {},
                                follow_redirects=False)

    def test_one_time_code_and_csrf(self):
        code = self.store.issue("agent")
        self.assertEqual(self.client.get("/").headers["Referrer-Policy"], "same-origin")
        wrong_origin = self.client.post("/login", headers={"Origin": "https://wrong.example.test"},
                                        data={"code": code})
        self.assertEqual(wrong_origin.status_code, 400)
        null_origin = self.client.post("/login", headers={"Origin": "null"}, data={"code": code})
        self.assertEqual(null_origin.status_code, 400)
        absent_origin = self.client.post("/login", data={"code": code})
        self.assertEqual(absent_origin.status_code, 400)
        signed_in = self.post("/login", {"code": code})
        self.assertEqual(signed_in.status_code, 303)
        self.assertIn("HttpOnly", signed_in.headers["set-cookie"])
        self.assertIn("Secure", signed_in.headers["set-cookie"])
        self.assertEqual(self.post("/login", {"code": code}).status_code, 403)

    def test_login_rate_limit_and_host_check(self):
        with patch("bridge.store.time.time", return_value=1800000000):
            code = self.store.issue("owner")
            for _ in range(20):
                self.assertEqual(self.post("/login", {"code": "invalid"}).status_code, 403)
            self.assertEqual(self.post("/login", {"code": code}).status_code, 429)
            response = self.client.post("/login", headers={
                "Origin": self.origin, "X-Bridge-Client-IP": "192.0.2.20",
            }, data={"code": code}, follow_redirects=False)
            self.assertEqual(response.status_code, 303)
        self.assertEqual(self.client.get("/", headers={"Host": "wrong.example.test"}).status_code, 400)

    def test_owner_only_browser_share_and_agent_revocation(self):
        agent = self.store.issue("agent")
        self.assertEqual(self.post("/login", {"code": agent}).status_code, 303)
        self.assertEqual(self.client.get("/internal/hh-access").status_code, 403)
        self.assertEqual(self.post("/hh/share").status_code, 403)
        owner = TestClient(self.client.app, base_url=self.origin)
        self.addCleanup(owner.close)
        headers = {"Origin": self.origin, "Content-Type": "application/x-www-form-urlencoded"}
        owner.post("/login", headers=headers, data={"code": self.store.issue("owner")})
        owner.post("/hh/share", headers=headers, content=b"")
        self.assertEqual(self.client.get("/internal/hh-access").status_code, 204)
        with patch.object(web, "hh_request", return_value={"state": "requested", "busy": True}):
            self.assertEqual(self.client.get("/internal/hh-access").status_code, 403)
            self.assertEqual(owner.get("/internal/hh-access").status_code, 403)
        owner.post("/revoke", headers=headers, content=b"")
        self.assertEqual(self.client.get("/internal/hh-access").status_code, 403)
        self.assertIn("Одноразовый код", self.client.get("/").text)

    def test_preview_proof_is_required_and_binds_message(self):
        self.post("/login", {"code": self.store.issue("agent")})
        values = {"recipient": "@example_user", "vacancy": "https://hh.ru/vacancy/345?tracking=1",
                  "message": "Привет <script>!"}
        preview = self.post("/telegram/preview", values)
        self.assertIn("&lt;script&gt;", preview.text)
        self.assertNotIn("<script>", preview.text)
        self.assertIn("https://hh.ru/vacancy/345", preview.text)
        self.assertEqual(self.post("/telegram/send", values).status_code, 400)
        values["proof"] = re.search(r'name="proof" value="([^"]+)"', preview.text)[1]
        with patch.object(web.Telegram, "send", return_value=(10, 23, "Чат добавлен в папку «Отклики».")) as send:
            self.assertEqual(self.post("/telegram/send", values | {"message": "Другой текст"}).status_code, 400)
            send.assert_not_called()
            result = self.post("/telegram/send", values)
            self.assertEqual(result.status_code, 200)
            self.assertIn("ID сообщения 23", result.text)
            self.assertIn("Чат добавлен в папку «Отклики».", result.text)


class DeliveryTests(unittest.TestCase):
    def test_saved_messages_text_then_pdf_with_empty_vacancy(self):
        from unittest.mock import AsyncMock
        client = MockTelegram()
        client.get_me = AsyncMock(return_value=User(id=123))
        self.store.resume.write_bytes(b"%PDF-1.7 local-test")
        draft = telegram.Draft("self", "", "Проверка", False)
        service = telegram.Telegram(self.store)
        with patch.object(telegram, "new_client", return_value=client):
            asyncio.run(service.send(draft))
            asyncio.run(service.send(replace(draft, attach=True)))
        self.assertEqual(client.send_count, 2)
        self.assertEqual([r["status"] for r in self.store.recent()], ["sent", "sent"])
        self.assertEqual(client.folder_reads, 0)

    def test_revoked_queued_send_never_contacts_telegram(self):
        async def scenario():
            service = telegram.Telegram(self.store)
            token, _ = self.store.redeem(self.store.issue("agent"))
            await service.lock.acquire()
            task = asyncio.create_task(service.send(
                self.draft, authorize=lambda: self.store.role(token) == "agent"))
            await asyncio.sleep(0)
            self.store.revoke_agents()
            service.lock.release()
            with self.assertRaisesRegex(Rejected, "Доступ отозван"):
                await task
        with patch.object(telegram, "new_client") as client:
            asyncio.run(scenario())
            client.assert_not_called()

    def test_revocation_during_history_check_stops_delivery(self):
        client = MockTelegram()
        service = telegram.Telegram(self.store)
        token, _ = self.store.redeem(self.store.issue("agent"))
        async def history(_client, _peer):
            self.store.revoke_agents()
        with patch.object(telegram, "new_client", return_value=client), patch.object(telegram, "ensure_new_contact", history):
            with self.assertRaisesRegex(Rejected, "Доступ отозван"):
                asyncio.run(service.send(self.draft, authorize=lambda: self.store.role(token) == "agent"))
        self.assertEqual(client.send_count, 0)
        self.assertEqual(self.store.recent(), [])

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Store(Path(tmp.name), Fernet.generate_key(), daily_limit=8)
        encrypted = self.store.cipher.encrypt(json.dumps({"id": 1, "hash": "x", "session": "mock"}).encode())
        self.store.set("tg_session", encrypted.decode())
        self.draft = telegram.Draft("@example_user", "https://hh.ru/vacancy/1", "Тест", False)

    def test_duplicate_and_unknown_result(self):
        client = MockTelegram()
        client.history = [Message(id=2, peer_id=PeerUser(123), out=False)]
        service = telegram.Telegram(self.store)
        with patch.object(telegram, "new_client", return_value=client):
            delivery_id, message_id, notice = asyncio.run(service.send(self.draft))
            self.assertEqual((delivery_id, message_id), (1, 42))
            self.assertIn("Создай обычную папку «Отклики»", notice)
            with self.assertRaisesRegex(Rejected, "уже есть"):
                asyncio.run(service.send(replace(self.draft, recipient="@renamed_user", vacancy="https://hh.ru/vacancy/2")))
            client.fail = True
            another = replace(self.draft, recipient="@other_user")
            with self.assertRaisesRegex(Rejected, "неизвестен"):
                asyncio.run(service.send(another))
            with self.assertRaisesRegex(Rejected, "уже есть"):
                asyncio.run(service.send(replace(another, vacancy="https://hh.ru/vacancy/3")))
        self.assertEqual([row["status"] for row in self.store.recent()], ["unknown", "sent"])
        self.assertEqual(client.send_count, 2)
        self.assertEqual(client.folder_reads, 1)

    def test_confirmed_delivery_adds_chat_to_existing_folder_once(self):
        client = MockTelegram()
        pinned = types.InputPeerUser(42, 1)
        excluded = types.InputPeerUser(77, 1)
        folder = types.DialogFilter(
            id=4, title=types.TextWithEntities("Отклики", []), pinned_peers=[pinned],
            include_peers=[], exclude_peers=[excluded, types.InputPeerUser(123, 1)], groups=True,
        )
        client.folders = [types.DialogFilterDefault(), folder]
        with patch.object(telegram, "new_client", return_value=client):
            delivery_id, message_id, notice = asyncio.run(telegram.Telegram(self.store).send(self.draft))
        self.assertEqual((delivery_id, message_id), (1, 42))
        self.assertIn("Чат добавлен", notice)
        self.assertEqual(len(client.folder_updates), 1)
        request = client.folder_updates[0]
        self.assertEqual(request.id, 4)
        self.assertEqual(request.filter.include_peers, [types.InputPeerUser(123, 1)])
        self.assertEqual(request.filter.pinned_peers, [pinned])
        self.assertEqual(request.filter.exclude_peers, [excluded])
        self.assertTrue(request.filter.groups)
        self.assertIn("Чат уже в папке", asyncio.run(telegram.add_to_applications_folder(client, User(id=123))))
        self.assertEqual(len(client.folder_updates), 1)

    def test_folder_update_failure_keeps_confirmed_delivery(self):
        client = MockTelegram()
        client.folders = [types.DialogFilter(
            id=4, title=types.TextWithEntities("Отклики", []),
            pinned_peers=[], include_peers=[], exclude_peers=[], contacts=True,
        )]
        client.folder_error = OSError("connection closed")
        service = telegram.Telegram(self.store)
        with patch.object(telegram, "new_client", return_value=client):
            delivery_id, message_id, notice = asyncio.run(service.send(self.draft))
            with self.assertRaisesRegex(Rejected, "уже есть"):
                asyncio.run(service.send(self.draft))
        self.assertEqual((delivery_id, message_id), (1, 42))
        self.assertIn("не подтвердил добавление", notice)
        self.assertEqual(client.send_count, 1)
        self.assertEqual(self.store.recent()[0]["status"], "sent")

    def test_manual_outgoing_message_blocks_an_application_with_pdf(self):
        client = MockTelegram()
        client.history = [
            Message(id=2, peer_id=PeerUser(123), out=False),
            Message(id=1, peer_id=PeerUser(123), out=True),
        ]
        self.store.resume.write_bytes(b"%PDF-1.7")
        with patch.object(telegram, "new_client", return_value=client):
            with self.assertRaisesRegex(Rejected, "исходящее сообщение"):
                asyncio.run(telegram.Telegram(self.store).send(replace(self.draft, attach=True)))
        self.assertEqual(client.send_count, 0)
        self.assertEqual(self.store.recent(), [])

    def test_unavailable_history_stops_sending(self):
        client = MockTelegram()
        client.history_error = OSError("connection closed")
        with patch.object(telegram, "new_client", return_value=client):
            with self.assertRaisesRegex(Rejected, "проверить историю"):
                asyncio.run(telegram.Telegram(self.store).send(self.draft))
        self.assertEqual(client.send_count, 0)

    def test_two_concurrent_claims_for_one_user_allow_only_one_send(self):
        barrier = Barrier(2)

        def claim(vacancy):
            barrier.wait(timeout=3)
            try:
                self.store.claim("@example_user", 123, vacancy)
            except Rejected:
                return False
            return True

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(claim, ["https://hh.ru/vacancy/1", "https://hh.ru/vacancy/2"]))
        self.assertCountEqual(results, [True, False])

    def test_attachment_uses_utf16_limit(self):
        fields = {"recipient": "self", "message": "🙂" * 513, "attach": "1"}
        with self.assertRaisesRegex(Rejected, "1024"):
            telegram.read_draft(fields)
        self.assertTrue(telegram.read_draft(fields | {"message": "🙂" * 512}).attach)


class MockTelegram:
    def __init__(self):
        self.send_count = 0
        self.fail = False
        self.history = []
        self.history_error = None
        self.folders = []
        self.folder_reads = 0
        self.folder_updates = []
        self.folder_error = None

    async def connect(self):
        pass

    async def disconnect(self):
        pass

    async def is_user_authorized(self):
        return True

    async def get_entity(self, username):
        return User(id=456 if username == "@other_user" else 123, username=username)

    async def get_input_entity(self, peer):
        return types.InputPeerUser(peer.id, 1)

    async def __call__(self, request):
        if isinstance(request, functions.messages.GetDialogFiltersRequest):
            self.folder_reads += 1
            return types.messages.DialogFilters(filters=self.folders)
        if isinstance(request, functions.messages.UpdateDialogFilterRequest):
            bytes(request)
            self.folder_updates.append(request)
            if self.folder_error:
                raise self.folder_error
            return True
        raise AssertionError(f"Unexpected Telegram request {request!r}")

    async def iter_messages(self, peer):
        if self.history_error:
            raise self.history_error
        for message in self.history:
            yield message

    async def send_message(self, *_args, **_kwargs):
        self.send_count += 1
        if self.fail:
            raise TimeoutError
        return type("Sent", (), {"id": 42})()

    send_file = send_message


class MailTests(unittest.TestCase):
    def test_probe_accepts_own_profile_redirect_and_rejects_other_paths(self):
        page = MagicMock()
        page.url = "https://hh.ru/applicant/profile/me"
        page.goto.return_value.status = 200
        page.goto.return_value.ok = True
        page.get_by_role.return_value.first.is_visible.return_value = True
        page.locator.return_value.count.return_value = 0
        page.get_by_text.return_value.all.return_value = []
        self.assertTrue(hh_auth.checked_probe(page))
        page.get_by_role.return_value.first.is_visible.return_value = False
        with self.assertRaises(hh_auth.Halt):
            hh_auth.checked_probe(page)
        page.get_by_role.return_value.first.is_visible.return_value = True
        page.url = "https://hh.ru/applicant/profile/other"
        with self.assertRaises(hh_auth.Halt):
            hh_auth.checked_probe(page)

    def test_hh_html_code_after_preheader_padding_and_css(self):
        message = EmailMessage()
        message["From"] = "noreply@hh.ru"
        message["Subject"] = "Код подтверждения"
        message["Authentication-Results"] = "mx.google.com; dmarc=pass header.from=hh.ru"
        message.set_content(
            '<html><head><style>' + '.padding{margin:2026px;}' * 180 +
            '</style></head><body><div>Для входа на hh' +
            '\u200c\u00a0' * 1800 + '\u2800' * 500 +
            '</div><h1>Код подтверждения</h1><p>1212 — ваш код подтверждения email/входа для hh.ru</p>'
            '<p>Если нужна помощь</p><p>Написать в поддержку</p><p>Оставайтесь на связи</p>'
            '<p>Мобильное приложение</p><p>Вы получили это письмо, поскольку зарегистрированы на hh.ru</p>'
            '<p>ООО Хэдхантер, адрес 123456, дом 12, ОГРН 1234567890123. © 2000–2026</p></body></html>',
            subtype="html")
        self.assertEqual(hh_auth.extract_code(message.as_bytes(), "noreply@hh.ru"), "1212")

    def test_ambiguous_confirmation_codes_are_rejected(self):
        message = EmailMessage()
        message["From"] = "noreply@hh.ru"
        message["Subject"] = "Код подтверждения"
        message["Authentication-Results"] = "mx.google.com; dmarc=pass header.from=hh.ru"
        message.set_content("Код подтверждения: 1212 или 3434")
        self.assertIsNone(hh_auth.extract_code(message.as_bytes(), "noreply@hh.ru"))

    def test_mail_configuration_migrates_to_ciphertext_and_keeps_credentials(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            key_path = root / "hh.key"
            key = Fernet.generate_key()
            key_path.write_bytes(key)
            path = root / "config.json"
            original = {"hh_login": "hh@example.test", "mailbox": "mail@gmail.com", "app_password": "abcdefghijklmnop"}
            path.write_text(json.dumps(original))
            with patch.dict(os.environ, {"HH_KEY_FILE": str(key_path)}):
                self.assertEqual(hh_auth.read_config(path), original)
                self.assertNotIn(b"abcdefghijklmnop", path.read_bytes())
                self.assertEqual(hh_auth.read_config(path), original)
                self.assertEqual(json.loads(Fernet(key).decrypt(path.read_bytes())), original)
            encrypted = path.read_bytes()
            key_path.write_bytes(Fernet.generate_key())
            with patch.dict(os.environ, {"HH_KEY_FILE": str(key_path)}):
                with self.assertRaises(hh_auth.InvalidToken):
                    hh_auth.read_config(path)
            self.assertEqual(path.read_bytes(), encrypted)

    def test_code_requires_gmail_authentication_and_context(self):
        message = EmailMessage()
        message["From"] = "HeadHunter <noreply@hh.ru>"
        message["Subject"] = "Код для входа на hh.ru"
        message["Authentication-Results"] = "mx.google.com; dkim=pass header.i=@hh.ru header.s=mail"
        message.set_content("Код для входа: 1212\nНе передавайте его другим.")
        self.assertEqual(hh_auth.extract_code(message.as_bytes(), "noreply@hh.ru"), "1212")
        message.replace_header("Authentication-Results", "mx.google.com; dkim=pass header.i=@hh.ru.example")
        self.assertIsNone(hh_auth.extract_code(message.as_bytes(), "noreply@hh.ru"))
        message.replace_header("Authentication-Results", "mx.google.com; dmarc=pass header.from=hh.ru")
        message.replace_header("Subject", "Новости hh.ru")
        message.set_content("На сайте 2026 вакансий.")
        self.assertIsNone(hh_auth.extract_code(message.as_bytes(), "noreply@hh.ru"))


    def test_worker_reauthenticates_expired_profile(self):
        with TemporaryDirectory() as directory, patch.object(hh_auth, "AUTH_DIR", Path(directory)):
            worker = hh_auth.Worker()
            browser, context = MagicMock(), MagicMock()
            page = context.expect_page.return_value.__enter__.return_value.value
            settings = {"hh_login": "account@example.test"}
            with (
                patch.object(hh_auth, "checked_probe", side_effect=[False, True]),
                patch.object(hh_auth, "Gmail") as gmail,
                patch.object(hh_auth, "email_form") as login_form,
                patch.object(hh_auth, "code_fields") as fields,
                patch.object(hh_auth, "submit_code") as submit,
                patch.object(hh_auth, "challenge", return_value=False),
                patch.object(hh_auth.time, "sleep"),
            ):
                gmail.return_value.__enter__.return_value.next_code.return_value = "1212"
                self.assertEqual(worker.check(browser, context, settings), "restored")
                login_form.assert_called_once_with(page, settings["hh_login"])
                login_form.return_value.click.assert_called_once()
                submit.assert_called_once_with(page, fields.return_value, "1212")
                page.close.assert_called_once()
                self.assertTrue(worker.cooldown_path.is_file())

    def test_worker_does_not_request_a_second_code_during_cooldown(self):
        with TemporaryDirectory() as directory, patch.object(hh_auth, "AUTH_DIR", Path(directory)):
            worker = hh_auth.Worker()
            hh_auth.write_json(worker.cooldown_path, {"at": int(hh_auth.time.time())})
            with patch.object(hh_auth, "checked_probe", return_value=False), patch.object(hh_auth, "Gmail") as gmail:
                self.assertEqual(worker.check(MagicMock(), MagicMock(), {}), "cooldown")
                gmail.assert_not_called()


@unittest.skipUnless(os.environ.get("RUN_BROWSER_TESTS") == "1", "set RUN_BROWSER_TESTS=1 on a Chromium-capable host")
class BrowserTests(unittest.TestCase):
    def test_email_tab_with_hidden_radio(self):
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or shutil.which("chromium"),
                                       args=["--disable-setuid-sandbox"])
            page = browser.new_page()
            page.route("https://hh.ru/**", lambda route: route.fulfill(
                status=200, content_type="text/html", body='''<meta charset="utf-8">
                <h2>Почта</h2>
                <div data-qa="credential-type-switch">
                  <label for="mail">Почта
                    <input id="mail" type="radio" name="method" data-qa="credential-type-email" hidden
                        onchange="this.dataset.qa='credential-type-email checked'; document.getElementById('email').hidden=false">
                  </label>
                </div>
                <input id="email" data-qa="applicant-login-input-email" hidden>
                <button>Дальше</button>'''))
            page.goto(hh_auth.LOGIN)
            button = hh_auth.email_form(page, "test@example.test")
            self.assertTrue(page.locator("#mail").is_checked())
            self.assertEqual(page.locator("#email").input_value(), "test@example.test")
            self.assertTrue(button.is_enabled())
            browser.close()

    def test_probe_and_split_code_with_repeated_digits(self):
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or shutil.which("chromium"),
                                       args=["--disable-setuid-sandbox"])
            page = browser.new_page()
            state = {"signed_in": False}
            email_step = """
              <button onclick="this.remove(); login.hidden=false">Войти</button>
              <div id="login" hidden>
               <div data-qa="credential-type-switch"><label>Почта <input type="radio" name="method" data-qa="credential-type-email"></label></div>
               <input data-qa="applicant-login-input-email">
               <button onclick="this.parentElement.remove(); otp.hidden=false">Дальше</button>
              </div>
              <div id="otp" hidden><h2>Введите код из письма</h2>
               <input inputmode="numeric" maxlength="1"><input inputmode="numeric" maxlength="1">
               <input inputmode="numeric" maxlength="1"><input inputmode="numeric" maxlength="1">
               <button onclick="this.parentElement.dataset.sent=[...this.parentElement.querySelectorAll('input')].map(i=>i.value).join(''); this.parentElement.hidden=true;">Подтвердить</button>
              </div>"""

            def route(request):
                url = request.request.url
                if "/applicant/resumes" in url:
                    if state["signed_in"]:
                        request.fulfill(status=302, headers={"Location": "https://hh.ru/applicant/profile/me"})
                    else:
                        request.fulfill(status=403, content_type="text/html", body='<button data-qa="expand-login-by-password">Войти с паролем</button>')
                elif "/applicant/profile/me" in url:
                    request.fulfill(status=200, content_type="text/html", body='<meta charset="utf-8"><h1>Мои резюме</h1>')
                else:
                    request.fulfill(status=200, content_type="text/html", body='<meta charset="utf-8">' + email_step)

            page.route("https://hh.ru/**", route)
            self.assertFalse(hh_auth.checked_probe(page))
            page.goto(hh_auth.LOGIN)
            hh_auth.email_form(page, "test@example.test").click()
            hh_auth.submit_code(page, hh_auth.code_fields(page), "1212")
            self.assertEqual(page.locator("#otp").get_attribute("data-sent"), "1212")
            state["signed_in"] = True
            self.assertTrue(hh_auth.checked_probe(page))
            browser.close()


if __name__ == "__main__":
    unittest.main()
