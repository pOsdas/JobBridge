import asyncio
from hashlib import sha256
from hmac import compare_digest
from html import escape
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
from urllib.error import URLError
from urllib.parse import parse_qsl
from urllib.request import Request as InternalRequest, urlopen

from cryptography.fernet import InvalidToken
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.websockets import WebSocket, WebSocketDisconnect
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

from .config import open_store
from .store import Rejected
from .telegram import Telegram, read_draft


COOKIE = "__Host-job_bridge"
STATIC_DIR = Path(__file__).with_name("static")
HH_SCREEN = "/hh-screen/vnc.html?autoconnect=1&resize=scale&path=%2Fhh-screen%2Fwebsockify"
STYLE = """
[hidden]{display:none!important}*{box-sizing:border-box}body{margin:0;font:16px/1.55 system-ui,sans-serif;color:#14232d;background:#f1f5f6}
main{max-width:850px;padding:24px;margin:auto}h1,h2{line-height:1.2}section{background:white;border:1px solid #cedbe0;
border-radius:12px;padding:20px;margin:16px 0}label{display:block;margin:12px 0}input:not([type=checkbox]),textarea{
display:block;width:100%;padding:9px;border:1px solid #8a9ca6;border-radius:5px;font:inherit}
textarea{min-height:135px}button,.link{display:inline-block;padding:8px 12px;margin:4px 6px 4px 0;border:0;border-radius:5px;
background:#08515b;color:#fff;font:inherit;text-decoration:none;cursor:pointer}.secondary{background:#425a65}
a{color:#064e63}.inline{display:inline}.notice{border-left:4px solid #0b7480;padding:8px 12px;background:#e6f4f4}
li{margin-bottom:7px;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0f5f7;padding:12px}
"""


def page(title, content, status=200):
    return HTMLResponse(f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#08515b">
<link rel="icon" href="/favicon.ico?v=1" sizes="16x16 32x32 48x48">
<link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32.png?v=1">
<link rel="icon" type="image/svg+xml" sizes="any" href="/assets/favicon.svg?v=1">
<link rel="apple-touch-icon" sizes="180x180" href="/assets/apple-touch-icon.png?v=1">
<title>{escape(title)} · Job Bridge</title><style>{STYLE}</style></head>
<body><main><h1>{escape(title)}</h1>{content}</main></body></html>""", status_code=status, headers={
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        "Referrer-Policy": "same-origin",
        "X-Frame-Options": "DENY",
    })


def button(path, label):
    return f'<form class="inline" action="{path}" method="post"><button>{escape(label)}</button></form>'


def error_page(message, status=400):
    return page("Job Bridge", f'<p class="notice">{escape(message)}</p><p><a href="/">К панели</a></p>', status)


def hh_request(action="status"):
    method = "GET" if action == "status" else "POST"
    try:
        with urlopen(InternalRequest(f"http://hh:8780/{action}", method=method), timeout=1) as response:
            return json.loads(response.read(4096))
    except (OSError, URLError, ValueError):
        return {"state": "unavailable", "busy": False}


async def read_form(request, origin):
    if request.headers.get("origin") != origin:
        raise Rejected("Обнови панель и повтори действие с этого сайта.")
    if request.headers.get("content-type", "").split(";")[0] != "application/x-www-form-urlencoded":
        raise Rejected("Неподдерживаемая форма.")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 64 * 1024:
            raise Rejected("Форма слишком большая.")
    try:
        return dict(parse_qsl(body.decode("ascii"), keep_blank_values=True, errors="strict", max_num_fields=8))
    except (ValueError, UnicodeError):
        raise Rejected("Некорректная форма.") from None


STATUS = {
    "off": "Автовход не настроен.",
    "paused": "Автовход приостановлен владельцем.",
    "checking": "Проверяю сессию hh.ru.",
    "signed_in": "Сессия hh.ru активна.",
    "requested": "Выполняется вход. Экран браузера временно закрыт.",
    "restored": "Вход восстановлен.",
    "manual": "hh.ru запросил дополнительную проверку или изменил форму. Требуется проверка владельцем.",
    "mail": "Почта не приняла подключение или код не получен. Проверь настройку почты.",
    "cooldown": "Действует пауза перед повторным запросом кода.",
    "network": "Не удалось проверить сессию hh.ru. Проверка повторится.",
    "unavailable": "Сервис автовхода сейчас недоступен.",
}


def create_app(store, host):
    origin = f"https://{host}"
    telegram = Telegram(store)

    def session_role(connection):
        return store.role(connection.cookies.get(COOKIE))

    async def browser_access(connection):
        role = session_role(connection)
        if role not in ("owner", "agent"):
            return False
        if role == "agent" and store.get("hh_shared") != "1":
            return False
        state = await asyncio.to_thread(hh_request)
        return not state["busy"] and (role == "owner" or state["state"] != "unavailable")

    async def home(request):
        role = session_role(request)
        if not role:
            return page("Вход в Job Bridge", """
<section><form method="post" action="/login">
<label>Одноразовый код доступа к панели <input name="code" type="password" maxlength="32" autocomplete="off" required></label>
<button>Войти</button></form></section>""")
        status = await asyncio.to_thread(hh_request)
        shared = store.get("hh_shared") == "1"
        hh = f'<p class="notice">{escape(STATUS.get(status["state"], STATUS["unavailable"]))}</p>'
        if not status["busy"] and (role == "owner" or (shared and status["state"] != "unavailable")):
            hh += f'<a class="link" href="{HH_SCREEN}">Открыть браузер hh.ru</a>'
        if role == "owner" or shared:
            hh += button("/hh/check", "Проверить вход")
        if role == "owner":
            hh += button("/hh/share", "Закрыть браузер для помощника" if shared else "Открыть браузер для помощника")
            hh += button("/revoke", "Отозвать доступ помощника")
        statuses = {"sent": "отправлено", "failed": "отклонено", "sending": "в обработке", "unknown": "нужна сверка"}
        history = "".join(
            f"<li>№{item['id']} · {item['day']} · {escape(item['recipient'])} · "
            f"{escape(statuses[item['status']])} · {escape(item['vacancy'])}"
            f"{' · ID ' + str(item['message_id']) if item['message_id'] is not None else ''}</li>"
            for item in store.recent()
        )
        tg = "подключён" if store.get("tg_session") else "ожидает подключения"
        attachment = "доступно" if store.resume.is_file() else "ещё не загружено"
        return page("Job Bridge", f"""
<section><h2>hh.ru</h2>{hh}</section>
<section><h2>Отклик в Telegram</h2><p>Telegram {tg}. Резюме PDF {attachment}.</p>
<form method="post" action="/telegram/preview">
<label>Получатель <input name="recipient" placeholder="@username или self для теста" maxlength="33" required></label>
<label>Ссылка на вакансию <input type="url" name="vacancy" maxlength="1024"></label>
<label>Текст отклика <textarea name="message" maxlength="4096" required></textarea></label>
<label><input type="checkbox" name="attach" value="1"> Приложить resume.pdf</label>
<button>Предпросмотр</button></form></section>
<section><h2>Последние отправки</h2>{f'<ol>{history}</ol>' if history else '<p>Журнал пуст.</p>'}</section>
{button("/logout", "Выйти из панели")}""")

    async def post(request: Request):
        path = request.url.path
        try:
            fields = await read_form(request, origin)
            token = request.cookies.get(COOKIE)
            role = store.role(token)
            if path == "/login":
                try:
                    client_ip = str(ip_address(request.headers.get("x-bridge-client-ip", "")))
                except ValueError:
                    client_ip = request.client.host if request.client else "unknown"
                if not store.allow_login(client_ip):
                    response = error_page("Слишком много попыток входа. Подожди минуту.", 429)
                    response.headers["Retry-After"] = "60"
                    return response
                code = fields.get("code", "").strip()
                redeemed = store.redeem(code, token) if re.fullmatch(r"[A-Za-z0-9_-]{32}", code) else None
                if not redeemed:
                    return error_page("Одноразовый код неверен, истёк или уже использован.", 403)
                response = RedirectResponse("/", status_code=303)
                response.set_cookie(COOKIE, redeemed[0], max_age=redeemed[1], secure=True, httponly=True, samesite="strict")
                return response
            if not role:
                return error_page("Сначала войди в панель.", 403)
            if path == "/logout":
                store.logout(token)
                response = RedirectResponse("/", status_code=303)
                response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="strict")
                return response
            if path in ("/hh/share", "/revoke"):
                if role != "owner":
                    return error_page("Это действие доступно владельцу.", 403)
                if path == "/hh/share":
                    store.set("hh_shared", "0" if store.get("hh_shared") == "1" else "1")
                else:
                    store.revoke_agents()
                return RedirectResponse("/", status_code=303)
            if path == "/hh/check":
                if role != "owner" and store.get("hh_shared") != "1":
                    return error_page("Владелец закрыл доступ к hh.ru.", 403)
                await asyncio.to_thread(hh_request, "check")
                return RedirectResponse("/", status_code=303)
            draft = read_draft(fields)
            fingerprint = sha256(json.dumps([token, draft.recipient, draft.vacancy, draft.message, draft.attach]).encode()).digest()
            if path == "/telegram/preview":
                proof = store.cipher.encrypt(fingerprint).decode()
                if draft.attach and not store.resume.is_file():
                    raise Rejected("На VPS ещё не загружено резюме PDF.")
                return page("Проверь отклик", f"""
<section><p>Получатель: <b>{escape(draft.recipient)}</b></p>
<p>Вакансия: {escape(draft.vacancy) or 'тестовая отправка'}</p><p>PDF: {'да' if draft.attach else 'нет'}</p>
<pre>{escape(draft.message)}</pre><form method="post" action="/telegram/send">
<input type="hidden" name="recipient" value="{escape(draft.recipient)}">
<input type="hidden" name="vacancy" value="{escape(draft.vacancy)}">
<textarea name="message" hidden>{escape(draft.message)}</textarea>
<input type="hidden" name="attach" value="{int(draft.attach)}">
<input type="hidden" name="proof" value="{proof}">
<button>Отправить в Telegram</button></form><p><a href="/">Отмена</a></p></section>""")
            try:
                sealed = store.cipher.decrypt(fields.get("proof", "").encode(), ttl=900)
            except InvalidToken:
                raise Rejected("Открой предпросмотр заново перед отправкой.") from None
            if not compare_digest(sealed, fingerprint):
                raise Rejected("Отклик изменился. Открой предпросмотр заново.")
            delivery, message, folder_notice = await telegram.send(
                draft, authorize=lambda: store.role(token) in ("owner", "agent"),
            )
            folder_result = f'<p class="notice">{escape(folder_notice)}</p>' if folder_notice else ""
            return page("Telegram подтвердил отправку",
                        f'<p>Запись №{delivery}. ID сообщения {message}.</p>{folder_result}<p><a href="/">К панели</a></p>')
        except Rejected as exc:
            return error_page(str(exc))

    async def hh_auth(request):
        if await browser_access(request):
            return Response(status_code=204)
        return PlainTextResponse("Доступ к экрану hh.ru закрыт. Вернись в панель.", status_code=403)

    async def screen(ws: WebSocket):
        if ws.headers.get("origin") != origin or not await browser_access(ws):
            await ws.close(code=1008)
            return
        protocol = "binary" if "binary" in ws.scope["subprotocols"] else None
        try:
            async with connect("ws://hh:6080/websockify", subprotocols=["binary"], proxy=None,
                               open_timeout=3, max_size=8 * 1024 * 1024) as upstream:
                await ws.accept(subprotocol=protocol)

                async def from_viewer():
                    while True:
                        await upstream.send(await ws.receive_bytes())

                async def from_browser():
                    async for data in upstream:
                        if not isinstance(data, bytes):
                            break
                        await ws.send_bytes(data)

                async def watch_access():
                    while await browser_access(ws):
                        await asyncio.sleep(1)

                tasks = [asyncio.create_task(coro()) for coro in (from_viewer, from_browser, watch_access)]
                try:
                    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
        except (OSError, TimeoutError, WebSocketDisconnect, WebSocketException):
            pass
        try:
            await ws.close(code=1008)
        except (RuntimeError, WebSocketDisconnect):
            pass

    async def health(request):
        return PlainTextResponse("ok")

    async def favicon(request):
        return FileResponse(STATIC_DIR / "favicon.ico", media_type="image/vnd.microsoft.icon")

    forms = ("/login", "/logout", "/revoke", "/hh/share", "/hh/check", "/telegram/preview", "/telegram/send")
    return Starlette(middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=[host, "127.0.0.1"])], routes=[
        Route("/", home), Route("/health", health), Route("/internal/hh-access", hh_auth),
        Route("/favicon.ico", favicon),
        Mount("/assets", app=StaticFiles(directory=STATIC_DIR), name="assets"),
        *(Route(path, post, methods=["POST"]) for path in forms),
        WebSocketRoute("/hh-screen/websockify", screen),
    ])


app = create_app(open_store(), os.environ["BRIDGE_HOST"]) if "BRIDGE_HOST" in os.environ else None
