import asyncio
from dataclasses import dataclass
from io import BytesIO
import json
import re
import time
from urllib.parse import urlsplit, urlunsplit

from telethon import TelegramClient, errors, functions, types
from telethon.sessions import StringSession

from .store import Rejected


APPLICATION_FOLDER = "Отклики"


@dataclass(frozen=True)
class Draft:
    recipient: str
    vacancy: str
    message: str
    attach: bool


def read_draft(fields):
    recipient = fields.get("recipient", "").strip().lower()
    if recipient != "self" and not re.fullmatch(r"@[a-z][a-z0-9_]{2,31}", recipient):
        raise Rejected("Укажи Telegram @username или self для теста в Избранном.")
    vacancy = fields.get("vacancy", "").strip()
    if vacancy or recipient != "self":
        if len(vacancy) > 1024 or re.search(r"[\s\\\x00-\x1f]", vacancy):
            raise Rejected("Укажи HTTPS-ссылку на вакансию.")
        try:
            url = urlsplit(vacancy)
            host = url.hostname
            if url.scheme != "https" or not host or url.username or url.password or url.port not in (None, 443):
                raise ValueError
        except ValueError:
            raise Rejected("Укажи HTTPS-ссылку на вакансию.") from None
        hh_vacancy = re.fullmatch(r"/vacancy/(\d+)/?", url.path)
        if hh_vacancy and (host == "hh.ru" or host.endswith(".hh.ru")):
            vacancy = f"https://hh.ru/vacancy/{hh_vacancy[1]}"
        else:
            vacancy = urlunsplit(("https", host, url.path or "/", url.query, ""))
    message = fields.get("message", "").strip()
    attach = fields.get("attach") == "1"
    limit = 1024 if attach else 4096
    if not message or len(message.encode("utf-16-le")) // 2 > limit or "\x00" in message:
        raise Rejected(f"Введи текст. Максимум {limit} знаков UTF-16 для выбранного режима.")
    return Draft(recipient, vacancy, message, attach)


def new_client(api_id, api_hash, session="", *, receive_updates=False):
    return TelegramClient(
        StringSession(session), api_id, api_hash,
        device_model="Job Bridge VPS", receive_updates=receive_updates,
        request_retries=0, connection_retries=1, auto_reconnect=False,
        flood_sleep_threshold=0, raise_last_call_error=True,
    )


async def ensure_new_contact(client, peer):
    try:
        async with asyncio.timeout(20):
            # Telegram ignores the sender filter in private chats. Use the
            # outgoing flag on messages from the available history instead.
            async for message in client.iter_messages(peer):
                if isinstance(message, types.Message) and message.out:
                    raise Rejected("В этом чате уже есть исходящее сообщение от твоего аккаунта. Повторный отклик пропущен.")
    except (Rejected, errors.FloodWaitError, errors.PeerFloodError):
        raise
    except Exception:
        raise Rejected("Не удалось проверить историю Telegram. Отклик не отправлен.") from None


async def add_to_applications_folder(client, peer):
    try:
        async with asyncio.timeout(10):
            input_peer = await client.get_input_entity(peer)
            result = await client(functions.messages.GetDialogFiltersRequest())
            matches = [folder for folder in result.filters
                       if isinstance(folder, types.DialogFilter) and folder.title.text == APPLICATION_FOLDER]
            if not matches:
                return f"Создай обычную папку «{APPLICATION_FOLDER}» в Telegram, чтобы новые чаты добавлялись туда автоматически."
            if len(matches) > 1:
                return f"Найдено несколько папок «{APPLICATION_FOLDER}». Для автодобавления оставь это имя у одной папки."

            folder = matches[0]
            already_listed = any(getattr(item, "user_id", None) == peer.id
                                 for item in (*folder.include_peers, *folder.pinned_peers))
            exclusions = [item for item in folder.exclude_peers if getattr(item, "user_id", None) != peer.id]
            if already_listed and len(exclusions) == len(folder.exclude_peers):
                return f"Чат уже в папке «{APPLICATION_FOLDER}»."

            folder.exclude_peers = exclusions
            if not already_listed:
                folder.include_peers.append(input_peer)
            if await client(functions.messages.UpdateDialogFilterRequest(folder.id, filter=folder)):
                return f"Чат добавлен в папку «{APPLICATION_FOLDER}»."
    except Exception:
        pass
    return f"Telegram не подтвердил добавление чата в папку «{APPLICATION_FOLDER}»."


class Telegram:
    def __init__(self, store):
        self.store = store
        self.lock = asyncio.Lock()

    async def send(self, draft, authorize=None):
        async with self.lock:
            if authorize is not None and not authorize():
                raise Rejected("Доступ отозван или сессия завершена. Отправка отменена.")
            self.store.check_telegram_limit()
            encrypted = self.store.get("tg_session")
            if not encrypted:
                raise Rejected("Владелец ещё не подключил Telegram на VPS.")
            file = None
            if draft.attach:
                if not self.store.resume.is_file():
                    raise Rejected("На VPS ещё не загружено резюме PDF.")
                file = BytesIO(self.store.resume.read_bytes())
                file.name = "resume.pdf"
            settings = json.loads(self.store.cipher.decrypt(encrypted.encode()))
            client = new_client(settings["id"], settings["hash"], settings["session"])
            delivery_id = None
            try:
                async with asyncio.timeout(50):
                    await client.connect()
                    if not await client.is_user_authorized():
                        raise Rejected("Сессия Telegram завершена. Подключи аккаунт заново на VPS.")
                    if draft.recipient == "self":
                        peer = await client.get_me()
                    else:
                        try:
                            peer = await client.get_entity(draft.recipient)
                        except (ValueError, errors.UsernameInvalidError, errors.UsernameNotOccupiedError):
                            raise Rejected("Telegram не нашёл пользователя с таким @username.") from None
                    if not isinstance(peer, types.User) or peer.bot or peer.deleted:
                        raise Rejected("Получателем может быть личный аккаунт Telegram.")
                    if draft.recipient != "self":
                        await ensure_new_contact(client, peer)
                    if authorize is not None and not authorize():
                        raise Rejected("Доступ отозван или сессия завершена. Отправка отменена.")
                    delivery_id = self.store.claim(draft.recipient, peer.id, draft.vacancy)
                    if file:
                        sent = await client.send_file(peer, file, caption=draft.message, parse_mode=None, force_document=True)
                    else:
                        sent = await client.send_message(peer, draft.message, parse_mode=None, link_preview=False)
                message_id = getattr(sent, "id", None)
                if not isinstance(message_id, int):
                    raise RuntimeError("missing message ID")
                self.store.finish(delivery_id, "sent", message_id)
            except errors.FloodWaitError as exc:
                self.store.set("tg_wait_until", str(int(time.time()) + exc.seconds + 1))
                if delivery_id is not None:
                    self.store.finish(delivery_id, "failed")
                raise Rejected(f"Telegram попросил подождать {exc.seconds} сек.") from None
            except errors.PeerFloodError:
                self.store.set("tg_wait_until", str(int(time.time()) + 86400))
                if delivery_id is not None:
                    self.store.finish(delivery_id, "failed")
                raise Rejected("Telegram ограничил отправку. Пауза на сутки.") from None
            except (errors.BadRequestError, errors.ForbiddenError, errors.UnauthorizedError) as exc:
                if delivery_id is not None:
                    self.store.finish(delivery_id, "failed")
                raise Rejected(f"Telegram отклонил запрос ({type(exc).__name__}).") from None
            except Rejected:
                raise
            except Exception:
                if delivery_id is not None:
                    self.store.finish(delivery_id, "unknown")
                    raise Rejected(f"Исход отправки №{delivery_id} неизвестен. Проверь чат Telegram.") from None
                raise Rejected("Не удалось подключиться к Telegram. Сообщение не отправлялось.") from None
            else:
                folder_notice = None
                if draft.recipient != "self":
                    folder_notice = await add_to_applications_folder(client, peer)
                return delivery_id, message_id, folder_notice
            finally:
                try:
                    await client.disconnect()
                except Exception:
                    pass
