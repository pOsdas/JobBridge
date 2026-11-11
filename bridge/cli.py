import argparse
import asyncio
from getpass import getpass
import json
import os
import re
import sys
from tempfile import NamedTemporaryFile

from telethon import errors

from .config import open_store
from .store import Rejected
from .telegram import new_client


def show_login_qr(url):
    import qrcode

    qr = qrcode.QRCode(border=4)
    qr.add_data(url)
    qr.make(fit=True)
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="", flush=True)
    print("Telegram → Настройки → Устройства → Подключить устройство.")
    print("Сканируй этот QR телефоном. Не пересылай его и не присылай снимок в чат.")
    qr.print_ascii(out=sys.stdout, tty=False, invert=True)
    sys.stdout.flush()


async def authorize_by_qr(client):
    qr = await client.qr_login()
    for attempt in range(5):
        # Register the update handler before exposing the QR to the phone.
        waiter = asyncio.create_task(qr.wait())
        try:
            await asyncio.sleep(0)
            show_login_qr(qr.url)
            await waiter
            return
        except asyncio.TimeoutError:
            if attempt == 4:
                raise Rejected("Время QR-входа истекло. Запусти команду снова, когда телефон готов.") from None
        finally:
            if not waiter.done():
                waiter.cancel()
            await asyncio.gather(waiter, return_exceptions=True)
        await qr.recreate()



async def connect_telegram(store, use_qr=False):
    api_id = int(input("Telegram api_id: ").strip())
    api_hash = getpass("Telegram api_hash: ").strip()
    if api_id <= 0 or not re.fullmatch(r"[0-9a-fA-F]{32}", api_hash):
        raise Rejected("Проверь api_id и api_hash.")
    phone = None
    if not use_qr:
        phone = input("Номер Telegram в международном формате: ").strip()
        if not re.fullmatch(r"\+[1-9][0-9]{7,14}", phone):
            raise Rejected("Проверь номер.")
    client = new_client(api_id, api_hash, receive_updates=use_qr)
    try:
        await client.connect()
        try:
            if use_qr:
                await authorize_by_qr(client)
            else:
                challenge = await client.send_code_request(phone)
                await client.sign_in(phone, getpass("Код Telegram: ").strip(), phone_code_hash=challenge.phone_code_hash)
        except errors.SessionPasswordNeededError:
            await client.sign_in(password=getpass("Облачный пароль Telegram: "))
        me = await client.get_me()
        if not me or me.bot:
            raise Rejected("Не удалось войти в личный аккаунт.")
        payload = json.dumps({"id": api_id, "hash": api_hash, "session": client.session.save()})
        store.set("tg_session", store.cipher.encrypt(payload.encode()).decode())
    finally:
        if use_qr and sys.stdout.isatty():
            print("\033[2J\033[H", end="", flush=True)
        await client.disconnect()
    print("Telegram подключён.")


def set_resume(store):
    max_size = 10 * 1024 * 1024
    data = sys.stdin.buffer.read(max_size + 1)
    if not data.startswith(b"%PDF-") or len(data) > max_size:
        raise Rejected("Передай PDF размером до 10 МБ через stdin.")
    with NamedTemporaryFile(dir=store.root, delete=False) as output:
        output.write(data)
    os.replace(output.name, store.resume)
    print("Резюме загружено.")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    code = commands.add_parser("code")
    code.add_argument("role", choices=["owner", "agent"])
    telegram = commands.add_parser("telegram")
    telegram.add_argument("--qr", action="store_true", help="Войти сканированием QR в Telegram на телефоне")
    for command in ("resume", "revoke-agents"):
        commands.add_parser(command)
    resolve = commands.add_parser("resolve")
    resolve.add_argument("id", type=int)
    resolve.add_argument("status", choices=["sent", "failed"])
    args = parser.parse_args()
    store = open_store()
    try:
        if args.command == "code":
            print(store.issue(args.role))
        elif args.command == "telegram":
            asyncio.run(connect_telegram(store, use_qr=args.qr))
        elif args.command == "resume":
            set_resume(store)
        elif args.command == "resolve":
            store.resolve(args.id, args.status)
            print("Журнал обновлён.")
        else:
            store.revoke_agents()
            print("Доступ помощника отозван.")
    except (Rejected, ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from None
    except errors.FloodWaitError as exc:
        raise SystemExit(f"Telegram просит подождать {exc.seconds} секунд. Не повторяй вход до окончания ожидания.") from None
    except errors.RPCError as exc:
        raise SystemExit(f"Telegram отклонил вход ({type(exc).__name__}).") from None


if __name__ == "__main__":
    main()
