"""Generate a fresh VPS configuration from the deployment hostname."""
import base64
import os
import re
import secrets
from pathlib import Path


def main():
    config = Path(__file__).resolve().with_name(".env")
    if config.exists():
        raise SystemExit(".env уже существует. Существующий ключ нужен для чтения сессии Telegram.")
    host = input("DNS-имя для HTTPS без https:// и порта: ").strip().lower()
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(host) > 253 or not re.fullmatch(rf"(?:{label}\.)+[a-z](?:[a-z0-9-]{{0,61}}[a-z0-9])", host):
        raise SystemExit("Укажи полное DNS-имя. Для IDN используй Punycode.")
    key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
        file.write(f"BRIDGE_HOST={host}\nBRIDGE_KEY={key}\nBRIDGE_DAILY_LIMIT=8\n")
    print(f"Панель после запуска: https://{host}/")
    print("Перед запуском Docker выполни sudo python3 secure_setup.py")


if __name__ == "__main__":
    main()
