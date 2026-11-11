"""Prepare per-service secret files while preserving an existing Telegram key."""
import base64
import binascii
import fcntl
import os
from pathlib import Path
import secrets
from tempfile import NamedTemporaryFile


def validate_key(key):
    try:
        decoded = base64.b64decode(key, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise SystemExit("Некорректный ключ. Существующая настройка сохранена.") from None
    if len(decoded) != 32:
        raise SystemExit("Некорректная длина ключа. Существующая настройка сохранена.")


def install_secret(path, key, uid):
    if path.is_symlink():
        raise SystemExit(f"Символьная ссылка вместо файла секрета: {path.name}")
    with NamedTemporaryFile(dir=path.parent, delete=False) as output:
        output.write(key + b"\n")
        output.flush()
        os.fchmod(output.fileno(), 0o400)
        os.fchown(output.fileno(), uid, uid)
        os.fsync(output.fileno())
    os.replace(output.name, path)


def prepare(root):
    env_path = root / ".env"
    if env_path.is_symlink() or not env_path.is_file():
        raise SystemExit("Сначала выполни python3 init.py в каталоге проекта.")
    original = env_path.read_text()
    fields = {}
    for line in original.splitlines():
        name, separator, value = line.partition("=")
        if separator and not name.lstrip().startswith("#"):
            name = name.strip()
            if name in fields:
                raise SystemExit("В .env есть повторяющиеся параметры. Исправь их перед переносом ключа.")
            fields[name] = value.strip().strip('"').strip("'")
    if not fields.get("BRIDGE_HOST"):
        raise SystemExit("В .env отсутствует BRIDGE_HOST.")

    directory = root / "secrets"
    if directory.is_symlink():
        raise SystemExit("Символьная ссылка вместо каталога secrets.")
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    os.chown(directory, 0, 0)
    bridge_path = directory / "bridge.key"
    hh_path = directory / "hh.key"
    if bridge_path.is_symlink() or hh_path.is_symlink():
        raise SystemExit("Обнаружена символьная ссылка вместо ключа.")
    existing_bridge = bridge_path.read_bytes().strip() if bridge_path.exists() else None
    env_key = fields.get("BRIDGE_KEY", "").encode() or None
    if existing_bridge and env_key and existing_bridge != env_key:
        raise SystemExit("Ключ в .env отличается от secrets/bridge.key. Остановлено для сохранения сессии Telegram.")
    bridge_key = existing_bridge or env_key
    if not bridge_key:
        raise SystemExit("Ключ Telegram не найден. Автоматическая замена ключа остановлена.")
    hh_key = hh_path.read_bytes().strip() if hh_path.exists() else base64.urlsafe_b64encode(secrets.token_bytes(32))
    validate_key(bridge_key)
    validate_key(hh_key)
    install_secret(bridge_path, bridge_key, 10001)
    install_secret(hh_path, hh_key, 10003)

    # Remove the old plaintext environment copy only after both key files exist.
    env_lines = [line for line in original.splitlines() if line.partition("=")[0].strip() != "BRIDGE_KEY"]
    metadata = env_path.stat()
    with NamedTemporaryFile(mode="w", dir=root, encoding="utf-8", delete=False) as output:
        output.write("\n".join(env_lines) + "\n")
        output.flush()
        os.fchmod(output.fileno(), 0o600)
        os.fchown(output.fileno(), metadata.st_uid, metadata.st_gid)
        os.fsync(output.fileno())
    os.replace(output.name, env_path)
    print("Ключи подготовлены. Существующий ключ Telegram сохранён.")


def main():
    if os.geteuid() != 0:
        raise SystemExit("Запусти sudo python3 secure_setup.py")
    os.umask(0o077)
    root = Path(__file__).resolve().parent
    descriptor = os.open(root / ".secure-setup.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        prepare(root)


if __name__ == "__main__":
    main()
