import os
from pathlib import Path

from .store import Store


def open_store():
    os.umask(0o077)
    limit = int(os.getenv("BRIDGE_DAILY_LIMIT", "8"))
    if not 1 <= limit <= 20:
        raise ValueError("BRIDGE_DAILY_LIMIT должен быть от 1 до 20")
    key_file = os.getenv("BRIDGE_KEY_FILE")
    key = Path(key_file).read_text().strip() if key_file else os.environ["BRIDGE_KEY"]
    return Store(Path(os.getenv("BRIDGE_DATA", "/data")), key, limit)
