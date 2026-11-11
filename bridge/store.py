from contextlib import contextmanager
from datetime import datetime
from hashlib import sha256
from pathlib import Path
import secrets
import sqlite3
import time
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet


class Rejected(Exception):
    """An error safe to show to the operator."""


class Store:
    def __init__(self, root: Path, key: str, daily_limit: int):
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.cipher = Fernet(key)
        self.daily_limit = daily_limit
        self.resume = self.root / "resume.pdf"
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS codes (
                    digest TEXT PRIMARY KEY, role TEXT NOT NULL, expires INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    digest TEXT PRIMARY KEY, role TEXT NOT NULL, expires INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS settings (
                    name TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS login_attempts (
                    client TEXT NOT NULL, minute INTEGER NOT NULL, attempts INTEGER NOT NULL,
                    PRIMARY KEY (client, minute)
                );
                CREATE TABLE IF NOT EXISTS deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    day TEXT NOT NULL,
                    started_at INTEGER NOT NULL,
                    recipient TEXT NOT NULL,
                    peer_id INTEGER NOT NULL,
                    vacancy TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message_id INTEGER
                );
            """)
            # Migrate the previous index atomically. Saved Messages is a test
            # destination and may receive repeated tests with the same URL.
            db.executescript("""
                BEGIN IMMEDIATE;
                DROP INDEX IF EXISTS delivery_in_progress;
                CREATE UNIQUE INDEX IF NOT EXISTS delivery_in_progress_v2
                    ON deliveries(peer_id, vacancy)
                    WHERE status != 'failed' AND recipient != 'self';
                COMMIT;
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.root / "bridge.sqlite3", timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def digest(secret):
        return sha256(secret.encode()).hexdigest()

    def issue(self, role):
        code = secrets.token_urlsafe(24)
        now = int(time.time())
        with self.connect() as db:
            db.execute("DELETE FROM codes WHERE expires <= ?", (now,))
            db.execute("INSERT INTO codes VALUES (?, ?, ?)", (self.digest(code), role, now + 600))
        return code

    def redeem(self, code, old_session=None):
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.connect() as db:
            item = db.execute(
                "DELETE FROM codes WHERE digest = ? AND expires > ? RETURNING role",
                (self.digest(code), now),
            ).fetchone()
            if item is None:
                return None
            duration = 8 * 3600 if item["role"] == "owner" else 30 * 86400
            db.execute("DELETE FROM sessions WHERE expires <= ?", (now,))
            if old_session:
                db.execute("DELETE FROM sessions WHERE digest = ?", (self.digest(old_session),))
            db.execute("INSERT INTO sessions VALUES (?, ?, ?)", (
                self.digest(token), item["role"], now + duration,
            ))
        return token, duration

    def allow_login(self, client):
        minute = int(time.time()) // 60
        with self.connect() as db:
            db.execute("DELETE FROM login_attempts WHERE minute < ?", (minute - 1,))
            row = db.execute(
                "INSERT INTO login_attempts VALUES (?, ?, 1) "
                "ON CONFLICT(client, minute) DO UPDATE SET attempts = attempts + 1 RETURNING attempts",
                (self.digest(client), minute),
            ).fetchone()
        return row["attempts"] <= 20

    def role(self, token):
        if not token:
            return None
        with self.connect() as db:
            row = db.execute(
                "SELECT role FROM sessions WHERE digest = ? AND expires > ?",
                (self.digest(token), int(time.time())),
            ).fetchone()
        return row["role"] if row else None

    def logout(self, token):
        if token:
            with self.connect() as db:
                db.execute("DELETE FROM sessions WHERE digest = ?", (self.digest(token),))

    def revoke_agents(self):
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE role = 'agent'")
            db.execute("DELETE FROM codes WHERE role = 'agent'")
            db.execute("DELETE FROM settings WHERE name = 'hh_shared'")

    def get(self, name, default=None):
        with self.connect() as db:
            row = db.execute("SELECT value FROM settings WHERE name = ?", (name,)).fetchone()
        return row["value"] if row else default

    def set(self, name, value):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES (?, ?)", (name, value))

    def check_telegram_limit(self):
        if int(self.get("tg_wait_until", "0")) > time.time():
            raise Rejected("Действует пауза Telegram. Повтори проверку позже.")

    def claim(self, recipient, peer_id, vacancy):
        day = datetime.now(ZoneInfo("Europe/Moscow")).date().isoformat()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if recipient != "self" and db.execute(
                "SELECT 1 FROM deliveries WHERE peer_id = ? AND status != 'failed' LIMIT 1",
                (peer_id,),
            ).fetchone():
                raise Rejected("Для этого получателя уже есть отправка в журнале.")
            count = db.execute("SELECT count(*) FROM deliveries WHERE day = ?", (day,)).fetchone()[0]
            if count >= self.daily_limit:
                raise Rejected(f"Исчерпан лимит попыток на сегодня по МСК ({self.daily_limit}).")
            try:
                item = db.execute(
                    "INSERT INTO deliveries(day, started_at, recipient, peer_id, vacancy, status) "
                    "VALUES (?, ?, ?, ?, ?, 'sending') RETURNING id",
                    (day, int(time.time()), recipient, peer_id, vacancy),
                ).fetchone()
            except sqlite3.IntegrityError:
                raise Rejected("Для этого получателя и вакансии уже есть отправка в журнале.") from None
        return item["id"]

    def finish(self, item_id, status, message_id=None):
        with self.connect() as db:
            db.execute(
                "UPDATE deliveries SET status = ?, message_id = ? WHERE id = ? AND status = 'sending'",
                (status, message_id, item_id),
            )

    def resolve(self, item_id, status):
        with self.connect() as db:
            row = db.execute(
                "UPDATE deliveries SET status = ? WHERE id = ? AND "
                "(status = 'unknown' OR (status = 'sending' AND started_at <= ?)) RETURNING id",
                (status, item_id, int(time.time()) - 120),
            ).fetchone()
        if row is None:
            raise Rejected("Запись для сверки не найдена.")

    def recent(self):
        with self.connect() as db:
            return db.execute(
                "SELECT id, day, recipient, vacancy, status, message_id "
                "FROM deliveries ORDER BY id DESC LIMIT 30"
            ).fetchall()
