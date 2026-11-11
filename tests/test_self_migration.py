from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cryptography.fernet import Fernet
from bridge.store import Store, Rejected


class SelfMigrationTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.key = Fernet.generate_key()
        self.store = Store(self.root, self.key, daily_limit=8)

    def test_same_saved_messages_target_can_be_used_repeatedly(self):
        first = self.store.claim('self', 123, '')
        self.store.finish(first, 'sent', 100)
        second = self.store.claim('self', 123, '')
        third = self.store.claim('self', 123, '')
        self.assertEqual(len({first, second, third}), 3)

    def test_real_recipient_is_still_protected_across_alias_and_vacancy(self):
        first = self.store.claim('@example_user', 123, 'https://hh.ru/vacancy/1')
        self.store.finish(first, 'sent', 100)
        with self.assertRaises(Rejected):
            self.store.claim('@renamed_user', 123, 'https://hh.ru/vacancy/2')

    def test_old_index_migration_preserves_history_auth_and_settings(self):
        first = self.store.claim('self', 123, '')
        self.store.finish(first, 'sent', 100)
        encrypted = self.store.cipher.encrypt(b'test-session').decode()
        self.store.set('tg_session', encrypted)
        token, _ = self.store.redeem(self.store.issue('agent'))
        with self.store.connect() as db:
            db.executescript("""
                DROP INDEX delivery_in_progress_v2;
                CREATE UNIQUE INDEX delivery_in_progress
                  ON deliveries(peer_id, vacancy) WHERE status != 'failed';
            """)
        migrated = Store(self.root, self.key, daily_limit=8)
        migrated.claim('self', 123, '')
        self.assertEqual(migrated.role(token), 'agent')
        self.assertEqual(migrated.get('tg_session'), encrypted)
        self.assertTrue(any(r['message_id'] == 100 for r in migrated.recent()))
        again = Store(self.root, self.key, daily_limit=8)
        again.claim('self', 123, '')
        with again.connect() as db:
            self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='delivery_in_progress'").fetchone())
            self.assertIsNotNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='delivery_in_progress_v2'").fetchone())

    def test_saved_messages_tests_still_obey_daily_limit(self):
        limited = Store(self.root, self.key, daily_limit=2)
        limited.claim('self', 123, '')
        limited.claim('self', 123, '')
        with self.assertRaisesRegex(Rejected, 'лимит'):
            limited.claim('self', 123, '')
