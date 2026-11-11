import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet

from bridge.config import open_store
import secure_setup


class SecretMigrationTests(unittest.TestCase):
    def test_existing_bridge_key_survives_setup_and_repeat_execution(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "secure_setup.py"
            script.touch()
            key = Fernet.generate_key()
            env = root / ".env"
            env.write_text(f"BRIDGE_HOST=jobs.example.test\nBRIDGE_KEY={key.decode()}\nBRIDGE_DAILY_LIMIT=8\n")
            saved_session = Fernet(key).encrypt(b"existing Telegram session")
            with (
                patch.object(secure_setup, "__file__", str(script)),
                patch.object(secure_setup.os, "geteuid", return_value=0),
                patch.object(secure_setup.os, "chown"),
                patch.object(secure_setup.os, "fchown"),
                patch.object(secure_setup.os, "umask"),
            ):
                secure_setup.main()
                hh_key = (root / "secrets/hh.key").read_bytes()
                secure_setup.main()
            bridge_key = (root / "secrets/bridge.key").read_bytes().strip()
            self.assertEqual(bridge_key, key)
            self.assertEqual(Fernet(bridge_key).decrypt(saved_session), b"existing Telegram session")
            self.assertEqual((root / "secrets/hh.key").read_bytes(), hh_key)
            self.assertNotIn("BRIDGE_KEY=", env.read_text())
            self.assertEqual((root / "secrets/bridge.key").stat().st_mode & 0o777, 0o400)
            with patch.dict(os.environ, {
                "BRIDGE_DATA": str(root / "data"), "BRIDGE_KEY_FILE": str(root / "secrets/bridge.key"),
                "BRIDGE_KEY": "unused legacy value",
            }):
                store = open_store()
                self.assertEqual(store.cipher.decrypt(saved_session), b"existing Telegram session")

    def test_conflicting_key_leaves_environment_and_stored_key_intact(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "secrets").mkdir()
            existing = Fernet.generate_key()
            (root / "secrets/bridge.key").write_bytes(existing)
            original = f"BRIDGE_HOST=jobs.example.test\nBRIDGE_KEY={Fernet.generate_key().decode()}\n"
            (root / ".env").write_text(original)
            with (
                patch.object(secure_setup, "__file__", str(root / "secure_setup.py")),
                patch.object(secure_setup.os, "geteuid", return_value=0),
                patch.object(secure_setup.os, "chown"),
                patch.object(secure_setup.os, "fchown"),
                patch.object(secure_setup.os, "umask"),
            ):
                with self.assertRaisesRegex(SystemExit, "отличается"):
                    secure_setup.main()
            self.assertEqual((root / ".env").read_text(), original)
            self.assertEqual((root / "secrets/bridge.key").read_bytes(), existing)


if __name__ == "__main__":
    unittest.main()
