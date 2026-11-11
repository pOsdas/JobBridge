from pathlib import Path
import os
import subprocess
from tempfile import TemporaryDirectory
import unittest


class BrowserLockTests(unittest.TestCase):
    def test_stale_links_are_removed_only_with_exclusive_profile_access(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "profile/chromium"
            profile.mkdir(parents=True)
            cookies = profile / "Cookies"
            cookies.write_bytes(b"persisted account data")
            for name in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
                (profile / name).symlink_to("old-container")
            script = (Path(__file__).resolve().parents[1] / "browser/start.sh").read_text()
            prefix = script.split("children=()", 1)[0]
            prefix = prefix.replace("/profile", str(root / "profile"))
            environment = {"XDG_RUNTIME_DIR": str(root / "runtime")}
            environment = dict(os.environ, **environment)
            holder = subprocess.Popen(
                ["bash", "-c", prefix + "printf 'ready\\n'; IFS= read -r line"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=environment,
            )
            try:
                self.assertEqual(holder.stdout.readline().strip(), "ready")
                self.assertTrue(all(not (profile / name).is_symlink()
                                    for name in ("SingletonLock", "SingletonSocket", "SingletonCookie")))
                # A competing start must not touch the active profile's lock.
                (profile / "SingletonLock").symlink_to("active-container")
                contender = subprocess.run(
                    ["bash", "-c", prefix], env=environment, capture_output=True, text=True, timeout=3,
                )
                self.assertEqual(contender.returncode, 75)
                self.assertTrue((profile / "SingletonLock").is_symlink())
                self.assertEqual(cookies.read_bytes(), b"persisted account data")
            finally:
                holder.terminate()
                holder.communicate(timeout=3)
            restarted = subprocess.run(
                ["bash", "-c", prefix], env=environment, capture_output=True, text=True, timeout=3,
            )
            self.assertEqual(restarted.returncode, 0, restarted.stderr)
            self.assertFalse((profile / "SingletonLock").is_symlink())
            self.assertEqual(cookies.read_bytes(), b"persisted account data")


if __name__ == "__main__":
    unittest.main()
