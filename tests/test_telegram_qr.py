import asyncio
from contextlib import redirect_stdout
from io import StringIO
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography.fernet import Fernet
from telethon import errors
from bridge import cli
from bridge.store import Rejected


class QRTests(unittest.IsolatedAsyncioTestCase):
    def setup_login(self):
        store = SimpleNamespace(cipher=Fernet(Fernet.generate_key()), set=MagicMock())
        client = SimpleNamespace(
            connect=AsyncMock(), disconnect=AsyncMock(),
            qr_login=AsyncMock(), send_code_request=AsyncMock(), sign_in=AsyncMock(),
            get_me=AsyncMock(return_value=SimpleNamespace(bot=False)),
            session=SimpleNamespace(save=lambda: 'test-session'),
        )
        qr = SimpleNamespace(url='tg://login?token=test', wait=AsyncMock(), recreate=AsyncMock())
        client.qr_login.return_value = qr
        return store, client, qr

    async def login(self, store, client, passwords=None, use_qr=True):
        with (patch.object(cli, 'input', side_effect=['12345', '+12025550123'], create=True),
              patch.object(cli, 'getpass', side_effect=passwords or ['a' * 32]),
              patch.object(cli, 'new_client', return_value=client) as factory,
              patch.object(cli, 'show_login_qr'), redirect_stdout(StringIO())):
            await cli.connect_telegram(store, use_qr=use_qr)
            factory.assert_called_once_with(12345, 'a' * 32, receive_updates=use_qr)

    async def test_qr_saves_existing_encrypted_schema_without_requesting_code(self):
        store, client, qr = self.setup_login()
        await self.login(store, client)
        client.send_code_request.assert_not_awaited()
        client.sign_in.assert_not_awaited()
        client.disconnect.assert_awaited_once()
        key, ciphertext = store.set.call_args.args
        self.assertEqual(key, 'tg_session')
        self.assertEqual(json.loads(store.cipher.decrypt(ciphertext.encode())),
                         {'id': 12345, 'hash': 'a' * 32, 'session': 'test-session'})

    async def test_qr_two_factor_password(self):
        store, client, qr = self.setup_login()
        qr.wait.side_effect = errors.SessionPasswordNeededError(request=None)
        await self.login(store, client, ['a' * 32, 'local-test-password'])
        client.sign_in.assert_awaited_once_with(password='local-test-password')
        store.set.assert_called_once()
        client.disconnect.assert_awaited_once()

    async def test_expired_qr_is_refreshed(self):
        store, client, qr = self.setup_login()
        qr.wait.side_effect = [asyncio.TimeoutError(), None]
        await self.login(store, client)
        qr.recreate.assert_awaited_once()
        self.assertEqual(qr.wait.await_count, 2)

    async def test_expiration_limit_preserves_old_session_and_disconnects(self):
        store, client, qr = self.setup_login()
        qr.wait.side_effect = asyncio.TimeoutError()
        with self.assertRaises(Rejected):
            await self.login(store, client)
        self.assertEqual(qr.wait.await_count, 5)
        self.assertEqual(qr.recreate.await_count, 4)
        store.set.assert_not_called()
        client.disconnect.assert_awaited_once()

    async def test_rejected_account_never_overwrites_session(self):
        store, client, qr = self.setup_login()
        client.get_me.return_value = SimpleNamespace(bot=True)
        with self.assertRaises(Rejected):
            await self.login(store, client)
        store.set.assert_not_called()
        client.disconnect.assert_awaited_once()

    async def test_code_login_still_works(self):
        store, client, qr = self.setup_login()
        client.send_code_request.return_value = SimpleNamespace(phone_code_hash='local-challenge')
        await self.login(store, client, ['a' * 32, '12345'], use_qr=False)
        client.qr_login.assert_not_awaited()
        client.send_code_request.assert_awaited_once_with('+12025550123')
        client.sign_in.assert_awaited_once_with('+12025550123', '12345', phone_code_hash='local-challenge')
        store.set.assert_called_once()

    def test_terminal_renderer_outputs_qr_without_plain_token(self):
        output = StringIO()
        with redirect_stdout(output):
            cli.show_login_qr('tg://login?token=local-nonsecret-test')
        self.assertNotIn('tg://login', output.getvalue())
        self.assertIn('Подключить устройство', output.getvalue())
        self.assertIn('█', output.getvalue())
