import base64
import ctypes
import ctypes.util
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/migrate-signing-secrets.py"
SPEC = importlib.util.spec_from_file_location("secret_migration", SCRIPT)
migration = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(migration)


class SecretMigrationTests(unittest.TestCase):
    def test_missing_secret_writes_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "sealed.json"
            with self.assertRaisesRegex(ValueError, "Missing required secrets"):
                migration.migrate({}, destination)
            self.assertFalse(destination.exists())

    def test_invalid_recipient_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "32-byte"):
            migration.seal("synthetic-test-value", base64.b64encode(b"short"))

    @unittest.skipUnless(ctypes.util.find_library("sodium"), "libsodium required")
    def test_only_recipient_can_decrypt_all_values(self):
        sodium = migration.sodium_library()
        public_key = ctypes.create_string_buffer(32)
        private_key = ctypes.create_string_buffer(32)
        sodium.crypto_box_keypair.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        self.assertEqual(sodium.crypto_box_keypair(public_key, private_key), 0)
        sodium.crypto_box_seal_open.argtypes = (
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong,
            ctypes.c_void_p, ctypes.c_void_p,
        )
        values = {
            name: f"synthetic-{index}-value\nsecond line"
            for index, name in enumerate(migration.SECRET_NAMES)
        }
        environment = dict(values)
        recipient = base64.b64encode(public_key.raw).decode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "sealed.json"
            with mock.patch.object(migration, "ENVIRONMENT_PUBLIC_KEY", recipient):
                migration.migrate(environment, destination)
            text = destination.read_text()
        self.assertEqual(environment, {})
        payload = json.loads(text)
        self.assertEqual(payload["environment"], "macos-signing")
        self.assertEqual(payload["key_id"], migration.ENVIRONMENT_KEY_ID)
        self.assertEqual(set(payload["secrets"]), set(migration.SECRET_NAMES))
        for name, expected in values.items():
            self.assertNotIn(expected, text)
            ciphertext = base64.b64decode(payload["secrets"][name])
            plaintext = ctypes.create_string_buffer(len(ciphertext) - 48)
            self.assertEqual(sodium.crypto_box_seal_open(
                plaintext, ciphertext, len(ciphertext), public_key, private_key,
            ), 0)
            self.assertEqual(plaintext.raw.decode("utf-8"), expected)


if __name__ == "__main__":
    unittest.main()
