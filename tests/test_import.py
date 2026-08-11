"""Tests for the ``import`` command."""

from __future__ import annotations

import json

import keyring
import pytest
from typer.testing import CliRunner

from secretsmgr import app, _encrypt, DEFAULT_SERVICE

runner = CliRunner()


class TestImportCommand:
    """Tests for ``secretsmgr import``."""

    def test_import_restores_secrets(self, file_keyring, service_name, tmp_path):
        """Importing an encrypted export writes secrets into the keyring."""
        payload = json.dumps({"key1": "val1", "key2": "val2"}).encode()
        blob = _encrypt(payload, "password123")

        import_file = tmp_path / "import.enc"
        import_file.write_bytes(blob)

        result = runner.invoke(
            app,
            ["import", str(import_file), "password123", "--service", service_name],
        )
        assert result.exit_code == 0
        assert "Imported 2 secret(s)" in result.stderr
        assert keyring.get_password(service_name, "key1") == "val1"
        assert keyring.get_password(service_name, "key2") == "val2"

    def test_import_wrong_password(self, file_keyring, service_name, tmp_path):
        """Importing with the wrong password fails cleanly."""
        payload = json.dumps({"key1": "val1"}).encode()
        blob = _encrypt(payload, "correct-password")

        import_file = tmp_path / "import.enc"
        import_file.write_bytes(blob)

        result = runner.invoke(
            app,
            ["import", str(import_file), "wrong-password", "--service", service_name],
        )
        assert result.exit_code == 1
        assert "Decryption failed" in result.stderr
        assert keyring.get_password(service_name, "key1") is None

    def test_import_corrupted_file(self, file_keyring, service_name, tmp_path):
        """Importing a corrupted/garbage file fails cleanly."""
        import_file = tmp_path / "import.enc"
        import_file.write_bytes(b"not a valid encrypted blob at all, just garbage")

        result = runner.invoke(
            app,
            ["import", str(import_file), "password123", "--service", service_name],
        )
        assert result.exit_code == 1
        assert "Decryption failed" in result.stderr

    def test_import_default_service(self, file_keyring, tmp_path):
        """Omitting --service imports into DEFAULT_SERVICE."""
        payload = json.dumps({"mykey": "mysecret"}).encode()
        blob = _encrypt(payload, "password123")

        import_file = tmp_path / "import.enc"
        import_file.write_bytes(blob)

        result = runner.invoke(
            app,
            ["import", str(import_file), "password123"],
        )
        assert result.exit_code == 0
        assert f"into service '{DEFAULT_SERVICE}'" in result.stderr
        assert keyring.get_password(DEFAULT_SERVICE, "mykey") == "mysecret"

    def test_import_overwrites_existing(self, file_keyring, service_name, tmp_path):
        """Importing overwrites secrets that already exist for the same key."""
        keyring.set_password(service_name, "key1", "old-value")

        payload = json.dumps({"key1": "new-value"}).encode()
        blob = _encrypt(payload, "password123")

        import_file = tmp_path / "import.enc"
        import_file.write_bytes(blob)

        result = runner.invoke(
            app,
            ["import", str(import_file), "password123", "--service", service_name],
        )
        assert result.exit_code == 0
        assert keyring.get_password(service_name, "key1") == "new-value"

    def test_import_empty_secrets_dict(self, file_keyring, service_name, tmp_path):
        """Importing an export with zero secrets is a no-op that still succeeds."""
        payload = json.dumps({}).encode()
        blob = _encrypt(payload, "password123")

        import_file = tmp_path / "import.enc"
        import_file.write_bytes(blob)

        result = runner.invoke(
            app,
            ["import", str(import_file), "password123", "--service", service_name],
        )
        assert result.exit_code == 0
        assert "Imported 0 secret(s)" in result.stderr

    def test_import_nonexistent_file(self, file_keyring, service_name, tmp_path):
        """Importing a file that doesn't exist raises an error."""
        missing_file = tmp_path / "does-not-exist.enc"

        result = runner.invoke(
            app,
            ["import", str(missing_file), "password123", "--service", service_name],
        )
        assert result.exit_code != 0

    def test_roundtrip_export_then_import(self, file_keyring, service_name, tmp_path):
        """A full export → wipe → import roundtrip restores all secrets."""
        keyring.set_password(service_name, "key1", "val1")
        keyring.set_password(service_name, "key2", "val2")
        keyring.set_password(service_name, "key3", "val3")

        export_file = tmp_path / "roundtrip.enc"
        password = "roundtrip-password"

        export_result = runner.invoke(
            app,
            ["export", str(export_file), password, "--service", service_name],
        )
        assert export_result.exit_code == 0

        # Wipe the originals.
        keyring.delete_password(service_name, "key1")
        keyring.delete_password(service_name, "key2")
        keyring.delete_password(service_name, "key3")
        assert keyring.get_password(service_name, "key1") is None

        # Import them back.
        import_result = runner.invoke(
            app,
            ["import", str(export_file), password, "--service", service_name],
        )
        assert import_result.exit_code == 0
        assert keyring.get_password(service_name, "key1") == "val1"
        assert keyring.get_password(service_name, "key2") == "val2"
        assert keyring.get_password(service_name, "key3") == "val3"

    def test_roundtrip_to_different_service(self, file_keyring, tmp_path):
        """Exporting from one service and importing into another works."""
        keyring.set_password("service-a", "key1", "val1")

        export_file = tmp_path / "cross-service.enc"
        password = "password123"

        runner.invoke(
            app,
            ["export", str(export_file), password, "--service", "service-a"],
        )
        result = runner.invoke(
            app,
            ["import", str(export_file), password, "--service", "service-b"],
        )
        assert result.exit_code == 0
        assert keyring.get_password("service-b", "key1") == "val1"
        # Original service is untouched.
        assert keyring.get_password("service-a", "key1") == "val1"
