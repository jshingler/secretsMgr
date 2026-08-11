"""Tests for the ``export`` command."""

from __future__ import annotations

import json

import keyring
import pytest
from typer.testing import CliRunner

from secretsmgr import app, _decrypt, DEFAULT_SERVICE

runner = CliRunner()


class TestExportCommand:
    """Tests for ``secretsmgr export``."""

    def test_export_creates_encrypted_file(self, file_keyring, service_name, tmp_path):
        """Exporting writes an encrypted file to disk."""
        keyring.set_password(service_name, "key1", "val1")
        keyring.set_password(service_name, "key2", "val2")

        export_file = tmp_path / "export.enc"

        result = runner.invoke(
            app,
            ["export", str(export_file), "password123", "--service", service_name],
        )
        assert result.exit_code == 0
        assert export_file.exists()
        assert "Exported 2 secret(s)" in result.stderr

    def test_export_file_is_encrypted(self, file_keyring, service_name, tmp_path):
        """The exported file should not contain plaintext secrets."""
        keyring.set_password(service_name, "key1", "supersecretvalue")

        export_file = tmp_path / "export.enc"

        runner.invoke(
            app,
            ["export", str(export_file), "password123", "--service", service_name],
        )

        blob = export_file.read_bytes()
        assert b"supersecretvalue" not in blob
        assert b"key1" not in blob

    def test_export_can_be_decrypted(self, file_keyring, service_name, tmp_path):
        """The exported file can be decrypted with the same password."""
        keyring.set_password(service_name, "key1", "val1")
        keyring.set_password(service_name, "key2", "val2")

        export_file = tmp_path / "export.enc"
        password = "my-password"

        runner.invoke(
            app,
            ["export", str(export_file), password, "--service", service_name],
        )

        blob = export_file.read_bytes()
        plaintext = _decrypt(blob, password)
        secrets = json.loads(plaintext)
        assert secrets == {"key1": "val1", "key2": "val2"}

    def test_export_empty_service(self, file_keyring, service_name, tmp_path):
        """Exporting a service with no secrets exits with code 1."""
        export_file = tmp_path / "export.enc"

        result = runner.invoke(
            app,
            ["export", str(export_file), "password123", "--service", service_name],
        )
        assert result.exit_code == 1
        assert "No secrets found" in result.stderr
        assert not export_file.exists()

    def test_export_default_service(self, file_keyring, tmp_path):
        """Omitting --service exports from DEFAULT_SERVICE."""
        keyring.set_password(DEFAULT_SERVICE, "mykey", "mysecret")

        export_file = tmp_path / "export.enc"

        result = runner.invoke(
            app,
            ["export", str(export_file), "password123"],
        )
        assert result.exit_code == 0
        assert f"from service '{DEFAULT_SERVICE}'" in result.stderr

    def test_export_single_secret(self, file_keyring, service_name, tmp_path):
        """Exporting a service with one secret works."""
        keyring.set_password(service_name, "onlykey", "onlyval")

        export_file = tmp_path / "export.enc"

        result = runner.invoke(
            app,
            ["export", str(export_file), "password123", "--service", service_name],
        )
        assert result.exit_code == 0
        assert "Exported 1 secret(s)" in result.stderr

    def test_export_wrong_password_fails_on_import(
        self, file_keyring, service_name, tmp_path
    ):
        """An export encrypted with one password can't be decrypted with another."""
        keyring.set_password(service_name, "key1", "val1")

        export_file = tmp_path / "export.enc"

        runner.invoke(
            app,
            ["export", str(export_file), "correct-password", "--service", service_name],
        )

        blob = export_file.read_bytes()
        from cryptography.fernet import InvalidToken

        with pytest.raises(InvalidToken):
            _decrypt(blob, "wrong-password")

    def test_export_multiple_services_isolated(
        self, file_keyring, service_name, tmp_path
    ):
        """Exporting one service doesn't include secrets from another."""
        keyring.set_password(service_name, "key1", "val1")
        keyring.set_password("other-service", "key2", "val2")

        export_file = tmp_path / "export.enc"

        runner.invoke(
            app,
            ["export", str(export_file), "password123", "--service", service_name],
        )

        blob = export_file.read_bytes()
        plaintext = _decrypt(blob, "password123")
        secrets = json.loads(plaintext)
        assert secrets == {"key1": "val1"}
        assert "key2" not in secrets
