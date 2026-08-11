"""Tests for the ``delete`` command."""

from __future__ import annotations

import keyring
import pytest
from typer.testing import CliRunner

from secretsmgr import app, DEFAULT_SERVICE

runner = CliRunner()


class TestDeleteCommand:
    """Tests for ``secretsmgr delete``."""

    def test_delete_existing_secret(self, file_keyring, service_name):
        """Deleting a secret that exists succeeds."""
        keyring.set_password(service_name, "mykey", "mysecret")

        result = runner.invoke(
            app,
            ["delete", "mykey", "--service", service_name],
        )
        assert result.exit_code == 0
        assert "Deleted secret 'mykey'" in result.stderr
        assert "from service 'test-service'" in result.stderr

        # Verify it's gone.
        assert keyring.get_password(service_name, "mykey") is None

    def test_delete_default_service(self, file_keyring):
        """Omitting --service uses DEFAULT_SERVICE."""
        keyring.set_password(DEFAULT_SERVICE, "mykey", "mysecret")

        result = runner.invoke(app, ["delete", "mykey"])
        assert result.exit_code == 0
        assert f"from service '{DEFAULT_SERVICE}'" in result.stderr
        assert keyring.get_password(DEFAULT_SERVICE, "mykey") is None

    def test_delete_missing_secret(self, file_keyring, service_name):
        """Deleting a key that doesn't exist exits with code 1."""
        result = runner.invoke(
            app,
            ["delete", "nonexistent", "--service", service_name],
        )
        assert result.exit_code == 1
        assert "No secret found" in result.stderr
        assert "nonexistent" in result.stderr

    def test_delete_one_key_leaves_others(self, file_keyring, service_name):
        """Deleting one key doesn't affect other keys in the same service."""
        keyring.set_password(service_name, "key1", "val1")
        keyring.set_password(service_name, "key2", "val2")

        result = runner.invoke(
            app,
            ["delete", "key1", "--service", service_name],
        )
        assert result.exit_code == 0
        assert keyring.get_password(service_name, "key1") is None
        assert keyring.get_password(service_name, "key2") == "val2"

    def test_delete_already_deleted(self, file_keyring, service_name):
        """Deleting a key twice — second attempt fails."""
        keyring.set_password(service_name, "mykey", "mysecret")

        # First delete succeeds.
        result1 = runner.invoke(
            app,
            ["delete", "mykey", "--service", service_name],
        )
        assert result1.exit_code == 0

        # Second delete fails.
        result2 = runner.invoke(
            app,
            ["delete", "mykey", "--service", service_name],
        )
        assert result2.exit_code == 1
        assert "No secret found" in result2.stderr

    def test_delete_key_with_dashes(self, file_keyring, service_name):
        """Keys with dashes are deleted correctly."""
        keyring.set_password(service_name, "my-key-name", "value")

        result = runner.invoke(
            app,
            ["delete", "my-key-name", "--service", service_name],
        )
        assert result.exit_code == 0
        assert keyring.get_password(service_name, "my-key-name") is None

    def test_delete_keyring_locked(self, file_keyring, service_name):
        """When the keyring is locked, exit code is 1 and message is shown."""
        from unittest.mock import patch

        def raise_locked(*args, **kwargs):
            raise keyring.errors.KeyringLocked("locked!")

        with patch.object(keyring, "delete_password", raise_locked):
            result = runner.invoke(
                app,
                ["delete", "mykey", "--service", service_name],
            )
        assert result.exit_code == 1
        assert "Keyring is locked" in result.stderr
