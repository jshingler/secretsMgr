"""Tests for the ``set`` command."""

from __future__ import annotations

from unittest.mock import patch

import keyring
import pytest
from typer.testing import CliRunner

from secretsmgr import app, DEFAULT_SERVICE

runner = CliRunner()


class TestSetCommand:
    """Tests for ``secretsmgr set``."""

    def test_set_with_explicit_value(self, file_keyring, service_name):
        """Storing a secret with an explicit value argument."""
        result = runner.invoke(
            app,
            ["set", "mykey", "mysecret", "--service", service_name],
        )
        assert result.exit_code == 0
        assert "Set secret 'mykey'" in result.stderr
        assert "in service 'test-service'" in result.stderr

        # Verify it was actually stored.
        assert keyring.get_password(service_name, "mykey") == "mysecret"

    def test_set_with_default_service(self, file_keyring):
        """Omitting --service uses DEFAULT_SERVICE."""
        result = runner.invoke(app, ["set", "mykey", "mysecret"])
        assert result.exit_code == 0
        assert f"in service '{DEFAULT_SERVICE}'" in result.stderr
        assert keyring.get_password(DEFAULT_SERVICE, "mykey") == "mysecret"

    def test_set_from_stdin(self, file_keyring, service_name):
        """Reading the value from stdin when the argument is omitted."""
        result = runner.invoke(
            app,
            ["set", "mykey", "--service", service_name],
            input="piped-value\n",
        )
        assert result.exit_code == 0
        assert keyring.get_password(service_name, "mykey") == "piped-value"

    def test_set_from_stdin_with_pipe(self, file_keyring, service_name):
        """Reading the value from a non-tty stdin (pipe)."""
        result = runner.invoke(
            app,
            ["set", "mykey", "--service", service_name],
            input="data-from-pipe",
        )
        assert result.exit_code == 0
        # stdin.read().rstrip("\n") strips trailing newlines.
        assert keyring.get_password(service_name, "mykey") == "data-from-pipe"

    def test_set_overwrites_existing(self, file_keyring, service_name):
        """Setting a key that already exists overwrites the value."""
        keyring.set_password(service_name, "mykey", "old-value")

        result = runner.invoke(
            app,
            ["set", "mykey", "new-value", "--service", service_name],
        )
        assert result.exit_code == 0
        assert keyring.get_password(service_name, "mykey") == "new-value"

    def test_set_empty_value(self, file_keyring, service_name):
        """An empty string is a valid secret value."""
        result = runner.invoke(
            app,
            ["set", "mykey", "", "--service", service_name],
        )
        assert result.exit_code == 0
        assert keyring.get_password(service_name, "mykey") == ""

    def test_set_value_with_special_characters(self, file_keyring, service_name):
        """Values with special characters are stored verbatim."""
        special = "p@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?"
        result = runner.invoke(
            app,
            ["set", "mykey", special, "--service", service_name],
        )
        assert result.exit_code == 0
        assert keyring.get_password(service_name, "mykey") == special

    def test_set_key_with_dashes(self, file_keyring, service_name):
        """Keys with dashes are handled correctly."""
        result = runner.invoke(
            app,
            ["set", "my-key-name", "value", "--service", service_name],
        )
        assert result.exit_code == 0
        assert keyring.get_password(service_name, "my-key-name") == "value"

    def test_set_multiple_keys_same_service(self, file_keyring, service_name):
        """Multiple keys can be stored in the same service."""
        runner.invoke(app, ["set", "key1", "val1", "--service", service_name])
        runner.invoke(app, ["set", "key2", "val2", "--service", service_name])

        assert keyring.get_password(service_name, "key1") == "val1"
        assert keyring.get_password(service_name, "key2") == "val2"

    def test_set_keyring_locked(self, file_keyring, service_name):
        """When the keyring is locked, exit code is 1 and message is shown."""
        # Patch set_password to raise KeyringLocked.
        def raise_locked(*args, **kwargs):
            raise keyring.errors.KeyringLocked("locked!")

        with patch.object(keyring, "set_password", raise_locked):
            result = runner.invoke(
                app,
                ["set", "mykey", "mysecret", "--service", service_name],
            )
        assert result.exit_code == 1
        assert "Keyring is locked" in result.stderr
        assert "PYTHON_KEYRING_BACKEND" in result.stderr
