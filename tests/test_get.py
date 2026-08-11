"""Tests for the ``get`` command."""

from __future__ import annotations

import keyring
import pytest
from typer.testing import CliRunner

from secretsmgr import app, DEFAULT_SERVICE

runner = CliRunner()


class TestGetCommand:
    """Tests for ``secretsmgr get``."""

    def test_get_existing_secret(self, file_keyring, service_name):
        """Retrieving a secret that exists prints the value to stdout."""
        keyring.set_password(service_name, "mykey", "mysecret")

        result = runner.invoke(
            app,
            ["get", "mykey", "--service", service_name],
        )
        assert result.exit_code == 0
        assert result.stdout == "mysecret\n"

    def test_get_default_service(self, file_keyring):
        """Omitting --service uses DEFAULT_SERVICE."""
        keyring.set_password(DEFAULT_SERVICE, "mykey", "mysecret")

        result = runner.invoke(app, ["get", "mykey"])
        assert result.exit_code == 0
        assert result.stdout == "mysecret\n"

    def test_get_missing_secret(self, file_keyring, service_name):
        """Retrieving a key that doesn't exist exits with code 1."""
        result = runner.invoke(
            app,
            ["get", "nonexistent", "--service", service_name],
        )
        assert result.exit_code == 1
        assert "No secret found" in result.stderr
        assert "nonexistent" in result.stderr

    def test_get_empty_value(self, file_keyring, service_name):
        """An empty-string secret is retrieved as an empty line."""
        keyring.set_password(service_name, "emptykey", "")

        result = runner.invoke(
            app,
            ["get", "emptykey", "--service", service_name],
        )
        assert result.exit_code == 0
        assert result.stdout == "\n"

    def test_get_value_with_newlines(self, file_keyring, service_name):
        """Values containing newlines are printed verbatim."""
        multiline = "line1\nline2\nline3"
        keyring.set_password(service_name, "mlkey", multiline)

        result = runner.invoke(
            app,
            ["get", "mlkey", "--service", service_name],
        )
        assert result.exit_code == 0
        assert result.stdout == "line1\nline2\nline3\n"

    def test_get_value_with_special_characters(self, file_keyring, service_name):
        """Special characters in the value are preserved."""
        special = "p@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?"
        keyring.set_password(service_name, "specialkey", special)

        result = runner.invoke(
            app,
            ["get", "specialkey", "--service", service_name],
        )
        assert result.exit_code == 0
        assert result.stdout == special + "\n"

    def test_get_does_not_print_to_stderr(self, file_keyring, service_name):
        """The secret value goes to stdout, not stderr."""
        keyring.set_password(service_name, "mykey", "mysecret")

        result = runner.invoke(
            app,
            ["get", "mykey", "--service", service_name],
        )
        assert result.exit_code == 0
        assert result.stderr == ""

    def test_get_keyring_locked(self, file_keyring, service_name):
        """When the keyring is locked, exit code is 1 and message is shown."""
        from unittest.mock import patch

        def raise_locked(*args, **kwargs):
            raise keyring.errors.KeyringLocked("locked!")

        with patch.object(keyring, "get_password", raise_locked):
            result = runner.invoke(
                app,
                ["get", "mykey", "--service", service_name],
            )
        assert result.exit_code == 1
        assert "Keyring is locked" in result.stderr
