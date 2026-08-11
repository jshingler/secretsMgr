"""Tests for the ``list`` command."""

from __future__ import annotations

import keyring
import pytest
from typer.testing import CliRunner

from secretsmgr import app, DEFAULT_SERVICE

runner = CliRunner()


class TestListCommand:
    """Tests for ``secretsmgr list``."""

    def test_list_keys_in_service(self, file_keyring, service_name):
        """Listing returns all keys for a service, sorted."""
        keyring.set_password(service_name, "charlie", "val1")
        keyring.set_password(service_name, "alpha", "val2")
        keyring.set_password(service_name, "bravo", "val3")

        result = runner.invoke(
            app,
            ["list", "--service", service_name],
        )
        assert result.exit_code == 0
        lines = result.stdout.strip().split("\n")
        assert lines == ["alpha", "bravo", "charlie"]

    def test_list_default_service(self, file_keyring):
        """Omitting --service lists keys from DEFAULT_SERVICE."""
        keyring.set_password(DEFAULT_SERVICE, "mykey", "mysecret")

        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0
        assert "mykey" in result.stdout

    def test_list_empty_service(self, file_keyring, service_name):
        """Listing a service with no secrets shows a message."""
        result = runner.invoke(
            app,
            ["list", "--service", service_name],
        )
        assert result.exit_code == 0
        assert "No secrets found" in result.stderr

    def test_list_single_key(self, file_keyring, service_name):
        """Listing a service with one key returns just that key."""
        keyring.set_password(service_name, "onlykey", "value")

        result = runner.invoke(
            app,
            ["list", "--service", service_name],
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == "onlykey"

    def test_list_keys_with_dashes(self, file_keyring, service_name):
        """Keys with dashes are listed correctly (file backend decodes them)."""
        keyring.set_password(service_name, "my-key", "val1")
        keyring.set_password(service_name, "other-key", "val2")

        result = runner.invoke(
            app,
            ["list", "--service", service_name],
        )
        assert result.exit_code == 0
        lines = result.stdout.strip().split("\n")
        assert "my-key" in lines
        assert "other-key" in lines

    def test_list_does_not_show_values(self, file_keyring, service_name):
        """Listing only shows keys, never the secret values."""
        keyring.set_password(service_name, "mykey", "supersecretvalue")

        result = runner.invoke(
            app,
            ["list", "--service", service_name],
        )
        assert result.exit_code == 0
        assert "supersecretvalue" not in result.stdout

    def test_list_empty_service_no_stderr(self, file_keyring, service_name):
        """The 'No secrets found' message goes to stderr, not stdout."""
        result = runner.invoke(
            app,
            ["list", "--service", service_name],
        )
        assert result.exit_code == 0
        assert result.stdout == ""
        assert "No secrets found" in result.stderr

    def test_list_sorted_alphabetically(self, file_keyring, service_name):
        """Keys are returned in alphabetical order."""
        for key in ["zebra", "apple", "mango", "banana"]:
            keyring.set_password(service_name, key, "val")

        result = runner.invoke(
            app,
            ["list", "--service", service_name],
        )
        assert result.exit_code == 0
        lines = result.stdout.strip().split("\n")
        assert lines == sorted(lines)
