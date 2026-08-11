"""Pytest fixtures for secretsmgr tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import keyring
import pytest
from keyrings.alt.file import PlaintextKeyring


@pytest.fixture
def file_keyring(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> PlaintextKeyring:
    """Provide a file-based keyring backend in a temp directory.

    This avoids depending on a system keyring daemon (e.g. gnome-keyring)
    and gives us a clean, isolated store for every test.
    """
    keyring_file = tmp_path / "keyring.json"
    backend = PlaintextKeyring()
    backend.file_path = str(keyring_file)

    # Swap in the file backend for the duration of the test.
    monkeypatch.setattr(keyring, "get_keyring", lambda: backend)
    monkeypatch.setattr(keyring, "set_password", backend.set_password)
    monkeypatch.setattr(keyring, "get_password", backend.get_password)
    monkeypatch.setattr(keyring, "delete_password", backend.delete_password)
    monkeypatch.setattr(keyring, "get_credential", backend.get_credential)

    # Also set the env var so any code that checks it sees the file backend.
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyrings.alt.file.PlaintextKeyring")

    return backend


@pytest.fixture
def service_name() -> str:
    """A test service name."""
    return "test-service"
