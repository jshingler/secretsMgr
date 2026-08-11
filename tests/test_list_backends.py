"""Regression tests for the backend-specific branches of ``_list_keys``.

These exercise the SecretService and macOS Keychain listing paths via
mocks, since neither a real (unlocked) SecretService collection nor a real
macOS Keychain is available in CI/sandboxed test environments. The other
backends (file, generic fallback) are covered end-to-end in test_list.py
via the file_keyring fixture.

Regression coverage:
  - SecretService: `_list_keys` must match on the real `.name` value
    ("SecretService Keyring"), not the bare "SecretService" string the
    original code checked (which never matched — see git history).
  - SecretService: must use the current `secretstorage` module-level API
    (`dbus_init` / `search_items`), not the removed `Connection`/`Collection`
    classes the original code called (which raised ImportError as soon as
    the name-match bug above was fixed and this branch could execute).
  - macOS: `_list_keys` must shell out to `security dump-keychain` and
    parse only entries matching the requested service, since keyring's
    macOS backend has no listing API of its own.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from secretsmgr import _list_keys, _list_keys_macos


class FakeBackend:
    """Minimal stand-in for a keyring backend with a `.name` attribute."""

    def __init__(self, name: str):
        self.name = name


class TestSecretServiceListing:
    """Regression tests for the SecretService branch of _list_keys."""

    def test_matches_real_backend_name(self, monkeypatch):
        """The real SecretService backend reports name 'SecretService Keyring',
        not bare 'SecretService' — _list_keys must match on that.
        """
        import keyring

        chainer = MagicMock()
        chainer.backends = [FakeBackend("SecretService Keyring")]
        monkeypatch.setattr(keyring, "get_keyring", lambda: chainer)
        monkeypatch.setattr("sys.platform", "linux")

        fake_item = MagicMock()
        fake_item.get_attributes.return_value = {"username": "mykey"}

        with patch("secretstorage.dbus_init") as mock_init, patch(
            "secretstorage.search_items"
        ) as mock_search:
            mock_init.return_value = object()
            mock_search.return_value = [fake_item]

            keys = _list_keys("myservice")

        assert keys == ["mykey"]
        mock_search.assert_called_once()
        # Called with (connection, {"service": "myservice"}) — verify the
        # attributes dict, not the connection object identity.
        _, called_attrs = mock_search.call_args[0]
        assert called_attrs == {"service": "myservice"}

    def test_uses_current_secretstorage_api(self, monkeypatch):
        """Must call secretstorage.dbus_init/search_items (module-level),
        never the removed Connection/Collection classes.
        """
        import keyring

        chainer = MagicMock()
        chainer.backends = [FakeBackend("SecretService Keyring")]
        monkeypatch.setattr(keyring, "get_keyring", lambda: chainer)
        monkeypatch.setattr("sys.platform", "linux")

        with patch("secretstorage.dbus_init") as mock_init, patch(
            "secretstorage.search_items"
        ) as mock_search:
            mock_init.return_value = object()
            mock_search.return_value = []

            result = _list_keys("myservice")

        assert result == []
        mock_init.assert_called_once()
        mock_search.assert_called_once()

    def test_multiple_items_sorted(self, monkeypatch):
        """Multiple matching items are returned sorted."""
        import keyring

        chainer = MagicMock()
        chainer.backends = [FakeBackend("SecretService Keyring")]
        monkeypatch.setattr(keyring, "get_keyring", lambda: chainer)
        monkeypatch.setattr("sys.platform", "linux")

        items = []
        for name in ["zebra", "apple", "mango"]:
            item = MagicMock()
            item.get_attributes.return_value = {"username": name}
            items.append(item)

        with patch("secretstorage.dbus_init") as mock_init, patch(
            "secretstorage.search_items"
        ) as mock_search:
            mock_init.return_value = object()
            mock_search.return_value = items

            keys = _list_keys("myservice")

        assert keys == ["apple", "mango", "zebra"]

    def test_no_items_returns_empty_list(self, monkeypatch):
        """An empty search result returns [] (list still 'supported', just empty)."""
        import keyring

        chainer = MagicMock()
        chainer.backends = [FakeBackend("SecretService Keyring")]
        monkeypatch.setattr(keyring, "get_keyring", lambda: chainer)
        monkeypatch.setattr("sys.platform", "linux")

        with patch("secretstorage.dbus_init") as mock_init, patch(
            "secretstorage.search_items"
        ) as mock_search:
            mock_init.return_value = object()
            mock_search.return_value = []

            keys = _list_keys("myservice")

        assert keys == []


class TestMacOSListing:
    """Regression tests for _list_keys_macos (the `security dump-keychain` path)."""

    # Symbolic "svce" tag — the format assumed (wrongly, as the sole case) by
    # the first cut of this parser.
    SAMPLE_DUMP = """\
keychain: "/Users/jim/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="ping"
    "svce"<blob>="secretsmgr"
data:
"pong"
keychain: "/Users/jim/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="otherkey"
    "svce"<blob>="secretsmgr"
data:
"otherval"
keychain: "/Users/jim/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="unrelated"
    "svce"<blob>="some-other-app"
data:
"whatever"
"""

    # Raw-integer service tag — reproduces a real `security dump-keychain`
    # dump from a SQL-based login.keychain-db (macOS, reported in the wild):
    # "svce" never appears at all; the service string prints under a bare
    # hex attribute tag (0x00000007) instead. "acct" still prints
    # symbolically. This is the format the original parser silently
    # dropped every item under — it looked only for a line starting with
    # `"svce"`.
    SAMPLE_DUMP_RAW_TAG = """\
keychain: "/Users/jshingler/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="secretsmgr"
    0x00000008 <blob>=<NULL>
    "acct"<blob>="ping"
    "cdat"<timedate>=0x32303236303831313233333035305A00  "20260811233050Z\\000"
    "crtr"<uint32>=<NULL>
data:
"pong"
keychain: "/Users/jshingler/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="secretsmgr"
    "acct"<blob>="otherkey"
data:
"otherval"
keychain: "/Users/jshingler/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="some-other-app"
    "acct"<blob>="unrelated"
data:
"whatever"
"""

    def test_lists_only_matching_service(self):
        """Only items whose svce matches the requested service are returned."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=self.SAMPLE_DUMP, returncode=0
            )
            keys = _list_keys_macos("secretsmgr")

        assert keys == ["otherkey", "ping"]
        assert "unrelated" not in keys

    def test_lists_only_matching_service_raw_tag(self):
        """Same as above, but against a dump where the service attribute
        prints under a raw hex tag (0x00000007) instead of "svce" — the
        real-world case that the original parser silently dropped.
        """
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=self.SAMPLE_DUMP_RAW_TAG, returncode=0
            )
            keys = _list_keys_macos("secretsmgr")

        assert keys == ["otherkey", "ping"]
        assert "unrelated" not in keys

    def test_empty_dump_returns_empty_list(self):
        """No matching items returns an empty list, not None or an error."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", returncode=0)
            keys = _list_keys_macos("secretsmgr")

        assert keys == []

    def test_security_command_missing(self):
        """If `security` isn't on PATH (shouldn't happen on real macOS), exit
        cleanly with an error rather than a raw traceback.
        """
        import typer

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            with pytest.raises(typer.Exit):
                _list_keys_macos("secretsmgr")

    def test_does_not_include_secret_values(self):
        """Only attributes are parsed — secret values (the `data:` lines) never
        leak into the returned key list.
        """
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=self.SAMPLE_DUMP, returncode=0
            )
            keys = _list_keys_macos("secretsmgr")

        assert "pong" not in keys
        assert "otherval" not in keys

    def test_darwin_platform_routes_to_macos_listing(self, monkeypatch):
        """_list_keys dispatches to _list_keys_macos when sys.platform is darwin,
        bypassing the SecretService/file-backend branches entirely.
        """
        monkeypatch.setattr("sys.platform", "darwin")

        with patch("secretsmgr._list_keys_macos") as mock_macos:
            mock_macos.return_value = ["ping"]
            result = _list_keys("secretsmgr")

        mock_macos.assert_called_once_with("secretsmgr")
        assert result == ["ping"]
