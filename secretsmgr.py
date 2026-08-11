#!/usr/bin/env python3
"""secretsmgr — a CLI for managing secrets via the OS keyring.

Usage:
    secretsmgr set KEY [VALUE] [--service NAME]
    secretsmgr get KEY [--service NAME]
    secretsmgr delete KEY [--service NAME]
    secretsmgr list [--service NAME]
    secretsmgr export FILE KEY [--service NAME]
    secretsmgr import FILE KEY [--service NAME]
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

import keyring
import typer
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing_extensions import Annotated

app = typer.Typer(
    help="Manage secrets in the OS keyring.",
    no_args_is_help=True,
)

DEFAULT_SERVICE = "secretsmgr"


def _resolve_service(service: str | None) -> str:
    """Return the service name, defaulting to DEFAULT_SERVICE."""
    return service or DEFAULT_SERVICE


@app.command()
def set(
    key: Annotated[str, typer.Argument(help="The key/identifier for the secret.")],
    value: Annotated[
        str | None,
        typer.Argument(
            help="The secret value. If omitted, reads from stdin (useful for piping)."
        ),
    ] = None,
    service: Annotated[
        str | None, typer.Option("--service", "-s", help="Service/namespace name.")
    ] = None,
) -> None:
    """Store a secret in the keyring."""
    if value is None:
        if sys.stdin.isatty():
            value = typer.prompt("value", hide_input=True)
        else:
            value = sys.stdin.read().rstrip("\n")

    svc = _resolve_service(service)
    try:
        keyring.set_password(svc, key, value)
    except keyring.errors.KeyringLocked as e:
        typer.echo(
            f"Keyring is locked: {e}. "
            "Try installing a secret service (e.g., gnome-keyring) "
            "or use the file backend: export PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring",
            err=True,
        )
        raise typer.Exit(1)
    typer.echo(f"Set secret '{key}' in service '{svc}'.", err=True)


@app.command()
def get(
    key: Annotated[str, typer.Argument(help="The key/identifier for the secret.")],
    service: Annotated[
        str | None, typer.Option("--service", "-s", help="Service/namespace name.")
    ] = None,
) -> None:
    """Retrieve a secret from the keyring and print it to stdout."""
    svc = _resolve_service(service)
    try:
        value = keyring.get_password(svc, key)
    except keyring.errors.KeyringLocked as e:
        typer.echo(
            f"Keyring is locked: {e}. "
            "Try installing a secret service (e.g., gnome-keyring) "
            "or use the file backend: export PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring",
            err=True,
        )
        raise typer.Exit(1)
    if value is None:
        typer.echo(f"No secret found for key '{key}' in service '{svc}'.", err=True)
        raise typer.Exit(1)
    # Print only the value to stdout — no trailing newline issues.
    sys.stdout.write(value)
    sys.stdout.write("\n")


@app.command()
def delete(
    key: Annotated[str, typer.Argument(help="The key/identifier for the secret.")],
    service: Annotated[
        str | None, typer.Option("--service", "-s", help="Service/namespace name.")
    ] = None,
) -> None:
    """Delete a secret from the keyring."""
    svc = _resolve_service(service)
    # delete_password returns None on success, raises PasswordDeleteError on failure.
    try:
        keyring.delete_password(svc, key)
        typer.echo(f"Deleted secret '{key}' from service '{svc}'.", err=True)
    except keyring.errors.KeyringLocked as e:
        typer.echo(
            f"Keyring is locked: {e}. "
            "Try installing a secret service (e.g., gnome-keyring) "
            "or use the file backend: export PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring",
            err=True,
        )
        raise typer.Exit(1)
    except keyring.errors.PasswordDeleteError:
        typer.echo(f"No secret found for key '{key}' in service '{svc}'.", err=True)
        raise typer.Exit(1)


@app.command(name="list")
def list_secrets(
    service: Annotated[
        str | None, typer.Option("--service", "-s", help="Service/namespace name.")
    ] = None,
) -> None:
    """List all secret keys for a service.

    Listing is supported on the SecretService backend (Linux) and the
    file backend (keyrings.alt). Other backends return only the first key.
    """
    svc = _resolve_service(service)
    backend = keyring.get_keyring()

    # Collect the list of backends to check (handle ChainerBackend).
    backends = []
    if hasattr(backend, "backends"):
        backends = backend.backends
    else:
        backends = [backend]

    # SecretService backend: search all items in the collection.
    for b in backends:
        if b.name == "SecretService":
            from secretstorage import Connection, Collection
            import dbus

            bus = dbus.SessionBus()
            try:
                with Connection(bus) as connection:
                    collection = Collection(connection)
                    items = collection.search_items({"service": svc})
                    keys = []
                    for item in items:
                        keys.append(item.get_attributes().get("username", "<unknown>"))
                    keys.sort()
                    if not keys:
                        typer.echo(f"No secrets found in service '{svc}'.", err=True)
                        return
                    for k in keys:
                        typer.echo(k)
                    return
            except Exception as e:
                typer.echo(f"Failed to list secrets: {e}", err=True)
                raise typer.Exit(1)

    # File backend (keyrings.alt.file): parse the config file directly.
    for b in backends:
        if "file" in b.name.lower():
            import configparser
            from keyrings.alt.file import escape_for_ini

            cfg = configparser.ConfigParser()
            cfg.read(b.file_path)
            # Section name is the escaped service name (dashes → _2D, uppercase).
            section = escape_for_ini(svc)
            if section not in cfg:
                typer.echo(f"No secrets found in service '{svc}'.", err=True)
                return
            # Keys are lowercased by configparser, so we decode case-insensitively.
            keys = sorted(cfg[section].keys())
            if not keys:
                typer.echo(f"No secrets found in service '{svc}'.", err=True)
                return
            for k in keys:
                # Decode the escape: _2d → - (case-insensitive since configparser
                # lowercased the keys).
                decoded = k.replace("_2d", "-")
                typer.echo(decoded)
            return

    # Other backends: try get_credential (returns first only, not all).
    cred = keyring.get_credential(svc, None)
    if cred is None:
        typer.echo(f"No secrets found in service '{svc}'.", err=True)
        return
    typer.echo(cred.username)


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

# PBKDF2 parameters for deriving a Fernet key from a user-provided password.
_PBKDF2_ITERATIONS = 600_000
_PBKDF2_KEY_LEN = 32  # Fernet requires a 32-byte key (urlsafe base64-encoded).


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from *password* and *salt* using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_PBKDF2_KEY_LEN,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def _encrypt(plaintext: bytes, password: str) -> bytes:
    """Encrypt *plaintext* with *password*, returning salt + ciphertext."""
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    token = Fernet(key).encrypt(plaintext)
    return salt + token


def _decrypt(blob: bytes, password: str) -> bytes:
    """Decrypt *blob* (salt + ciphertext) with *password*."""
    salt = blob[:16]
    token = blob[16:]
    key = _derive_key(password, salt)
    return Fernet(key).decrypt(token)


# ---------------------------------------------------------------------------
# Export / Import
# ---------------------------------------------------------------------------


def _collect_secrets(service: str) -> dict[str, str]:
    """Collect all secrets for *service* into a dict.

    Uses the same listing logic as the ``list`` command, then fetches each
    value individually.
    """
    backend = keyring.get_keyring()
    backends = backend.backends if hasattr(backend, "backends") else [backend]

    keys: list[str] = []

    # SecretService backend (Linux).
    for b in backends:
        if b.name == "SecretService":
            from secretstorage import Connection, Collection
            import dbus

            bus = dbus.SessionBus()
            with Connection(bus) as connection:
                collection = Collection(connection)
                items = collection.search_items({"service": service})
                for item in items:
                    keys.append(item.get_attributes().get("username", "<unknown>"))
            break

    # File backend (keyrings.alt).
    if not keys:
        for b in backends:
            if "file" in b.name.lower():
                import configparser
                from keyrings.alt.file import escape_for_ini

                cfg = configparser.ConfigParser()
                cfg.read(b.file_path)
                section = escape_for_ini(service)
                if section in cfg:
                    keys = [k.replace("_2d", "-") for k in cfg[section].keys()]
                break

    # Fallback: single credential.
    if not keys:
        cred = keyring.get_credential(service, None)
        if cred is not None:
            keys = [cred.username]

    return {k: keyring.get_password(service, k) for k in keys}


@app.command()
def export(
    file: Annotated[
        Path, typer.Argument(help="Output file path for the encrypted export.")
    ],
    key: Annotated[str, typer.Argument(help="Encryption key (password).")],
    service: Annotated[
        str | None, typer.Option("--service", "-s", help="Service/namespace name.")
    ] = None,
) -> None:
    """Export all secrets for a service to an encrypted file."""
    svc = _resolve_service(service)
    secrets = _collect_secrets(svc)
    if not secrets:
        typer.echo(f"No secrets found in service '{svc}'.", err=True)
        raise typer.Exit(1)

    payload = json.dumps(secrets, indent=2, sort_keys=True).encode()
    blob = _encrypt(payload, key)

    file.write_bytes(blob)
    typer.echo(
        f"Exported {len(secrets)} secret(s) from service '{svc}' to '{file}'.",
        err=True,
    )


@app.command(name="import")
def import_(
    file: Annotated[
        Path, typer.Argument(help="Input file path (encrypted export).")
    ],
    key: Annotated[str, typer.Argument(help="Decryption key (password).")],
    service: Annotated[
        str | None, typer.Option("--service", "-s", help="Service/namespace name.")
    ] = None,
) -> None:
    """Import secrets from an encrypted file into the keyring."""
    svc = _resolve_service(service)
    blob = file.read_bytes()
    try:
        plaintext = _decrypt(blob, key)
    except InvalidToken:
        typer.echo("Decryption failed: wrong key or corrupted file.", err=True)
        raise typer.Exit(1)

    secrets: dict[str, str] = json.loads(plaintext)
    for k, v in secrets.items():
        keyring.set_password(svc, k, v)

    typer.echo(
        f"Imported {len(secrets)} secret(s) into service '{svc}' from '{file}'.",
        err=True,
    )


if __name__ == "__main__":
    app()
