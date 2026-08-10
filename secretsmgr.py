#!/usr/bin/env python3
"""secretsmgr — a CLI for managing secrets via the OS keyring.

Usage:
    secretsmgr set KEY [VALUE] [--service NAME]
    secretsmgr get KEY [--service NAME]
    secretsmgr delete KEY [--service NAME]
    secretsmgr list [--service NAME]
"""

from __future__ import annotations

import sys

import keyring
import typer
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


if __name__ == "__main__":
    app()
