# secretsmgr

A CLI for managing secrets via the OS keyring.

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Set a secret (prompts for value if not provided)
secretsmgr set mykey "myvalue"
secretsmgr set mykey  # prompts for value

# Set with a custom service/namespace
secretsmgr set mykey "myvalue" --service prod

# Get a secret (prints value to stdout)
secretsmgr get mykey
secretsmgr get mykey --service prod

# List all secret keys for a service
secretsmgr list
secretsmgr list --service prod

# Delete a secret
secretsmgr delete mykey
secretsmgr delete mykey --service prod
```

## Backend

Uses Python's `keyring` library, which defaults to the OS keyring:
- **macOS**: Keychain
- **Windows**: Credential Locker
- **Linux**: Secret Service (GNOME Keyring / KWallet)

For headless environments, you can use a file-based backend:

```bash
export PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring
```

> Note: The file backend stores secrets in plaintext. Use only for testing.
