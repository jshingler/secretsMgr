To use secretsmgr on another computer, you have several options:

  Option 1: Copy the project and recreate the venv

  # On the new computer, copy the project directory
  cp -r /path/to/secretsMgr /destination/

  # Navigate to the project
  cd /destination/secretsMgr

  # Create a new virtual environment
  python3 -m venv .venv

  # Install dependencies
  . .venv/bin/activate
  pip install -e .

  # Now secretsmgr is available
  secretsmgr --help

  Option 2: Install as a global command (no venv)

  # Install keyring and typer globally
  pip install keyring typer

  # Install secretsmgr globally
  pip install -e /path/to/secretsMgr

  # Now secretsmgr is available system-wide
  secretsmgr --help

  Option 3: Use pipx (recommended for isolated CLI tools)

  # Install pipx if not already installed
  sudo apt install pipx  # Ubuntu/Debian
  # or
  brew install pipx      # macOS

  # Install secretsmgr in an isolated environment
  pipx install /path/to/secretsMgr

  # Now secretsmgr is available globally
  secretsmgr --help

  Option 4: Package and distribute

  Create a proper distribution package:

  cd /path/to/secretsMgr
  python -m build  # Creates dist/secretsmgr-0.1.0-py3-none-any.whl
  pip install dist/secretsmgr-0.1.0-py3-none-any.whl

  Note: The pyproject.toml already has the [project.scripts] entry point configured, so pip install will automatically create the secretsmgr command.
