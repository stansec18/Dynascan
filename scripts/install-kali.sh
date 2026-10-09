#!/usr/bin/env bash
# Install Dynascan on Kali / Debian / Ubuntu into an isolated virtualenv.
#   ./scripts/install-kali.sh            CLI + GUI (GUI is skipped automatically if it cannot be installed)
#   ./scripts/install-kali.sh --no-gui   CLI only (fastest, smallest)
# Run it with bash (not "sh scripts/install-kali.sh").

# Re-exec under bash if started with sh/dash.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

WANT_GUI=1
[[ "${1:-}" == "--no-gui" ]] && WANT_GUI=0

step() { printf '\n==> %s\n' "$*"; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

# sudo only when needed (root, or no sudo installed, runs commands directly)
SUDO=""
if [[ $EUID -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 && SUDO="sudo" || echo "note: not root and sudo not found - skipping apt packages"
fi

step "Checking Python (3.10+ required)"
command -v python3 >/dev/null 2>&1 || die "python3 not found. Install it with: sudo apt install python3"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || die "Python $(python3 -V 2>&1) is too old; Dynascan needs 3.10 or newer."

step "Installing system packages (failures here are non-fatal)"
if [[ -n "$SUDO" || $EUID -eq 0 ]]; then
  $SUDO apt-get update -qq || echo "warning: apt-get update failed (check network / Kali mirror); continuing"
  $SUDO apt-get install -y python3-venv python3-pip \
    || echo "warning: could not install python3-venv/pip via apt; continuing"
  if [[ $WANT_GUI -eq 1 ]]; then
    # Qt runtime libraries commonly missing on minimal Kali installs
    for pkg in libxcb-cursor0 libxkbcommon-x11-0 libgl1 libegl1; do
      $SUDO apt-get install -y "$pkg" >/dev/null 2>&1 || echo "warning: optional package $pkg not installed"
    done
  fi
fi

step "Creating virtualenv (.venv)"
rm -rf .venv
python3 -m venv .venv || die "venv creation failed. Run: sudo apt install python3-venv  and try again."
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip -q || echo "warning: could not upgrade pip; continuing"

step "Installing Dynascan (CLI)"
pip install -e ".[dev]" || die "CLI install failed - see the pip error above."

GUI_OK=0
if [[ $WANT_GUI -eq 1 ]]; then
  step "Installing GUI (PySide6, ~200 MB)"
  if pip install -e ".[gui]"; then GUI_OK=1; else
    echo "warning: GUI install failed. The CLI is installed and works; retry later with: pip install -e '.[gui]'"
  fi
fi

step "Self-test"
dynascan --list-checks >/dev/null && echo "CLI OK ($(dynascan --list-checks | wc -l) checks)" || die "dynascan command failed to start"
pytest -q 2>&1 | tail -1 || true

cat <<EOF

Done. Activate the environment in each new terminal with:
    source $(pwd)/.venv/bin/activate
Then:
    dynascan --help
EOF
[[ $GUI_OK -eq 1 ]] && echo "    dynascan-gui"
echo "Only scan systems you own or have written permission to test."
