#!/usr/bin/env bash
# Install Dynascan on Kali / Debian / Ubuntu into an isolated virtualenv.
# Usage:  ./scripts/install-kali.sh            (CLI + GUI)
#         ./scripts/install-kali.sh --no-gui   (CLI only, smaller)
set -euo pipefail

EXTRA="gui"
[[ "${1:-}" == "--no-gui" ]] && EXTRA=""

cd "$(dirname "$0")/.."

sudo apt-get update -qq
sudo apt-get install -y python3 python3-venv python3-pip
if [[ -n "$EXTRA" ]]; then
  # Qt runtime libraries needed by the GUI on a minimal Kali install
  sudo apt-get install -y libxcb-cursor0 libxkbcommon-x11-0 libgl1 || true
fi

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
if [[ -n "$EXTRA" ]]; then pip install -e ".[gui,dev]"; else pip install -e ".[dev]"; fi

echo
echo "Installed. Activate with:  source $(pwd)/.venv/bin/activate"
echo "Then run:                  dynascan --help        (CLI)"
[[ -n "$EXTRA" ]] && echo "                           dynascan-gui           (desktop GUI)"
echo "Reminder: only scan systems you own or have written permission to test."
