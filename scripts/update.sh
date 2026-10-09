#!/usr/bin/env bash
# Update a Dynascan git clone to the latest version on GitHub.
#   ./scripts/update.sh
# Reinstalls Python dependencies only if pyproject.toml changed.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
set -euo pipefail
cd "$(dirname "$0")/.."

[[ -d .git ]] || { echo "This folder is not a git clone. Clone your repo first: git clone <repo-url>"; exit 1; }

before=$(git rev-parse HEAD)
git pull --ff-only || {
  echo
  echo "Pull failed. If you edited files locally, run:  git stash && ./scripts/update.sh && git stash pop"
  exit 1
}
after=$(git rev-parse HEAD)

if [[ "$before" == "$after" ]]; then
  echo "Already up to date: $(git log -1 --oneline)"
  exit 0
fi

echo "Updated:"
git log --oneline "$before..$after"

if git diff --name-only "$before" "$after" | grep -qx 'pyproject.toml'; then
  echo "pyproject.toml changed - refreshing dependencies"
  if [[ -f .venv/bin/activate ]]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
    pip install -e ".[gui,dev]" || pip install -e ".[dev]"
  else
    echo "No .venv found; run ./scripts/install-kali.sh"
  fi
fi
echo "Done. Restart dynascan / dynascan-gui to use the new version."
