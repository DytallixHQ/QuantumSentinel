#!/usr/bin/env sh
set -eu

REPOSITORY_URL="${QS_REPOSITORY_URL:-https://github.com/DytallixHQ/QuantumSentinel.git}"
INSTALL_DIRECTORY="${QS_INSTALL_DIR:-${PWD}/QuantumSentinel}"

say() { printf '%s\n' "$*"; }
fail() { say "Quantum Sentinel setup stopped: $*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || fail "Git is required. Install Git and run this command again."
command -v node >/dev/null 2>&1 || fail "Node.js 20.19 or newer is required: https://nodejs.org/"
command -v npm >/dev/null 2>&1 || fail "npm is required and normally ships with Node.js."

NODE_MAJOR=$(node -p "Number(process.versions.node.split('.')[0])")
NODE_MINOR=$(node -p "Number(process.versions.node.split('.')[1])")
if [ "$NODE_MAJOR" -lt 20 ] || { [ "$NODE_MAJOR" -eq 20 ] && [ "$NODE_MINOR" -lt 19 ]; }; then
  fail "Node.js 20.19 or newer is required. Current version: $(node --version)"
fi

if [ -d "$INSTALL_DIRECTORY/.git" ]; then
  CURRENT_REMOTE=$(git -C "$INSTALL_DIRECTORY" remote get-url origin 2>/dev/null || true)
  [ "$CURRENT_REMOTE" = "$REPOSITORY_URL" ] || fail "$INSTALL_DIRECTORY is a different Git repository. Set QS_INSTALL_DIR to another location."
  say "Updating Quantum Sentinel in $INSTALL_DIRECTORY..."
  git -C "$INSTALL_DIRECTORY" pull --ff-only
elif [ -e "$INSTALL_DIRECTORY" ]; then
  fail "$INSTALL_DIRECTORY already exists and is not a Quantum Sentinel checkout. Set QS_INSTALL_DIR to another location."
else
  say "Downloading Quantum Sentinel to $INSTALL_DIRECTORY..."
  git clone --depth 1 "$REPOSITORY_URL" "$INSTALL_DIRECTORY"
fi

say "Installing dependencies and building the dashboard..."
cd "$INSTALL_DIRECTORY"
npm ci --no-audit --no-fund
npm run build

say "Quantum Sentinel installation is complete."
if [ "${QS_INSTALL_ONLY:-0}" = "1" ]; then
  say "Start it later with: cd \"$INSTALL_DIRECTORY\" && npm start"
  exit 0
fi

exec npm start
