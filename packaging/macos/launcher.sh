#!/bin/bash
set -euo pipefail

CONTENTS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${CONTENTS_DIR}/Resources/r1-plugins-sandbox"

if [ ! -x "${BIN}" ]; then
  if [ -x /usr/bin/osascript ]; then
    /usr/bin/osascript -e 'display dialog "Unable to locate the embedded r1-plugins-sandbox binary." buttons {"OK"} default button 1 with icon caution'
  fi
  exit 1
fi

# Copy the CLI to a stable location outside App Translocation so Terminal can exec it.
APP_SUPPORT_DIR="${HOME}/Library/Application Support/Ratio1"
INSTALLED_BIN="${APP_SUPPORT_DIR}/r1-plugins-sandbox"
if [ ! -e "${INSTALLED_BIN}" ] || ! cmp -s "${BIN}" "${INSTALLED_BIN}"; then
  mkdir -p "${APP_SUPPORT_DIR}"
  cp "${BIN}" "${INSTALLED_BIN}"
  chmod +x "${INSTALLED_BIN}"
  xattr -d com.apple.quarantine "${INSTALLED_BIN}" 2>/dev/null || true
fi
BIN="${INSTALLED_BIN}"

if [ -x /usr/bin/osascript ]; then
  /usr/bin/osascript - "${BIN}" <<'APPLESCRIPT'
on run argv
  set binPath to POSIX path of (item 1 of argv)
  tell application "Terminal"
    activate
    do script ("exec " & quoted form of binPath)
  end tell
end run
APPLESCRIPT
else
  /usr/bin/open -a Terminal "${BIN}"
fi
