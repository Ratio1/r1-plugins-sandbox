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
  exec "${BIN}"
fi
