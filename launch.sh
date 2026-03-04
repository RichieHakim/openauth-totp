#!/usr/bin/env bash
# macOS / Linux launcher
DIR="$(cd "$(dirname "$0")" && pwd)"

chrome=""
if [ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
    chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
elif command -v google-chrome &>/dev/null; then
    chrome="google-chrome"
elif command -v chromium-browser &>/dev/null; then
    chrome="chromium-browser"
elif command -v chromium &>/dev/null; then
    chrome="chromium"
fi

if [ -n "$chrome" ]; then
    "$chrome" --app="file://${DIR}/openauth.html" &
else
    echo "Chrome not found — opening in default browser."
    python3 -m webbrowser "file://${DIR}/openauth.html"
fi
