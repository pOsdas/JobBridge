#!/bin/bash
set -euo pipefail
umask 077
mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
profile_dir=/profile/chromium
mkdir -p "$profile_dir"
exec 9>/profile/.job-bridge-browser.lock
if ! flock -n 9; then
    printf '%s\n' 'Профиль Chromium уже используется другим контейнером.' >&2
    exit 75
fi
# Every browser started by this service holds the volume lock. A new container
# can remove stale Chromium symlinks only after the previous holder has exited.
rm -f -- "$profile_dir/SingletonLock" "$profile_dir/SingletonSocket" "$profile_dir/SingletonCookie"

children=()
cleanup() {
    if (("${#children[@]}")); then
        kill "${children[@]}" 2>/dev/null || true
        wait || true
    fi
}
trap cleanup EXIT
trap 'exit 0' INT TERM

Xvfb "$DISPLAY" -screen 0 1440x900x24 -nolisten tcp &
children+=("$!")
for attempt in {1..50}; do
    xdpyinfo >/dev/null 2>&1 && break
    sleep 0.2
done
xdpyinfo >/dev/null

openbox --sm-disable &
children+=("$!")
x11vnc -display "$DISPLAY" -localhost -rfbport 5900 -nopw -forever -shared -noxdamage &
children+=("$!")
websockify --web /usr/share/novnc 0.0.0.0:6080 127.0.0.1:5900 &
children+=("$!")
chromium --disable-setuid-sandbox --no-first-run --no-default-browser-check \
    --user-data-dir=/profile/chromium --password-store=basic \
    --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 \
    --start-maximized --lang=ru-RU https://hh.ru/ &
children+=("$!")

wait -n "${children[@]}"
