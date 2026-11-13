#!/bin/sh
set -eu
python3 /opt/netflow/bridge.py &
bridge=$!
i=0
until python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:18765/health", timeout=1)' >/dev/null 2>&1; do
  kill -0 "$bridge" 2>/dev/null || exit 1
  i=$((i + 1))
  [ "$i" -lt 15 ] || exit 1
  sleep 1
done
/opt/netflow/download-media.sh
exec /run/entry.sh
