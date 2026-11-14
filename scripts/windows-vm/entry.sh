#!/bin/sh
set -eu
# Opt-in validation of the host retry path. The marker is unique to this run
# and stored only on the owned validation volume; ordinary runs never use it.
if [ "${NETFLOW_TEST_BOOT_FAILURE:-}" = "1" ]; then
  case "${NETFLOW_RUN_ID:-}" in
    *[!0-9a-f]*|'') echo 'Invalid retry test run ID' >&2; exit 1 ;;
  esac
  marker="/storage/.netflow-retry-test-$NETFLOW_RUN_ID"
  if [ ! -f "$marker" ]; then
    : > "$marker"
    echo 'NETFLOW_TEST_SIMULATED: Timeout while waiting for QEMU to boot the machine, terminating...' >&2
    exit 1
  fi
  rm -f -- "$marker"
fi
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
# A read-only CD carries the fixed test payload. It is not a virtual hard
# disk and avoids downloading or self-updating executables inside the guest.
genisoimage -quiet -J -R -V NETFLOWVM -o /tmp/netflow-payload.iso /payload
export ARGUMENTS="${ARGUMENTS:-} -device ich9-ahci,id=netflow-cd-ahci -drive id=netflow-cd,file=/tmp/netflow-payload.iso,format=raw,if=none,media=cdrom,readonly=on -device ide-cd,drive=netflow-cd,bus=netflow-cd-ahci.0,serial=NETFLOW-VM-01"
exec /run/entry.sh
