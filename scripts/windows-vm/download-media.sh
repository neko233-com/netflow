#!/bin/sh
set -eu
# Keep a resumable official ISO outside upstream's disposable /storage/tmp.
# The hard link avoids storing a second copy during installation.
[ ! -f /storage/windows.system ] && [ ! -f /storage/windows.boot ] || exit 0
name=win10x64-enterprise-ltsc-eval.iso
url=https://software-download.microsoft.com/download/pr/19044.1288.211006-0501.21h2_release_svc_refresh_CLIENT_LTSC_EVAL_x64FRE_en-us.iso
sum=e4ab2e3535be5748252a8d5d57539a6e59be8d6726345ee10e7afd2cb89fefb5
mkdir -p /storage/netflow-media
file=/storage/netflow-media/$name
verified=0
if [ -f "$file" ] && [ ! -f "$file.aria2" ]; then
  if printf '%s  %s\n' "$sum" "$file" | sha256sum -c - >/dev/null 2>&1; then
    verified=1
  else
    rm -f -- "$file"
  fi
fi
if [ ! -f "$file" ] || [ -f "$file.aria2" ]; then
  echo 'Downloading official Windows evaluation media (resumable)...'
  aria2c --no-conf=true --dir=/storage/netflow-media --out="$name" --split=16 --max-connection-per-server=16 --file-allocation=none --continue=true --allow-overwrite=true --auto-file-renaming=false --max-tries=5 --retry-wait=5 --connect-timeout=30 --timeout=60 --summary-interval=60 --checksum="sha-256=$sum" "$url"
  verified=1
fi
[ "$verified" -eq 1 ] || exit 1
ln -f -- "$file" "/storage/$name"
