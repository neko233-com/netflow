# Release checks

Run `pwsh -File scripts/build-release.ps1` from Windows after updating the
version in `mygo.json`. It uses the MyGo CLI to
build Windows amd64 and macOS arm64, checks the binary formats and macOS
minimum version, makes portable ZIPs with Unix executable permissions, and
calculates SHA-256 checksums. WiX Toolset 3.14 is required for the per-user MSI.
The destination must not already contain files with the same release names.

`python scripts/smoke_windows.py -Quiet` extracts the portable executable into a
unique directory inside `build`, starts it with an isolated configuration,
and checks an HTTP request through the local mixed proxy to a local server.
`python scripts/smoke_silent_windows.py -Quiet -Installed` verifies that the
installed Windows application starts its core with a hidden native window,
using a temporary configuration rather than the user's network settings.

`smoke_installer.ps1` applies only to the older NSIS build, not the MSI.
For MSI validation, inspect and install the newly built package for the current
user, check its registration and file hashes, and preserve the user's data.

`pwsh -File scripts/test-docker-tun.ps1` uses a disposable Linux Docker
container with its own network namespace, `NET_ADMIN` and `/dev/net/tun` to
check real TUN creation, removal and restoration of IPv4 routes and rules,
including when a separate kernel worker loses its parent connection. A second
isolated container checks that REJECT blocks traffic and DIRECT forwards it,
including DNS hijacking and a Fake-IP request resolved by a local test server.
The worker is also reloaded through System, Mixed, gVisor and Mips, and each
stack forwards traffic to the isolated peer.
The test requires a Linux Docker engine and package-mirror access. It does not
validate Windows Wintun, macOS utun or IPv6 routing.

These checks do not verify Windows TUN, code signatures, Apple notarization,
or running the macOS app on a Mac.

The Windows background worker icon is generated from `resources/icon.ico`:
`windres --input scripts/netflow-worker.rc --input-format rc --output-format coff --target pe-x86-64 --output cmd/netflow-kernel-worker/icon_windows_amd64.syso`.
The checked-in resource object lets release builds run without windres.
