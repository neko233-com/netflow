# Release checks

Run `pwsh -File scripts/build-release.ps1` from Windows after updating the
version in `mygo.json` and `internal/ui/pages.go`. It uses the MyGo CLI to
build Windows amd64 and macOS arm64, checks the binary formats and macOS
minimum version, makes portable ZIPs with Unix executable permissions, and
calculates SHA-256 checksums. WiX Toolset 3.14 is required for the per-user MSI.
The destination must not already contain files with the same release names.

`python scripts/smoke_windows.py` extracts the portable executable into a
unique directory inside `build`, starts it with an isolated configuration,
and checks an HTTP request through the local mixed proxy to a local server.
`python scripts/smoke_silent_windows.py -Quiet -Installed` verifies that the
installed Windows application starts its core with a hidden native window,
using a temporary configuration rather than the user's network settings.

`smoke_installer.ps1` applies only to the older NSIS build, not the MSI.
For MSI validation, inspect and install the newly built package for the current
user, check its registration and file hashes, and preserve the user's data.

These checks do not verify real system-proxy switching, TUN, code signatures,
Apple notarization, or running the macOS app on a Mac.
