# Release checks

Run `pwsh -File scripts/build-release.ps1` from Windows after updating the
version in `mygo.json` and `internal/ui/pages.go`. It uses the MyGo CLI to
build Windows amd64 and macOS arm64, checks the binary formats and macOS
minimum version, makes portable ZIPs with Unix executable permissions, and
calculates SHA-256 checksums. The destination must not already contain files
with the same release names. Pass `-SkipInstaller` to skip the Windows setup.

`python scripts/smoke_windows.py` extracts the portable executable into a
unique directory inside `build`, starts it with an isolated configuration,
and checks an HTTP request through the local mixed proxy to a local server.

`pwsh -File scripts/smoke_installer.ps1 -Quiet` checks setup and uninstallation
in a unique directory inside `build`. It first refuses to run if a NetFlow
uninstall entry or shortcut already exists, and checks that the entry belongs
to its temporary directory before running the uninstaller. MyGo's generated
NSIS installer uses the Windows system PowerShell internally for its own
application-close helper; all scripts in this repository use PowerShell 7.

These checks do not verify real system-proxy switching, TUN, code signatures,
Apple notarization, or running the macOS app on a Mac.
