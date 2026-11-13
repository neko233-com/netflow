param(
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$oldLocation = Get-Location
try {
    Set-Location -LiteralPath $repo
    (Get-Process -Id $PID).PriorityClass = 'BelowNormal'
    $env:GOMAXPROCS = '1'
    $env:GOFLAGS = '-p=1'
    $env:CGO_ENABLED = '0'
    $buildArgs = @('tool', 'mygo', 'build', '-platform', 'windows/amd64,darwin/arm64', '-skip-dmg', '-o', 'build/release-artifacts')
    if ($SkipInstaller) { $buildArgs += '-skip-installer' }
    & go @buildArgs
    if ($LASTEXITCODE -ne 0) { throw "MyGo build failed with exit code $LASTEXITCODE" }
    & python scripts/package_release.py
    if ($LASTEXITCODE -ne 0) { throw "Packaging failed with exit code $LASTEXITCODE" }
} finally {
    Set-Location -LiteralPath $oldLocation
}
