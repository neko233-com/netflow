$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$oldLocation = Get-Location
try {
    Set-Location -LiteralPath $repo
    (Get-Process -Id $PID).PriorityClass = 'BelowNormal'
    $env:GOMAXPROCS = '1'
    $env:GOFLAGS = '-p=1 -tags=with_gvisor,no_tailscale'
    $env:CGO_ENABLED = '0'
    $version = (Get-Content -Raw mygo.json | ConvertFrom-Json).version
    $numericVersion = $version.Split('-')[0]
    if ($numericVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid MSI version' }
    $buildDir = "build/release-artifacts-$version"
    $msiDir = "build/msi/$version"
    New-Item -ItemType Directory -Force resources/windows-amd64,resources/darwin-arm64,$msiDir | Out-Null
    $env:GOOS = 'windows'; $env:GOARCH = 'amd64'
    & go build -o resources/windows-amd64/netflow-agent.exe ./cmd/netflow-agent
    if ($LASTEXITCODE -ne 0) { throw 'Windows agent build failed' }
    & go build '-ldflags=-H=windowsgui' -o resources/windows-amd64/netflow-kernel-worker.exe ./cmd/netflow-kernel-worker
    if ($LASTEXITCODE -ne 0) { throw 'Windows kernel worker build failed' }
    $env:GOOS = 'darwin'; $env:GOARCH = 'arm64'
    & go build -o resources/darwin-arm64/netflow-agent ./cmd/netflow-agent
    if ($LASTEXITCODE -ne 0) { throw 'macOS agent build failed' }
    Remove-Item Env:GOOS,Env:GOARCH
    $buildArgs = @('tool', 'mygo', 'build', '-platform', 'windows/amd64,darwin/arm64', '-skip-dmg', '-skip-installer', '-o', $buildDir)
    & go @buildArgs
    if ($LASTEXITCODE -ne 0) { throw "MyGo build failed with exit code $LASTEXITCODE" }
    $wix = 'C:\Program Files (x86)\WiX Toolset v3.14\bin'
    if (-not (Test-Path -LiteralPath (Join-Path $wix 'heat.exe'))) { throw 'WiX Toolset v3.14 is required' }
    $source = (Resolve-Path "$buildDir/windows-amd64").Path
    $icon = (Resolve-Path 'resources/icon.ico').Path
    & (Join-Path $wix 'heat.exe') dir $source -cg ApplicationFiles -dr INSTALLFOLDER -srd -sreg -scom -ag -var var.SourceDir -out "$msiDir/files.wxs"
    if ($LASTEXITCODE -ne 0) { throw 'WiX harvest failed' }
    & python scripts/fix_msi_components.py "$msiDir/files.wxs"
    if ($LASTEXITCODE -ne 0) { throw 'WiX component preparation failed' }
    & (Join-Path $wix 'candle.exe') -nologo -arch x64 "-dSourceDir=$source" "-dIconFile=$icon" "-dProductVersion=$numericVersion" -out "$msiDir/" installer/netflow.wxs "$msiDir/files.wxs"
    if ($LASTEXITCODE -ne 0) { throw 'WiX compile failed' }
    & (Join-Path $wix 'light.exe') -nologo -sice:ICE91 -out "$msiDir/NetFlow-$version-windows-amd64.msi" "$msiDir/netflow.wixobj" "$msiDir/files.wixobj"
    if ($LASTEXITCODE -ne 0) { throw 'WiX link failed' }
    & python scripts/package_release.py
    if ($LASTEXITCODE -ne 0) { throw "Packaging failed with exit code $LASTEXITCODE" }
} finally {
    Set-Location -LiteralPath $oldLocation
}
