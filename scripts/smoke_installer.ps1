param([switch]$Quiet)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$build = (Resolve-Path -LiteralPath (Join-Path $repo 'build')).Path
$config = Get-Content -Raw -LiteralPath (Join-Path $repo 'mygo.json') | ConvertFrom-Json
$installer = Join-Path $build "releases\$($config.version)\NetFlow-$($config.version)-windows-amd64-setup.exe"
$sourceExe = Join-Path $build 'release-artifacts\windows-amd64\NetFlow.exe'
$target = Join-Path $build ('installer-smoke-' + [guid]::NewGuid().ToString('N'))
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\com.neko233.netflow'
$startLink = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\NetFlow.lnk'
$desktopLink = Join-Path ([Environment]::GetFolderPath('Desktop')) 'NetFlow.lnk'

if (-not $target.StartsWith($build + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected installer test path' }
if ($target.Contains(' ')) { throw 'NSIS silent test requires a build path without spaces' }
if ((Test-Path -LiteralPath $target) -or (Test-Path -LiteralPath $key) -or (Test-Path -LiteralPath $startLink) -or (Test-Path -LiteralPath $desktopLink)) {
    throw 'An existing NetFlow installation or shortcut was found; isolated installer test was not started.'
}
if (-not (Test-Path -LiteralPath $installer -PathType Leaf) -or -not (Test-Path -LiteralPath $sourceExe -PathType Leaf)) { throw 'Build the release first' }
(Get-Process -Id $PID).PriorityClass = 'BelowNormal'

try {
    $proc = Start-Process -FilePath $installer -ArgumentList @('/S', "/D=$target") -WindowStyle Hidden -PassThru -Wait
    if ($proc.ExitCode -ne 0) { throw "Installer failed with exit code $($proc.ExitCode)" }
    $installed = Join-Path $target 'NetFlow.exe'
    $uninstaller = Join-Path $target 'Uninstall.exe'
    if (-not (Test-Path -LiteralPath $installed -PathType Leaf) -or -not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw 'Installer omitted the executable or uninstaller' }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $sourceExe).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $installed).Hash) { throw 'Installed executable differs from the release build' }
    foreach ($name in @('LICENSE', 'LICENSES', 'README.md')) {
        if (-not (Test-Path -LiteralPath (Join-Path $target $name))) { throw "Installer omitted $name" }
    }
    $registered = (Get-ItemProperty -LiteralPath $key).InstallLocation
    if (-not [String]::Equals($registered.TrimEnd('\'), $target.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected install location: $registered" }
    if (-not (Test-Path -LiteralPath $startLink -PathType Leaf)) { throw 'Start menu shortcut was not created' }
} finally {
    $uninstaller = Join-Path $target 'Uninstall.exe'
    if (Test-Path -LiteralPath $uninstaller -PathType Leaf) {
        $resolved = (Resolve-Path -LiteralPath $target).Path
        $registered = if (Test-Path -LiteralPath $key) { (Get-ItemProperty -LiteralPath $key).InstallLocation } else { '' }
        if (-not [String]::Equals($resolved, $target, [StringComparison]::OrdinalIgnoreCase) -or -not [String]::Equals($registered.TrimEnd('\'), $target.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Installer cleanup refused: test location or ownership did not match'
        }
        $remove = Start-Process -FilePath $uninstaller -ArgumentList '/S' -WindowStyle Hidden -PassThru -Wait
        if ($remove.ExitCode -ne 0) { throw "Uninstaller failed with exit code $($remove.ExitCode)" }
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        while ((Test-Path -LiteralPath $target) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
        if ((Test-Path -LiteralPath $target) -or (Test-Path -LiteralPath $key) -or (Test-Path -LiteralPath $startLink)) { throw 'Uninstaller did not remove all test artifacts' }
    } elseif (Test-Path -LiteralPath $target) {
        throw "Partial installer test remains at $target"
    }
}
if (-not $Quiet) { Write-Output 'Installer and uninstaller passed the isolated per-user test.' }
