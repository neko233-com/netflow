param([int]$TimeoutMinutes = 45, [switch]$TestPolicyOnly, [switch]$VerifyBootRetry)
$ErrorActionPreference = 'Stop'
function Test-NetFlowBootRetry([int]$Attempt, [bool]$HasResult, [string]$Log) {
    return $Attempt -lt 2 -and -not $HasResult -and $Log.Contains('Timeout while waiting for QEMU to boot the machine, terminating...')
}
function Protect-NetFlowDiagnostic([string]$Log, [string[]]$Secrets = @()) {
    $safe = [regex]::Replace($Log, '(?i)https?://[^\s"\\<>]+', '[URL redacted]')
    foreach ($secret in $Secrets) {
        if ($secret) { $safe = $safe.Replace($secret, '[secret redacted]') }
    }
    return $safe
}
function Assert-NetFlowReleaseCurrent {
    & python scripts/build_inputs.py verify
    if ($LASTEXITCODE -ne 0) { throw 'Cannot validate stale, modified or unrecorded release artifacts.' }
}
if ($TestPolicyOnly) {
    $message = 'Timeout while waiting for QEMU to boot the machine, terminating...'
    if (-not (Test-NetFlowBootRetry 1 $false $message)) { throw 'Expected one boot retry' }
    if ((Test-NetFlowBootRetry 2 $false $message) -or (Test-NetFlowBootRetry 1 $true $message) -or (Test-NetFlowBootRetry 1 $false 'unrelated failure')) { throw 'Unsafe boot retry decision' }
    $redacted = Protect-NetFlowDiagnostic 'failure https://example.invalid/path?token=synthetic-secret guest-password retained' @('guest-password')
    if ($redacted.Contains('synthetic-secret') -or $redacted.Contains('guest-password') -or -not $redacted.Contains('retained')) { throw 'Diagnostic redaction failed' }
    Write-Output 'Boot retry policy passed'
    return
}
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$previous = Get-Location
$guestStarted = $false
$runLock = $null
try {
    Set-Location -LiteralPath $repo
    (Get-Process -Id $PID).PriorityClass = 'BelowNormal'
    $env:GOMAXPROCS = '1'; $env:CGO_ENABLED = '0'; $env:GOWORK = 'off'
    $buildRoot = Join-Path $repo 'build'
    & python scripts/build_inputs.py check-vm
    if ($LASTEXITCODE -ne 0) { throw 'Windows validation paths are unsafe.' }
    New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null
    try {
        $runLock = [IO.File]::Open((Join-Path $buildRoot 'windows-vm-validator.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch { throw 'Another Windows validation may be running; refusing to start a concurrent run.' }
    & python scripts/build_inputs.py check-vm
    if ($LASTEXITCODE -ne 0) { throw 'Windows validation paths changed or are unsafe.' }
    $volume = 'netflow-windows-vm-v1'; $container = 'netflow-windows-vm-validation'
    $label = 'netflow.windows-vm'
    $context = Join-Path $repo 'build/windows-vm-context'
    $payload = Join-Path $repo 'build/windows-vm-payload'
    New-Item -ItemType Directory -Force -Path $context, $payload | Out-Null
    if ((docker version --format '{{.Server.Os}}') -ne 'linux') { throw 'A Linux Docker engine with nested KVM is required' }
    # Docker Desktop's Linux VM may not load the nested KVM driver until needed.
    wsl.exe -d docker-desktop -u root -- sh -c 'test -c /dev/kvm || { if grep -q AuthenticAMD /proc/cpuinfo; then modprobe kvm-amd; else modprobe kvm-intel; fi; }; test -c /dev/kvm'
    if ($LASTEXITCODE -ne 0) { throw 'Nested KVM is unavailable; a real Windows guest is required' }
    $version = (Get-Content -Raw mygo.json | ConvertFrom-Json).version
    $msi = Join-Path $repo "build/releases/$version/NetFlow-$version-windows-amd64.msi"
    if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) {
        Write-Output 'Release MSI is absent; building it locally before validation.'
        & pwsh -NoProfile -File (Join-Path $repo 'scripts/build-release.ps1')
        if ($LASTEXITCODE -ne 0) { throw 'Automatic local release build failed' }
    }
    Assert-NetFlowReleaseCurrent
    $existing = docker ps -a --filter "name=^/$container`$" --format '{{.ID}}'
    if ($existing) {
        $owned = docker inspect --format '{{ index .Config.Labels "netflow.windows-vm" }}' $existing
        if ($owned -ne '1') { throw 'Refusing to replace a container without the NetFlow validation label' }
        $running = docker inspect --format '{{.State.Running}}' $existing
        if ($running -ne 'false') { throw 'An existing validation guest is running or unavailable; refusing to interrupt it.' }
        docker rm $existing | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not remove the stopped validation container' }
    }
    $volumeExists = docker volume ls --filter "name=^$volume`$" --format '{{.Name}}'
    if ($volumeExists) {
        $owned = docker volume inspect --format '{{ index .Labels "netflow.windows-vm" }}' $volume
        if ($owned -ne '1') { throw 'Refusing to use a volume without the NetFlow validation label' }
    } else {
        docker volume create --label "$label=1" $volume | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not create validation volume' }
    }
    foreach ($name in @('Dockerfile', '.dockerignore', 'entry.sh', 'download-media.sh', 'bridge.py', 'test_monitor.py', 'install.bat')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot "windows-vm/$name") -Destination (Join-Path $context $name) -Force
    }
    $env:GOOS='windows'; $env:GOARCH='amd64'
    # Older runs included a separate unsigned bootstrapper. The verifier now
    # runs from the same optical-media test executable as the integration test.
    $obsoleteAgent = Join-Path $payload 'netflow-vm-agent.exe'
    if (Test-Path -LiteralPath $obsoleteAgent -PathType Leaf) { Remove-Item -LiteralPath $obsoleteAgent }
    go test -p 1 '-tags=integration,with_gvisor,no_tailscale' '-ldflags=-s -w -H=windowsgui' -c -o (Join-Path $payload 'netflow-app.test.exe') ./internal/app
    if ($LASTEXITCODE -ne 0) { throw 'Could not build Windows integration test' }
    Remove-Item Env:GOOS,Env:GOARCH
    $source = Join-Path $repo "build/release-artifacts-$version/windows-amd64"
    Copy-Item -LiteralPath $msi -Destination (Join-Path $payload 'NetFlow.msi') -Force
    $hashes = [ordered]@{}
    foreach ($name in @('NetFlow.exe','netflow-agent.exe','netflow-kernel-worker.exe')) {
        $hashes[$name] = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $source $name)).Hash.ToLowerInvariant()
    }
    [IO.File]::WriteAllText((Join-Path $payload 'expected.json'), ($hashes | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $payload 'ready'), 'ready', [Text.UTF8Encoding]::new($false))
    Assert-NetFlowReleaseCurrent
    docker build -t netflow-windows-vm:local $context
    if ($LASTEXITCODE -ne 0) { throw 'Docker image build failed' }
    docker run --rm --network none --cpus=1 --entrypoint python3 netflow-windows-vm:local /opt/netflow/test_monitor.py
    if ($LASTEXITCODE -ne 0) { throw 'Setup-media safety test failed' }
    $runID = [guid]::NewGuid().ToString('N')
    [IO.File]::WriteAllText((Join-Path $payload 'media-id.txt'), $runID, [Text.UTF8Encoding]::new($false))
    $guestPassword = [guid]::NewGuid().ToString('N') + 'Aa1!'
    $testEnv = @()
    if ($VerifyBootRetry) { $testEnv = @('-e', 'NETFLOW_TEST_BOOT_FAILURE=1') }
    docker run -d --name $container --label "$label=1" --cpus=1 --memory=5g --device=/dev/kvm --mount "type=volume,source=$volume,target=/storage" --mount "type=bind,source=$payload,target=/payload,readonly" -e "NETFLOW_RUN_ID=$runID" -e USERNAME=NetFlowTest -e "PASSWORD=$guestPassword" @testEnv netflow-windows-vm:local | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not start Windows validation guest' }
    $guestStarted = $true
    $until = (Get-Date).AddMinutes($TimeoutMinutes)
    $bootAttempt = 1
    while ((Get-Date) -lt $until) {
        $state = docker inspect --format '{{.State.Running}}' $container
        if ($state -ne 'true') {
            # A result can be written immediately before the guest exits.
            # Preserve it before deciding whether a boot retry is safe.
            $localResult = Join-Path $repo "build/windows-vm-result-$runID.json"
            docker cp "${container}:/storage/netflow-results/$runID.json" $localResult 2>$null
            $hasResult = $LASTEXITCODE -eq 0
            if ($hasResult) {
                $record = Get-Content -Raw -LiteralPath $localResult | ConvertFrom-Json
                $record.output
                if (-not $record.ok) { throw "Windows validation failed: $($record.error)" }
                Assert-NetFlowReleaseCurrent
                Write-Output "Windows validation passed: $runID"
                return
            }
            $logs = Protect-NetFlowDiagnostic (docker logs --tail 100 $container 2>&1 | Out-String) @($guestPassword)
            $logPath = Join-Path $repo "build/windows-vm-boot-$runID-attempt-$bootAttempt.log"
            [IO.File]::WriteAllText($logPath, $logs, [Text.UTF8Encoding]::new($false))
            Write-Output $logs
            if (Test-NetFlowBootRetry $bootAttempt $hasResult $logs) {
                $owned = docker inspect --format '{{ index .Config.Labels "netflow.windows-vm" }}' $container
                if ($owned -ne '1') { throw 'Refusing to restart an unowned validation container' }
                $bootAttempt++
                Write-Warning 'Boot watchdog expired before a result; retrying the owned guest once.'
                docker start $container | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'Could not restart the validation guest' }
                continue
            }
            throw 'Windows guest stopped before validation completed'
        }
        $result = docker exec $container sh -c "test ! -f /storage/netflow-results/$runID.json || cat /storage/netflow-results/$runID.json"
        if ($result) {
            $record = $result | ConvertFrom-Json
            docker cp "${container}:/storage/netflow-results/$runID.json" (Join-Path $repo "build/windows-vm-result-$runID.json")
            if ($LASTEXITCODE -ne 0) { throw 'Could not preserve the validation result' }
            $record.output
            if (-not $record.ok) { throw "Windows validation failed: $($record.error)" }
            Assert-NetFlowReleaseCurrent
            # Once a bootable disk has passed validation, the verified ISO is
            # no longer needed. Keep the virtual disk and all result records.
            docker exec $container sh -c 'if test -f /storage/windows.system || test -f /storage/windows.boot; then rm -f -- /storage/netflow-media/win10x64-enterprise-ltsc-eval.iso /storage/netflow-media/win10x64-enterprise-ltsc-eval.iso.aria2; fi'
            Write-Output "Windows validation passed: $runID"
            return
        }
        Start-Sleep -Seconds 10
    }
    $logs = Protect-NetFlowDiagnostic (docker logs --tail 100 $container 2>&1 | Out-String) @($guestPassword)
    $logPath = Join-Path $repo "build/windows-vm-timeout-$runID.log"
    [IO.File]::WriteAllText($logPath, $logs, [Text.UTF8Encoding]::new($false))
    Write-Output $logs
    throw "Windows validation exceeded $TimeoutMinutes minutes"
} finally {
    if ($guestStarted) {
        try {
            $owned = docker inspect --format '{{ index .Config.Labels "netflow.windows-vm" }}' $container 2>$null
            if ($LASTEXITCODE -eq 0 -and $owned -eq '1') {
                docker stop --timeout 30 $container | Out-Null
                if ($LASTEXITCODE -ne 0) { Write-Warning 'Could not stop the owned validation guest' }
            }
        } catch { Write-Warning "Could not stop the owned validation guest: $_" }
    }
    if ($null -ne $runLock) { $runLock.Dispose() }
    Set-Location -LiteralPath $previous
}
