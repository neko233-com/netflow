param(
    [int]$TimeoutMinutes = 45,
    [switch]$TestPolicyOnly,
    [switch]$VerifyBootRetry,
    [switch]$Quick,
    [ValidateSet('auto', '3G', '4G')][string]$GuestMemory = 'auto',
    [string]$SigningThumbprint = '',
    [string]$TimestampUrl = '',
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$SigningStore = 'CurrentUser',
    [switch]$RequireSigned
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-signing.ps1')
$requiredSigning = $null
if (Assert-NetFlowSigningOptions $SigningThumbprint $TimestampUrl ([bool]$RequireSigned)) {
    $requiredSigning = [pscustomobject]@{ Thumbprint = $SigningThumbprint.ToUpperInvariant(); Tool = (Get-NetFlowSignTool) }
}
function Test-NetFlowBootRetry([int]$Attempt, [bool]$HasResult, [string]$Log) {
    return $Attempt -lt 2 -and -not $HasResult -and $Log.Contains('Timeout while waiting for QEMU to boot the machine, terminating...')
}
function Select-NetFlowMemory([string]$Requested, [string]$DiskState) {
    if ($Requested -eq '3G' -or $Requested -eq '4G') { return $Requested }
    if ($Requested -ne 'auto') { throw 'Invalid guest memory selection' }
    if ($DiskState -eq 'reused') { return '3G' }
    if ($DiskState -eq 'fresh') { return '4G' }
    throw 'Invalid guest disk state'
}
function Protect-NetFlowDiagnostic([string]$Log, [string[]]$Secrets = @()) {
    $safe = [regex]::Replace($Log, '(?i)https?://[^\s"\\<>]+', '[URL redacted]')
    foreach ($secret in $Secrets) {
        if ($secret) { $safe = $safe.Replace($secret, '[secret redacted]') }
    }
    return $safe
}
function Invoke-NetFlowBoundedProcess([string]$Executable, [string[]]$Arguments, [int]$TimeoutSeconds = 20) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.Encoding]::UTF8
    $start.StandardErrorEncoding = [Text.Encoding]::UTF8
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'Could not start validation subprocess' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill($true) } catch { }
            [void]$process.WaitForExit(2000)
            throw 'Validation subprocess timed out'
        }
        if (-not $stdout.Wait(2000) -or -not $stderr.Wait(2000)) { throw 'Validation subprocess output timed out' }
        if ($stdout.Result.Length -gt 2097152 -or $stderr.Result.Length -gt 2097152) { throw 'Validation subprocess output exceeded limit' }
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $stdout.Result; Error = $stderr.Result }
    } finally { $process.Dispose() }
}
function Save-NetFlowValidationResult([string]$Json, [string]$RunID, [string]$Path) {
    if ($RunID -cnotmatch '^[0-9a-f]{32}$' -or $Json.Length -gt 2097152) { throw 'Invalid validation result identity or size' }
    $record = ConvertFrom-Json -InputObject $Json -AsHashtable
    if ($record -isnot [System.Collections.IDictionary] -or $record.id -cne $RunID -or $record.ok -isnot [bool] -or $record.output -isnot [string] -or ($record.ContainsKey('error') -and $record.error -isnot [string])) { throw 'Invalid validation result' }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
        try { $writer.Write($Json) } finally { $writer.Dispose() }
    } finally { $stream.Dispose() }
    return $record
}
function Test-NetFlowMissingCopy([string]$ErrorText, [string]$RunID) {
    if ($RunID -cnotmatch '^[0-9a-f]{32}$') { return $false }
    $source = [regex]::Escape("/storage/netflow-results/$RunID.json")
    return $ErrorText -match "(?i)could not find the file $source in container\b"
}
function Assert-NetFlowValidationScope([System.Collections.IDictionary]$Record, [string]$Mode) {
    $test = if ($Mode -ceq 'full') { 'TestWindowsVMEndToEnd' } elseif ($Mode -ceq 'quick') { 'TestWindowsVMQuick' } else { throw 'Invalid validation mode' }
    if (-not $Record.output.Contains("--- PASS: $test ")) { throw 'Guest result did not execute the requested validation scope' }
}
function Assert-NetFlowReleaseCurrent {
    & python scripts/build_inputs.py verify
    if ($LASTEXITCODE -ne 0) { throw 'Cannot validate stale, modified or unrecorded release artifacts.' }
    if ($null -ne $requiredSigning) {
        $source = Join-Path $repo "build/release-artifacts-$version/windows-amd64"
        foreach ($name in @('NetFlow.exe', 'netflow-agent.exe', 'netflow-kernel-worker.exe')) {
            Assert-NetFlowSignedFile $requiredSigning (Join-Path $source $name)
        }
        Assert-NetFlowSignedFile $requiredSigning $msi
    }
}
function Assert-NetFlowPayloadCurrent {
    $copied = Join-Path $payload 'NetFlow.msi'
    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $msi).Hash
    $copyHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $copied).Hash
    if ($sourceHash -ne $copyHash) { throw 'Guest MSI payload differs from the verified release' }
    $expected = Get-Content -Raw -LiteralPath (Join-Path $payload 'expected.json') | ConvertFrom-Json -AsHashtable
    if ($expected -isnot [System.Collections.IDictionary] -or $expected.Count -ne 3) { throw 'Guest binary hash policy is invalid' }
    foreach ($name in @('NetFlow.exe', 'netflow-agent.exe', 'netflow-kernel-worker.exe')) {
        if ($expected[$name] -cne $hashes[$name]) { throw 'Guest binary hash policy changed during validation' }
    }
    $actualSigner = [IO.File]::ReadAllText((Join-Path $payload 'signer.txt'), [Text.Encoding]::ASCII)
    if ($actualSigner -cne $signer) { throw 'Guest signing policy changed during validation' }
    $actualMode = [IO.File]::ReadAllText((Join-Path $payload 'test-mode.txt'), [Text.Encoding]::ASCII)
    if ($actualMode -cne $validationMode) { throw 'Guest validation mode changed during validation' }
    if ($null -ne $requiredSigning) { Assert-NetFlowSignedFile $requiredSigning $copied }
}
function Ensure-NetFlowKVM {
    # The Docker Desktop VM may unload KVM while the local build or image
    # preparation is running. Loading the appropriate module is idempotent.
    wsl.exe -d docker-desktop -u root -- sh -c 'test -c /dev/kvm || { if grep -q AuthenticAMD /proc/cpuinfo; then modprobe kvm-amd; else modprobe kvm-intel; fi; }; test -c /dev/kvm'
    if ($LASTEXITCODE -ne 0) { throw 'Nested KVM is unavailable; a real Windows guest is required' }
}
if ($TestPolicyOnly) {
    $message = 'Timeout while waiting for QEMU to boot the machine, terminating...'
    if (-not (Test-NetFlowBootRetry 1 $false $message)) { throw 'Expected one boot retry' }
    if ((Test-NetFlowBootRetry 2 $false $message) -or (Test-NetFlowBootRetry 1 $true $message) -or (Test-NetFlowBootRetry 1 $false 'unrelated failure')) { throw 'Unsafe boot retry decision' }
    if ((Select-NetFlowMemory 'auto' 'fresh') -ne '4G' -or (Select-NetFlowMemory 'auto' 'reused') -ne '3G' -or (Select-NetFlowMemory '4G' '') -ne '4G' -or (Select-NetFlowMemory '3G' '') -ne '3G') { throw 'Incorrect guest memory selection' }
    $invalidStateRejected = $false
    try { Select-NetFlowMemory 'auto' 'invalid' | Out-Null } catch { $invalidStateRejected = $_.Exception.Message -eq 'Invalid guest disk state' }
    if (-not $invalidStateRejected) { throw 'Invalid disk state accepted' }
    $redacted = Protect-NetFlowDiagnostic 'failure https://example.invalid/path?token=synthetic-secret guest-password retained' @('guest-password')
    if ($redacted.Contains('synthetic-secret') -or $redacted.Contains('guest-password') -or -not $redacted.Contains('retained')) { throw 'Diagnostic redaction failed' }
    $testBuild = (Resolve-Path ([IO.Path]::GetTempPath())).Path
    $testDir = Join-Path $testBuild ('payload-policy-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $testDir | Out-Null
    try {
        $payload = $testDir
        $msi = Join-Path $testDir 'source.bin'
        $signer = ''
        $validationMode = 'full'
        $hashes = [ordered]@{ 'NetFlow.exe' = 'a'; 'netflow-agent.exe' = 'b'; 'netflow-kernel-worker.exe' = 'c' }
        [IO.File]::WriteAllText($msi, 'synthetic')
        [IO.File]::WriteAllText((Join-Path $payload 'NetFlow.msi'), 'synthetic')
        [IO.File]::WriteAllText((Join-Path $payload 'signer.txt'), '')
        [IO.File]::WriteAllText((Join-Path $payload 'test-mode.txt'), $validationMode)
        [IO.File]::WriteAllText((Join-Path $payload 'expected.json'), ($hashes | ConvertTo-Json -Compress))
        Assert-NetFlowPayloadCurrent
        [IO.File]::WriteAllText((Join-Path $payload 'NetFlow.msi'), 'modified')
        $rejected = $false
        try { Assert-NetFlowPayloadCurrent } catch { $rejected = $true }
        if (-not $rejected) { throw 'Altered MSI payload was accepted' }
        [IO.File]::WriteAllText((Join-Path $payload 'NetFlow.msi'), 'synthetic')
        [IO.File]::WriteAllText((Join-Path $payload 'signer.txt'), 'changed')
        $rejected = $false
        try { Assert-NetFlowPayloadCurrent } catch { $rejected = $true }
        if (-not $rejected) { throw 'Changed signing policy was accepted' }
        [IO.File]::WriteAllText((Join-Path $payload 'signer.txt'), '')
        [IO.File]::WriteAllText((Join-Path $payload 'test-mode.txt'), 'quick')
        $rejected = $false
        try { Assert-NetFlowPayloadCurrent } catch { $rejected = $true }
        if (-not $rejected) { throw 'Changed validation mode was accepted' }
        [IO.File]::WriteAllText((Join-Path $payload 'test-mode.txt'), $validationMode)
        [IO.File]::WriteAllText((Join-Path $payload 'expected.json'), '{}')
        $rejected = $false
        try { Assert-NetFlowPayloadCurrent } catch { $rejected = $true }
        if (-not $rejected) { throw 'Changed binary hash policy was accepted' }
        $testID = '0123456789abcdef0123456789abcdef'
        $resultPath = Join-Path $testDir 'result.json'
        $valid = @{ id = $testID; ok = $true; output = 'passed' } | ConvertTo-Json -Compress
        $saved = Save-NetFlowValidationResult $valid $testID $resultPath
        if (-not $saved.ok -or $saved.output -ne 'passed' -or [IO.File]::ReadAllText($resultPath) -cne $valid) { throw 'Validation result was not preserved' }
        $rejected = $false
        try { Save-NetFlowValidationResult $valid $testID $resultPath | Out-Null } catch { $rejected = $true }
        if (-not $rejected) { throw 'Existing validation result was overwritten' }
        foreach ($invalid in @(
            (@{ id = 'ffffffffffffffffffffffffffffffff'; ok = $true; output = '' } | ConvertTo-Json -Compress),
            (@{ id = $testID; ok = 'true'; output = '' } | ConvertTo-Json -Compress),
            (@{ id = $testID; ok = $true; output = 1 } | ConvertTo-Json -Compress),
            ('x' * 2097153)
        )) {
            $rejected = $false
            try { Save-NetFlowValidationResult $invalid $testID (Join-Path $testDir 'invalid.json') | Out-Null } catch { $rejected = $true }
            if (-not $rejected) { throw 'Unsafe validation result accepted' }
        }
        if (-not (Test-NetFlowMissingCopy "Error response from daemon: Could not find the file /storage/netflow-results/$testID.json in container test" $testID) -or
            (Test-NetFlowMissingCopy 'no such file or directory' $testID) -or
            (Test-NetFlowMissingCopy 'Error response from daemon: No such container' $testID) -or
            (Test-NetFlowMissingCopy 'Could not find the file /different in container test' $testID) -or
            (Test-NetFlowMissingCopy "Could not find the file /storage/netflow-results/$testID.json in container test" 'invalid')) { throw 'Unsafe missing-result classification' }
        Assert-NetFlowValidationScope @{ output = "--- PASS: TestWindowsVMEndToEnd (1.0s)" } 'full'
        Assert-NetFlowValidationScope @{ output = "--- PASS: TestWindowsVMQuick (1.0s)" } 'quick'
        $rejected = $false
        try { Assert-NetFlowValidationScope @{ output = "--- PASS: TestWindowsVMQuick (1.0s)" } 'full' } catch { $rejected = $true }
        if (-not $rejected) { throw 'Quick result was accepted as a full validation' }
        $pwshPath = (Get-Command pwsh -CommandType Application | Select-Object -First 1).Source
        $command = Invoke-NetFlowBoundedProcess $pwshPath @('-NoProfile', '-Command', "[Console]::Out.Write('ok')") 10
        if ($command.ExitCode -ne 0 -or $command.Output -cne 'ok') { throw 'Validation subprocess output failed' }
        $timedOut = $false
        try { Invoke-NetFlowBoundedProcess $pwshPath @('-NoProfile', '-Command', 'Start-Sleep -Seconds 8') 1 | Out-Null } catch { $timedOut = $_.Exception.Message -eq 'Validation subprocess timed out' }
        if (-not $timedOut) { throw 'Validation subprocess timeout failed' }
    } finally {
        $resolved = (Resolve-Path -LiteralPath $testDir).Path
        $prefix = $testBuild.TrimEnd('\') + '\payload-policy-'
        if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing to remove unexpected test path' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
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
    Ensure-NetFlowKVM
    $env:GOOS='windows'; $env:GOARCH='amd64'
    # Fail before packaging if the dedicated, integration-tagged test cannot build.
    go test -p 1 '-tags=integration,with_gvisor,no_tailscale' '-ldflags=-s -w -H=windowsgui' -c -o (Join-Path $payload 'netflow-app.test.exe') ./internal/app
    if ($LASTEXITCODE -ne 0) { throw 'Could not build Windows integration test' }
    Remove-Item Env:GOOS,Env:GOARCH
    $version = (Get-Content -Raw mygo.json | ConvertFrom-Json).version
    $msi = Join-Path $repo "build/releases/$version/NetFlow-$version-windows-amd64.msi"
    if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) {
        Write-Output 'Release MSI is absent; building it locally before validation.'
        $signArgs = @()
        if ($null -ne $requiredSigning) { $signArgs = @('-SigningThumbprint', $SigningThumbprint, '-TimestampUrl', $TimestampUrl, '-SigningStore', $SigningStore, '-RequireSigned') }
        & pwsh -NoProfile -File (Join-Path $repo 'scripts/build-release.ps1') @signArgs
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
    # Older runs included a separate unsigned bootstrapper. The verifier now
    # runs from the same optical-media test executable as the integration test.
    $obsoleteAgent = Join-Path $payload 'netflow-vm-agent.exe'
    if (Test-Path -LiteralPath $obsoleteAgent -PathType Leaf) { Remove-Item -LiteralPath $obsoleteAgent }
    $source = Join-Path $repo "build/release-artifacts-$version/windows-amd64"
    Copy-Item -LiteralPath $msi -Destination (Join-Path $payload 'NetFlow.msi') -Force
    $hashes = [ordered]@{}
    foreach ($name in @('NetFlow.exe','netflow-agent.exe','netflow-kernel-worker.exe')) {
        $hashes[$name] = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $source $name)).Hash.ToLowerInvariant()
    }
    [IO.File]::WriteAllText((Join-Path $payload 'expected.json'), ($hashes | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    $signer = if ($null -ne $requiredSigning) { $requiredSigning.Thumbprint.ToLowerInvariant() } else { '' }
    [IO.File]::WriteAllText((Join-Path $payload 'signer.txt'), $signer, [Text.UTF8Encoding]::new($false))
    $validationMode = if ($Quick) { 'quick' } else { 'full' }
    [IO.File]::WriteAllText((Join-Path $payload 'test-mode.txt'), $validationMode, [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText((Join-Path $payload 'ready'), 'ready', [Text.UTF8Encoding]::new($false))
    Assert-NetFlowReleaseCurrent
    Assert-NetFlowPayloadCurrent
    docker build -t netflow-windows-vm:local $context
    if ($LASTEXITCODE -ne 0) { throw 'Docker image build failed' }
    docker run --rm --network none --cpus=1 --entrypoint python3 netflow-windows-vm:local /opt/netflow/test_monitor.py
    if ($LASTEXITCODE -ne 0) { throw 'Setup-media safety test failed' }
    $runID = [guid]::NewGuid().ToString('N')
    [IO.File]::WriteAllText((Join-Path $payload 'media-id.txt'), $runID, [Text.UTF8Encoding]::new($false))
    $guestPassword = [guid]::NewGuid().ToString('N') + 'Aa1!'
    $testEnv = @()
    if ($VerifyBootRetry) { $testEnv = @('-e', 'NETFLOW_TEST_BOOT_FAILURE=1') }
    $selectedMemory = $GuestMemory
    if ($selectedMemory -eq 'auto') {
        $diskState = (& docker run --rm --network none --cpus=1 --memory=64m --mount "type=volume,source=$volume,target=/storage,readonly" --entrypoint sh netflow-windows-vm:local -c 'if test -f /storage/windows.system || test -f /storage/windows.boot; then printf reused; else printf fresh; fi' | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $diskState -notin @('reused', 'fresh')) { throw 'Could not inspect the owned guest disk state' }
        $selectedMemory = Select-NetFlowMemory 'auto' $diskState
    }
    $containerMemory = if ($selectedMemory -eq '3G') { '4g' } else { '5g' }
    Write-Output "Windows guest memory: $selectedMemory; container limit: $containerMemory"
    Ensure-NetFlowKVM
    Assert-NetFlowPayloadCurrent
    docker run -d --name $container --label "$label=1" --cpus=1 "--memory=$containerMemory" --device=/dev/kvm --mount "type=volume,source=$volume,target=/storage" --mount "type=bind,source=$payload,target=/payload,readonly" -e "NETFLOW_RUN_ID=$runID" -e "RAM_SIZE=$selectedMemory" -e USERNAME=NetFlowTest -e "PASSWORD=$guestPassword" @testEnv netflow-windows-vm:local | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not start Windows validation guest' }
    $guestStarted = $true
    $until = (Get-Date).AddMinutes($TimeoutMinutes)
    $bootAttempt = 1
    $dockerPath = (Get-Command docker -CommandType Application | Select-Object -First 1).Source
    $pollSeconds = if ($Quick) { 2 } else { 10 }
    while ((Get-Date) -lt $until) {
        $inspection = Invoke-NetFlowBoundedProcess $dockerPath @('inspect', '--format', '{{.State.Running}}', $container)
        $state = $inspection.Output.Trim()
        if ($inspection.ExitCode -ne 0 -or $state -notin @('true', 'false')) { throw 'Cannot inspect Windows validation guest' }
        if ($state -ne 'true') {
            # A result can be written immediately before the guest exits.
            # Preserve it before deciding whether a boot retry is safe.
            $localResult = Join-Path $repo "build/windows-vm-result-$runID.json"
            $recovery = Join-Path $repo "build/windows-vm-recovery-$runID.json"
            $copy = Invoke-NetFlowBoundedProcess $dockerPath @('cp', "${container}:/storage/netflow-results/$runID.json", $recovery)
            $hasResult = $copy.ExitCode -eq 0
            if ($hasResult) {
                $record = Save-NetFlowValidationResult ([IO.File]::ReadAllText($recovery, [Text.Encoding]::UTF8)) $runID $localResult
                Remove-Item -LiteralPath $recovery -Force
                $record.output
                if (-not $record.ok) { throw "Windows validation failed: $($record.error)" }
                Assert-NetFlowValidationScope $record $validationMode
                Assert-NetFlowReleaseCurrent
                Assert-NetFlowPayloadCurrent
                Write-Output "Windows $validationMode validation passed: $runID"
                return
            }
            if (-not (Test-NetFlowMissingCopy $copy.Error $runID)) { throw 'Could not recover the stopped guest result' }
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
        $result = Invoke-NetFlowBoundedProcess $dockerPath @('exec', $container, 'sh', '-c', "test ! -f /storage/netflow-results/$runID.json || cat /storage/netflow-results/$runID.json")
        if ($result.ExitCode -ne 0) { throw 'Could not read the Windows validation result' }
        if ($result.Output) {
            $record = Save-NetFlowValidationResult $result.Output $runID (Join-Path $repo "build/windows-vm-result-$runID.json")
            $record.output
            if (-not $record.ok) { throw "Windows validation failed: $($record.error)" }
            Assert-NetFlowValidationScope $record $validationMode
            Assert-NetFlowReleaseCurrent
            Assert-NetFlowPayloadCurrent
            # Once a bootable disk has passed validation, the verified ISO is
            # no longer needed. Keep the virtual disk and all result records.
            $cleanup = Invoke-NetFlowBoundedProcess $dockerPath @('exec', $container, 'sh', '-c', 'if test -f /storage/windows.system || test -f /storage/windows.boot; then rm -f -- /storage/netflow-media/win10x64-enterprise-ltsc-eval.iso /storage/netflow-media/win10x64-enterprise-ltsc-eval.iso.aria2; fi')
            if ($cleanup.ExitCode -ne 0) { Write-Warning 'Could not remove cached installation media' }
            Write-Output "Windows $validationMode validation passed: $runID"
            return
        }
        Start-Sleep -Seconds $pollSeconds
    }
    $logs = Protect-NetFlowDiagnostic (docker logs --tail 100 $container 2>&1 | Out-String) @($guestPassword)
    $logPath = Join-Path $repo "build/windows-vm-timeout-$runID.log"
    [IO.File]::WriteAllText($logPath, $logs, [Text.UTF8Encoding]::new($false))
    Write-Output $logs
    throw "Windows validation exceeded $TimeoutMinutes minutes"
} finally {
    if ($guestStarted) {
        try {
            $owned = Invoke-NetFlowBoundedProcess $dockerPath @('inspect', '--format', '{{ index .Config.Labels "netflow.windows-vm" }}', $container) 10
            if ($owned.ExitCode -eq 0 -and $owned.Output.Trim() -eq '1') {
                $stopped = Invoke-NetFlowBoundedProcess $dockerPath @('stop', '--timeout', '30', $container) 40
                if ($stopped.ExitCode -ne 0) { Write-Warning 'Could not stop the owned validation guest' }
            }
        } catch { Write-Warning "Could not stop the owned validation guest: $_" }
    }
    if ($null -ne $runLock) { $runLock.Dispose() }
    Set-Location -LiteralPath $previous
}
