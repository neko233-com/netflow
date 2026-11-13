param([int]$TimeoutMinutes = 45)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$previous = Get-Location
try {
    Set-Location -LiteralPath $repo
    (Get-Process -Id $PID).PriorityClass = 'BelowNormal'
    $env:GOMAXPROCS = '1'; $env:CGO_ENABLED = '0'
    $volume = 'netflow-windows-vm-v1'; $container = 'netflow-windows-vm-validation'
    $label = 'netflow.windows-vm'
    $context = Join-Path $repo 'build/windows-vm-context'
    $payload = Join-Path $repo 'build/windows-vm-payload'
    New-Item -ItemType Directory -Force -Path $context, $payload | Out-Null
    if ((docker version --format '{{.Server.Os}}') -ne 'linux') { throw 'A Linux Docker engine with nested KVM is required' }
    # Docker Desktop's Linux VM may not load the nested KVM driver until needed.
    wsl.exe -d docker-desktop -u root -- sh -c 'test -c /dev/kvm || { if grep -q AuthenticAMD /proc/cpuinfo; then modprobe kvm-amd; else modprobe kvm-intel; fi; }; test -c /dev/kvm'
    if ($LASTEXITCODE -ne 0) { throw 'Nested KVM is unavailable; a real Windows guest is required' }
    $existing = docker ps -a --filter "name=^/$container`$" --format '{{.ID}}'
    if ($existing) {
        $owned = docker inspect --format '{{ index .Config.Labels "netflow.windows-vm" }}' $existing
        if ($owned -ne '1') { throw 'Refusing to replace a container without the NetFlow validation label' }
        docker stop --time 120 $existing | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not stop the existing validation guest' }
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
    foreach ($name in @('Dockerfile', 'entry.sh', 'download-media.sh', 'bridge.py', 'install.bat')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot "windows-vm/$name") -Destination (Join-Path $context $name) -Force
    }
    $env:GOOS='windows'; $env:GOARCH='amd64'
    go build -p 1 '-ldflags=-H=windowsgui' -o (Join-Path $context 'netflow-vm-agent.exe') ./cmd/netflow-vm-agent
    if ($LASTEXITCODE -ne 0) { throw 'Could not build guest agent' }
    Copy-Item -LiteralPath (Join-Path $context 'netflow-vm-agent.exe') -Destination (Join-Path $payload 'netflow-vm-agent.exe') -Force
    go test -p 1 '-tags=integration,with_gvisor,no_tailscale' -c -o (Join-Path $payload 'netflow-app.test.exe') ./internal/app
    if ($LASTEXITCODE -ne 0) { throw 'Could not build Windows integration test' }
    Remove-Item Env:GOOS,Env:GOARCH
    $version = (Get-Content -Raw mygo.json | ConvertFrom-Json).version
    $source = Join-Path $repo "build/release-artifacts-$version/windows-amd64"
    $msi = Join-Path $repo "build/releases/$version/NetFlow-$version-windows-amd64.msi"
    if (-not (Test-Path -LiteralPath $msi)) { throw 'Build the release MSI first using scripts/build-release.ps1' }
    Copy-Item -LiteralPath $msi -Destination (Join-Path $payload 'NetFlow.msi') -Force
    $hashes = [ordered]@{}
    foreach ($name in @('NetFlow.exe','netflow-agent.exe','netflow-kernel-worker.exe')) {
        $hashes[$name] = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $source $name)).Hash.ToLowerInvariant()
    }
    [IO.File]::WriteAllText((Join-Path $payload 'expected.json'), ($hashes | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $payload 'ready'), 'ready', [Text.UTF8Encoding]::new($false))
    docker build -t netflow-windows-vm:local $context
    if ($LASTEXITCODE -ne 0) { throw 'Docker image build failed' }
    $runID = [guid]::NewGuid().ToString('N')
    $guestPassword = [guid]::NewGuid().ToString('N') + 'Aa1!'
    docker run -d --name $container --label "$label=1" --cpus=1 --memory=5g --device=/dev/kvm --mount "type=volume,source=$volume,target=/storage" --mount "type=bind,source=$payload,target=/payload,readonly" -e "NETFLOW_RUN_ID=$runID" -e USERNAME=NetFlowTest -e "PASSWORD=$guestPassword" netflow-windows-vm:local | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not start Windows validation guest' }
    $until = (Get-Date).AddMinutes($TimeoutMinutes)
    while ((Get-Date) -lt $until) {
        $state = docker inspect --format '{{.State.Running}}' $container
        if ($state -ne 'true') { docker logs --tail 100 $container; throw 'Windows guest stopped before validation completed' }
        $result = docker exec $container sh -c "test ! -f /storage/netflow-results/$runID.json || cat /storage/netflow-results/$runID.json"
        if ($result) {
            $record = $result | ConvertFrom-Json
            $record.output
            if (-not $record.ok) { throw "Windows validation failed: $($record.error)" }
            Write-Output "Windows validation passed: $runID"
            return
        }
        Start-Sleep -Seconds 10
    }
    docker logs --tail 100 $container
    throw "Windows validation exceeded $TimeoutMinutes minutes"
} finally {
    Set-Location -LiteralPath $previous
}
