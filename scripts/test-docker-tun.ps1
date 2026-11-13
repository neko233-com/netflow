$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$previousLocation = Get-Location
$previous = @{}
$peerId = $null
foreach ($name in @('GOOS','GOARCH','CGO_ENABLED','GOMAXPROCS')) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    Set-Location -LiteralPath $repo
    (Get-Process -Id $PID).PriorityClass = 'BelowNormal'
    if ((docker version --format '{{.Server.Os}}') -ne 'linux') { throw 'A Linux Docker engine is required.' }
    $env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'; $env:GOMAXPROCS = '1'
    New-Item -ItemType Directory -Force -Path build | Out-Null
    & go test -p 1 -tags=integration,with_gvisor,no_tailscale -c -o build/netflow-core-linux-test ./internal/core
    if ($LASTEXITCODE -ne 0) { throw 'Linux integration test build failed.' }
    & go test -p 1 -tags=integration,with_gvisor,no_tailscale -c -o build/netflow-coreipc-linux-test ./internal/coreipc
    if ($LASTEXITCODE -ne 0) { throw 'Linux worker integration test build failed.' }
    $testBin = (Resolve-Path -LiteralPath 'build/netflow-core-linux-test').Path
    $workerTestBin = (Resolve-Path -LiteralPath 'build/netflow-coreipc-linux-test').Path
    $peerId = docker run -d --cpus=1 --network bridge --label 'netflow.test=tun-peer' alpine:3.23 sh -c 'while true; do printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p 8080; done'
    if ($LASTEXITCODE -ne 0 -or $peerId -notmatch '^[a-f0-9]{64}$') { throw 'Failed to start isolated test peer.' }
    $peerIP = docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $peerId
    if ($peerIP -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw 'Invalid test peer address.' }
    & docker run --rm --cpus=1 --network bridge --cap-add=NET_ADMIN --device=/dev/net/tun `
        --mount "type=bind,source=$testBin,target=/netflow-core-test,readonly" `
        --mount "type=bind,source=$workerTestBin,target=/netflow-coreipc-test,readonly" `
        -e NETFLOW_DOCKER_TUN=1 -e "NETFLOW_TUN_TEST_PEER=$peerIP" -e GOMAXPROCS=1 -e DEBIAN_FRONTEND=noninteractive `
        debian:bookworm-slim sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends iproute2 >/dev/null && /netflow-core-test -test.v -test.run "^TestDockerTUNLifecycle$" -test.timeout 60s && exec /netflow-coreipc-test -test.v -test.run "^TestDockerWorkerCleansTUNAfterDisconnect$" -test.timeout 60s'
    if ($LASTEXITCODE -ne 0) { throw 'Isolated Docker TUN test failed.' }
} finally {
    if ($peerId -match '^[a-f0-9]{64}$') {
        $label = docker inspect --format '{{index .Config.Labels "netflow.test"}}' $peerId 2>$null
        if ($label -eq 'tun-peer') { docker rm -f $peerId | Out-Null }
    }
    foreach ($name in $previous.Keys) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
    Set-Location -LiteralPath $previousLocation
}
