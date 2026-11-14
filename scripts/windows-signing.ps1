# Authenticode signing is explicit: this script never selects a certificate
# automatically and never accepts a private-key password on the command line.
function Get-NetFlowSignTool {
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
    if (-not (Test-Path -LiteralPath $kits -PathType Container)) { throw 'Windows SDK SignTool is required for signing' }
    $versions = Get-ChildItem -LiteralPath $kits -Directory | Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } | Sort-Object { [version]$_.Name } -Descending
    foreach ($version in $versions) {
        $tool = Join-Path $version.FullName 'x64/signtool.exe'
        if (Test-Path -LiteralPath $tool -PathType Leaf) { return $tool }
    }
    throw 'Windows SDK x64 SignTool is required for signing'
}

function Assert-NetFlowSigningOptions([string]$Thumbprint, [string]$TimestampUrl, [bool]$RequireSigned) {
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        if ($RequireSigned -or -not [string]::IsNullOrWhiteSpace($TimestampUrl)) { throw 'Signing requires an explicit certificate thumbprint and timestamp URL' }
        return $false
    }
    if ($Thumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'Signing certificate thumbprint must be 40 hexadecimal characters' }
    $uri = $null
    if (-not [uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https' -or -not $uri.Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
        throw 'Timestamp URL must be HTTPS without credentials, query or fragment'
    }
    return $true
}

function New-NetFlowSigningConfig([string]$Thumbprint, [string]$TimestampUrl, [string]$Store) {
    if ($Store -notin @('CurrentUser', 'LocalMachine')) { throw 'Invalid signing certificate store' }
    $null = Assert-NetFlowSigningOptions $Thumbprint $TimestampUrl $true
    $cert = Get-Item -LiteralPath "Cert:\$Store\My\$Thumbprint" -ErrorAction Stop
    $now = Get-Date
    if (-not $cert.HasPrivateKey -or $cert.NotBefore -gt $now -or $cert.NotAfter -le $now) { throw 'Signing certificate is expired, not yet valid, or lacks a private key' }
    $codeSigning = @($cert.EnhancedKeyUsageList | Where-Object { $_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.3' })
    if ($codeSigning.Count -eq 0) { throw 'Signing certificate does not allow code signing' }
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(10)
        $null = $chain.ChainPolicy.ApplicationPolicy.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
        if (-not $chain.Build($cert)) { throw 'Signing certificate chain is not trusted or revocation status could not be checked' }
    } finally { $chain.Dispose() }
    return [pscustomobject]@{ Thumbprint = $Thumbprint.ToUpperInvariant(); TimestampUrl = $TimestampUrl; Store = $Store; Tool = (Get-NetFlowSignTool) }
}

function Assert-NetFlowSignedFile($Config, [string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $Config.Thumbprint) { throw 'Artifact signer does not match the requested certificate' }
    if ($null -eq $signature.TimeStamperCertificate) { throw 'Artifact has no verified timestamp certificate' }
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) { throw "Artifact signature is not trusted: $($signature.Status)" }
    & $Config.Tool verify /pa /all /q $Path
    if ($LASTEXITCODE -ne 0) { throw 'Windows signature verification failed' }
}

function Invoke-NetFlowSignFile($Config, [string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Artifact to sign is missing' }
    # /sha1 selects a certificate by its Windows thumbprint; /fd and /td
    # select SHA-256 for the file signature and RFC 3161 timestamp.
    $arguments = @('sign', '/fd', 'SHA256', '/s', 'My', '/sha1', $Config.Thumbprint)
    if ($Config.Store -eq 'LocalMachine') { $arguments += '/sm' }
    $arguments += @('/tr', $Config.TimestampUrl, '/td', 'SHA256', $Path)
    & $Config.Tool @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Artifact signing or timestamping failed' }
    Assert-NetFlowSignedFile $Config $Path
}
