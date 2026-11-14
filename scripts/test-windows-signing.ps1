param(
    [Parameter(Mandatory)][string]$ExeFixture,
    [Parameter(Mandatory)][string]$MsiFixture
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-signing.ps1')

function Expect-NetFlowFailure([scriptblock]$Action, [string]$Message) {
    $failed = $false
    try { & $Action 2>&1 | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw $Message }
}

if (Assert-NetFlowSigningOptions '' '' $false) { throw 'Unsigned preview unexpectedly enabled signing' }
Expect-NetFlowFailure { Assert-NetFlowSigningOptions '' '' $true } 'Required signing accepted without a certificate'
Expect-NetFlowFailure { Assert-NetFlowSigningOptions 'bad' 'https://timestamp.example.test' $true } 'Malformed thumbprint accepted'
$sample = '0123456789ABCDEF0123456789ABCDEF01234567'
foreach ($url in @('', 'http://timestamp.example.test', 'https://user:secret@example.test', 'https://example.test/?token=secret', 'https://example.test/#fragment')) {
    Expect-NetFlowFailure { Assert-NetFlowSigningOptions $sample $url $true } 'Unsafe timestamp URL accepted'
}
if (-not (Assert-NetFlowSigningOptions $sample 'https://timestamp.example.test/rfc3161' $true)) { throw 'Valid signing options rejected' }
Expect-NetFlowFailure { New-NetFlowSigningConfig $sample 'https://timestamp.example.test' 'CurrentUser' } 'Missing certificate accepted'
$known = (Get-Command pwsh).Source
$knownSignature = Get-AuthenticodeSignature -LiteralPath $known
if ($knownSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or $null -eq $knownSignature.TimeStamperCertificate) { throw 'Known signed fixture is not trusted and timestamped' }
$knownConfig = [pscustomobject]@{ Thumbprint = $knownSignature.SignerCertificate.Thumbprint; Tool = (Get-NetFlowSignTool) }
Assert-NetFlowSignedFile $knownConfig $known
$wrongConfig = [pscustomobject]@{ Thumbprint = $sample; Tool = $knownConfig.Tool }
Expect-NetFlowFailure { Assert-NetFlowSignedFile $wrongConfig $known } 'Unexpected signer was accepted'

$build = (Resolve-Path (Join-Path $PSScriptRoot '../build')).Path
$temp = Join-Path $build ('signing-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$rsa = $null
$cert = $null
try {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=NetFlow synthetic signing test', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $eku = [System.Security.Cryptography.OidCollection]::new()
    $null = $eku.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $false))
    $cert = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(1))
    $pfx = Join-Path $temp 'synthetic.pfx'
    # This password protects a throwaway synthetic key only; no user key is used.
    $password = 'netflow-synthetic-test-only'
    [IO.File]::WriteAllBytes($pfx, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password))
    $tool = Get-NetFlowSignTool
    foreach ($fixture in @($ExeFixture, $MsiFixture)) {
        $source = (Resolve-Path -LiteralPath $fixture).Path
        $copy = Join-Path $temp ([IO.Path]::GetFileName($source))
        Copy-Item -LiteralPath $source -Destination $copy
        $before = (Get-FileHash -Algorithm SHA256 -LiteralPath $copy).Hash
        $missingConfig = [pscustomobject]@{ Thumbprint = $sample; TimestampUrl = 'https://127.0.0.1:1/rfc3161'; Store = 'CurrentUser'; Tool = $tool }
        Expect-NetFlowFailure { Invoke-NetFlowSignFile $missingConfig $copy } 'Failed signing was accepted'
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $copy).Hash -ne $before) { throw 'Failed signing changed the artifact' }
        & $tool sign /fd SHA256 /f $pfx /p $password $copy
        if ($LASTEXITCODE -ne 0) { throw 'Could not sign synthetic artifact' }
        $signature = Get-AuthenticodeSignature -LiteralPath $copy
        if ($null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint) { throw 'Synthetic signature was not recorded' }
        if ($signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid) { throw 'Synthetic certificate unexpectedly trusted' }
        $config = [pscustomobject]@{ Thumbprint = $cert.Thumbprint; Tool = $tool }
        Expect-NetFlowFailure { Assert-NetFlowSignedFile $config $copy } 'Untimestamped, untrusted artifact accepted'
    }
    Write-Output 'Signing options and real untrusted EXE/MSI signature rejection passed'
} finally {
    if ($null -ne $cert) { $cert.Dispose() }
    if ($null -ne $rsa) { $rsa.Dispose() }
    if (Test-Path -LiteralPath $temp) {
        $resolved = (Resolve-Path -LiteralPath $temp).Path
        $prefix = $build.TrimEnd('\') + '\signing-test-'
        if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing to remove an unexpected signing test path' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
