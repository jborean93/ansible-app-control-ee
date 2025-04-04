using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $CertPrefix,

    [Parameter(Mandatory)]
    [SecureString]
    $CertPassword
)

$ErrorActionPreference = 'Stop'

$Ansible.Changed = $false

$caSubject = "CN=$CertPrefix"
$ca = Get-ChildItem -LiteralPath Cert:\CurrentUser\My | Where-Object Subject -eq $caSubject
if (-not $ca) {
    $enhancedKeyUsage = [OidCollection]::new()
    $null = $enhancedKeyUsage.Add('1.3.6.1.5.5.7.3.3')  # Code Signing
    $caParams = @{
        Extension = @(
            [X509BasicConstraintsExtension]::new($true, $false, 0, $true),
            [X509KeyUsageExtension]::new('KeyCertSign', $false),
            [X509EnhancedKeyUsageExtension ]::new($enhancedKeyUsage, $false)
        )
        CertStoreLocation = 'Cert:\CurrentUser\My'
        NotAfter = (Get-Date).AddDays(30)
        Subject = $caSubject
        Type = 'Custom'
    }
    $ca = New-SelfSignedCertificate @caParams

    $caWithoutKey = [X509Certificate2]::new($ca.Export('Cert'))
    $root = Get-Item Cert:\LocalMachine\Root
    $root.Open('ReadWrite')
    $root.Add($caWithoutKey)
    $root.Dispose()

    $Ansible.Changed = $true
}

$signerSubject = "CN=$CertPrefix-Signer"
$signer = Get-ChildItem -LiteralPath Cert:\CurrentUser\My | Where-Object Subject -eq $signerSubject
if (-not $signer) {
    $certParams = @{
        CertStoreLocation = 'Cert:\CurrentUser\My'
        KeyUsage = 'DigitalSignature'
        Signer = $ca
        Subject = $signerSubject
        TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
        Type = 'Custom'
    }
    $signer = New-SelfSignedCertificate @certParams

    $signerWithoutKey = [X509Certificate2]::new($signer.Export('Cert'))
    $trustedPublisher = Get-Item Cert:\LocalMachine\TrustedPublisher
    $trustedPublisher.Open('ReadWrite')
    $trustedPublisher.Add($signerWithoutKey)
    $trustedPublisher.Dispose()

    $null = $signer | Export-PfxCertificate -Password $CertPassword -FilePath "C:\Windows\TEMP\$CertPrefix.pfx"
    $signer.Export('Cert') | Set-Content -LiteralPath "C:\Windows\TEMP\$CertPrefix.cer" -Encoding Byte

    $Ansible.Changed = $true
}

@{
    ca_thumbprint = $ca.Thumbprint
    signer_thumbprint = $signer.Thumbprint
}
