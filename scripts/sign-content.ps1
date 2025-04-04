#!/opt/microsoft/powershell/7/pwsh

using namespace System.Security.Cryptography.X509Certificates

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$CertPassPath
)

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/New-AnsiblePowerShellSignature.ps1"

$certPass = (Get-Content -LiteralPath $CertPassPath -Raw)
$signParams = @{
    Certificate = [X509Certificate2]::new("$PSScriptRoot/cert.pfx", $certPass)
    Collection = 'ansible.builtin', 'ansible.windows', 'community.windows', 'microsoft.ad', 'microsoft.iis'
    Unsupported = 'ansible.windows.win_updates'  # Does not support App Control right now
    TimeStampServer = 'http://timestamp.acs.microsoft.com'
    Verbose = $true
}
New-AnsiblePowerShellSignature @signParams
