# Ansible Windows App Control Execution Environment
This is an example of how you can build an Ansible Execution Environment (`EE`) with Windows content that is trusted to run with a deployed Windows App Control policy.

## Background
Windows App Control, formerly known as Windows Defender Application Control (`WDAC`), is a security feature in Windows that can block all executables and scripts from running unless explicitly signed by a trusted publisher.
When attempting to run Ansible against a host secured by WDAC it will fail with the following error:

```json
$ ansible windows -m win_ping

win | FAILED! => {
    "changed": false,
    "module_stderr": "Cannot invoke method. Method invocation is supported only on core types in this language mode.\r\n    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException\r\n    + FullyQualifiedErrorId : MethodInvocationNotSupportedInConstrainedLanguage\r\n",
    "module_stdout": "",
    "msg": "MODULE FAILURE\nSee stdout/stderr for the exact error",
    "rc": 1
}
```

Ansible 2.19 introduces a tech preview feature that allows you to sign content inside Ansible as well as with custom collections, and local scripts in order to work with the App Control policy on the target Windows host.
Using this repo, you can build an EE that contains the four main Windows collections, `ansible.windows`, `microsoft.ad`, `microsoft.iis`, and `community.windows`, which have been signed with a certificate trusted by the App Control policy on a target Windows host.

## Requirements


```powershell
$testPrefix = 'Ansible-WDAC'
$certPassword = ConvertTo-SecureString -String '{{ cert_pw }}' -Force -AsPlainText
$remoteTmpDir = '{{ remote_tmp_dir }}'
$enhancedKeyUsage = [Security.Cryptography.OidCollection]::new()
$null = $enhancedKeyUsage.Add('1.3.6.1.5.5.7.3.3')  # Code Signing
$caParams = @{
    Extension = @(
        [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true),
        [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new('KeyCertSign', $false),
        [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension ]::new($enhancedKeyUsage, $false)
    )
    CertStoreLocation = 'Cert:\CurrentUser\My'
    NotAfter = (Get-Date).AddDays(1)
    Type = 'Custom'
}
$ca = New-SelfSignedCertificate @caParams -Subject "CN=$testPrefix-Root"
$certParams = @{
    CertStoreLocation = 'Cert:\CurrentUser\My'
    KeyUsage = 'DigitalSignature'
    TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
    Type = 'Custom'
}
$cert = New-SelfSignedCertificate @certParams -Subject "CN=$testPrefix-Signed" -Signer $ca
$null = $cert | Export-PfxCertificate -Password $certPassword -FilePath "$remoteTmpDir\signing.pfx"
$cert.Export('Cert') | Set-Content -LiteralPath "$remoteTmpDir\signing.cer" -Encoding Byte
$certUntrusted = New-SelfSignedCertificate @certParams -Subject "CN=$testPrefix-Untrusted"
$null = $certUntrusted | Export-PfxCertificate -Password $certPassword -FilePath "$remoteTmpDir\untrusted.pfx"
$caWithoutKey = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ca.Export('Cert'))
$certWithoutKey = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert.Export('Cert'))
Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($ca.Thumbprint)" -DeleteKey -Force
Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey -Force
Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certUntrusted.Thumbprint)" -DeleteKey -Force
$root = Get-Item Cert:\LocalMachine\Root
$root.Open('ReadWrite')
$root.Add($caWithoutKey)
$root.Dispose()
$trustedPublisher = Get-Item Cert:\LocalMachine\TrustedPublisher
$trustedPublisher.Open('ReadWrite')
$trustedPublisher.Add($certWithoutKey)
$trustedPublisher.Dispose()
@{
    ca_thumbprint = $caWithoutKey.Thumbprint
    thumbprint = $certWithoutKey.Thumbprint
    untrusted_thumbprint = $certUntrusted.Thumbprint
} | ConvertTo-Json

$tmpPath = '{{ remote_tmp_dir }}'
$policyPath = Join-Path $tmpPath policy.xml
$certPath = Join-Path $tmpPath signing.cer
$policyName = 'Ansible_AppControl_Test'
Copy-Item "$env:windir\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml" $policyPath
Set-CIPolicyIdInfo -FilePath $policyPath -PolicyName $policyName -PolicyId (New-Guid)
Set-CIPolicyVersion -FilePath $policyPath -Version "1.0.0.0"
Add-SignerRule -FilePath $policyPath -CertificatePath $certPath -User
Set-RuleOption -FilePath $policyPath -Option 0          # Enabled:UMCI
Set-RuleOption -FilePath $policyPath -Option 3 -Delete  # Enabled:Audit Mode
Set-RuleOption -FilePath $policyPath -Option 11 -Delete # Disabled:Script Enforcement
Set-RuleOption -FilePath $policyPath -Option 19         # Enabled:Dynamic Code Security
# Using $tmpPath has this step fail
$policyBinPath = "$env:windir\System32\CodeIntegrity\SiPolicy.p7b"
$null = ConvertFrom-CIPolicy -XmlFilePath $policyPath -BinaryFilePath $policyBinPath
$ciTool = Get-Command -Name CiTool.exe -ErrorAction SilentlyContinue
$policyId = $null
if ($ciTool) {
    $setInfo = & $ciTool --update-policy $policyBinPath *>&1
    if ($LASTEXITCODE) {
        throw "citool.exe --update-policy failed ${LASTEXITCODE}: $setInfo"
    }
    $policyId = & $ciTool --list-policies --json |
        ConvertFrom-Json |
        Select-Object -ExpandProperty Policies |
        Where-Object FriendlyName -eq $policyName |
        Select-Object -ExpandProperty PolicyID
}
else {
    $rc = Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{
        FilePath = $policyBinPath
    }
    if ($rc.ReturnValue) {
        throw "PS_UpdateAndCompareCIPolicy Update failed $($rc.ReturnValue)"
    }
}
@{
    policy_id = $policyId
    path = $policyBinPath
} | ConvertTo-Json
```


## Build
To build the EE you will need to copy the certificate PFX to the current directory under `cert.pfx`, create a file called `cert_pass` that contains the password for the PFX and then run the following command:

```bash
ansible-builder build --extra-build-cli-args="--secret id=PFX_PASS,src=$( pwd )/cert_pass"
```
