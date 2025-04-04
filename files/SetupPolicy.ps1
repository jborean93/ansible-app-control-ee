[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $CertPath,

    [Parameter(Mandatory)]
    [string]
    $PolicyName
)

$ErrorActionPreference = 'Stop'

$policyPath = "C:\Windows\TEMP\$PolicyName.xml"

Copy-Item "$env:windir\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml" $policyPath
Set-CIPolicyIdInfo -FilePath $policyPath -PolicyName $policyName -PolicyId (New-Guid)
Set-CIPolicyVersion -FilePath $policyPath -Version "1.0.0.0"
Add-SignerRule -FilePath $policyPath -CertificatePath $CertPath -User
Set-RuleOption -FilePath $policyPath -Option 0          # Enabled:UMCI
Set-RuleOption -FilePath $policyPath -Option 3 -Delete  # Enabled:Audit Mode
Set-RuleOption -FilePath $policyPath -Option 11 -Delete # Disabled:Script Enforcement
Set-RuleOption -FilePath $policyPath -Option 19         # Enabled:Dynamic Code Security

$policyBinPath = "$env:windir\System32\CodeIntegrity\SiPolicy.p7b"
$null = ConvertFrom-CIPolicy -XmlFilePath $policyPath -BinaryFilePath $policyBinPath

$rc = Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{
    FilePath = $policyBinPath
}
if ($rc.ReturnValue) {
    throw "PS_UpdateAndCompareCIPolicy Update failed $($rc.ReturnValue)"
}
