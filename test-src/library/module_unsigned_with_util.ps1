#!powershell

#AnsibleRequires -CSharpUtil Ansible.Basic

<#
Unsigned modules in App Control are run in CLM and cannot reference any
module_utils. This will fail to run against a host with an App Control policy.
See module_unsigned.ps1 for a way to run a standalone module in CLM.
#>

$module = [Ansible.Basic.AnsibleModule]::Create($args, @{})
$module.ExitJson()
