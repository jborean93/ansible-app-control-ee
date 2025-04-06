#!powershell

#AnsibleRequires -CSharpUtil Ansible.Basic

using namespace Ansible.Basic

<#
Signed modules in App Control run as normal modules and can use the normal
module_utils.
#>

$spec = @{
    options = @{
        input = @{ type = 'str' }
    }
}
$module = [AnsibleModule]::Create($args, $spec)

$module.Result.language_mode = $ExecutionContext.SessionState.LanguageMode.ToString()
$module.Result.whoami = [Environment]::UserName
$module.Result.ünicode = $module.Params.input

$module.ExitJson()
