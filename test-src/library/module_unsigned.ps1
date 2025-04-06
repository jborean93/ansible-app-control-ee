#!powershell

#AnsibleRequires -Wrapper

<#
Unsigned modules in App Control are run in CLM and cannot be used with ansible
module_utils so we use the -Wrapper and handle it all inline. The remaining
code must all be valid for running in CLM or else it will fail.
#>

@{
    language_mode = $ExecutionContext.SessionState.LanguageMode.ToString()
    whoami = [Environment]::UserName
    ünicode = $complex_args.input
} | ConvertTo-Json
