[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $Value,

    [Parameter()]
    [switch]
    $AsRaw
)

$res = @{
    language_mode = $ExecutionContext.SessionState.LanguageMode.ToString()
    whoami = [Environment]::UserName
    ünicode = $Value
}

if ($AsRaw) {
    $res
}
else {
    $res | ConvertTo-Json
}
