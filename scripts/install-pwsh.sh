export PWSH_VERSION="${1}"

if [ "$( uname -i )" == "aarch64" ]
then
    export PWSH_ARCH="arm64"
else
    export PWSH_ARCH="x64"
fi

curl -L -o /tmp/powershell.tar.gz "https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell-${PWSH_VERSION}-linux-${PWSH_ARCH}.tar.gz"
mkdir -p /opt/microsoft/powershell/7
tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7
rm -f /tmp/powershell.tar.gz
chmod +x /opt/microsoft/powershell/7/pwsh
/opt/microsoft/powershell/7/pwsh -Command 'Install-PSResource -Name OpenAuthenticode -Quiet -TrustRepository'
