# Ansible Windows App Control Execution Environment
This is an example of how you can build an Ansible Execution Environment (`EE`) with Windows content that is trusted to run with a deployed Windows App Control policy.
Support for Windows App Control is being added in the Ansible 2.19 release as a tech preview.
Some of the content and setup may change over time as we adjust the interface and how Ansible interacts with App Control.

## Background
Windows App Control, formerly known as Windows Defender Application Control (`WDAC`), is a security feature in Windows that can block all executables and scripts from running unless explicitly signed by a trusted publisher.
When attempting to run Ansible against a host secured by WDAC it will fail with the following error:

```
$ ansible windows -m win_ping

win | FAILED! => {
    "changed": false,
    "module_stderr": "Cannot invoke method. Method invocation is supported only on core types in this language mode.\r\n    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException\r\n    + FullyQualifiedErrorId : MethodInvocationNotSupportedInConstrainedLanguage\r\n",
    "module_stdout": "",
    "msg": "MODULE FAILURE\nSee stdout/stderr for the exact error",
    "rc": 1
}
```

Ansible 2.19 introduces a tech preview feature that allows you to sign content inside Ansible as well as within custom collections, and local scripts.
These signed scripts will be invoked by Ansible in a specific way that works with the active App Control policy on the target Windows host.
Using this repo, you can build an EE that contains the four main Windows collections, `ansible.windows`, `microsoft.ad`, `microsoft.iis`, and `community.windows`, which have been signed with a certificate trusted by the App Control policy on a target Windows host.

## Ansible Metadata
There are two types of operations done by Ansible when it comes to verifying a signature for App Control:

+ Inline signatures - content contains Authenticode signature in the script itself
+ Collection `meta/powershell_signatures.ps1` metadata script

Any content not included in a collection (playbook `library/` modules, script files, etc) must use the inline signature format.
The signature is verified at runtime when Ansible attempts to run any content that is not included in the `powershell_signatures.ps1` hash list.

The second format is the PowerShell script in a collection under `${COLLECTION_ROOT}/meta/powershell_signatures.ps1`.
This PowerShell script is signed with an inline signature and it contains the SHA256 hash and runtime mode of the collections content.
The format of the file is (subject to tech preview status):

```powershell
#AnsibleVersion 1

@{
    HashList = @(
        # ansible.windows.win_ping.ps1
        @{
            Hash = 'SHA256 hash of the win_ping module'
            # Trusted - Will run in FLM
            # Unsupported - Will error if host has App Control enabled
            # Anything else or missing - Will run in CLM if host has App Control enabled
            Mode = 'Trusted|Unsupported'
        }
        # Repeats for all other modules/module_utils
        ...
    )
}

# SIG # Begin signature block
# MIId5gYJKoZIhvcNAQcCoIId1zCCHdMCAQMxDTALBglghkgBZQMEAgEwewYKKwYB
# ...
# SIG # End signature block
```

Ansible will first verify the inline Authenticode signature or the `powershell_signatures.ps1` is trusted by the App Control policy of the Windows host, if it is not then it is ignored.
Any incoming script will verify whether the SHA256 of itself (encoded as UTF-8 bytes) is contained in any of the provided collection's `HashList`.

The [New-AnsiblePowerShellSignature](ee/scripts/New-AnsiblePowerShellSignature.ps1) function can be used to sign both the `exec_wrapper.ps1` inside Ansible and any collections you provide to it.
The PowerShell example below shows how Ansible (`ansible.builtin`) and extra collections can be signed by that function:

```powershell
. ./New-AnsiblePowerShellSignature.ps1

$certPath = 'cert.pfx'
$certPass = Read-Host -Prompt "Enter pfx password" -AsSecureString
$signParams = @{
    Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certPath, $certPass)
    Collection = 'ansible.builtin', 'ansible.windows', 'community.windows', 'microsoft.ad', 'microsoft.iis'
    Unsupported = 'ansible.windows.win_updates'  # Does not support App Control right now
    TimeStampServer = 'http://timestamp.acs.microsoft.com'
    Verbose = $true
}
New-AnsiblePowerShellSignature @signParams
```

You can also use `Skip = 'namespace.name.module'` as a way to not trust a collection module but still allow it to run under CLM if you wish.

Keep in mind there is no official Red Hat support for this script while Ansible and Windows App Control is a tech preview.

## Trying It Out
To try out Ansible and Windows App Control we will need the following:

+ A Windows host with an App Control policy enforced - [see Environment Setup](#environment-setup)
+ An Ansible Execution Environment image with signed Ansible content - [see Build Execution Environment](#build-execution-environment)
+ A test Ansible directory with local signed and unsigned content - [see Testing Setup](#testing-setup)

Once all three areas have been setup we can run our tests outline in [Testing Ansible and App Control](#testing-ansible-and-app-control).

### Environment Setup
This section will go over how to setup a Windows environment with an App Control policy applied and a `.pfx` file we can use when building the EE.
You can skip this section if you have your own environment and certificate to use or wish to set it up manually.

The following programs need to be pre-installed for this setup:

+ `Vagrant` - for setting up the Windows VM
+ `uv` - Python package manager

To setup the Windows VM we will test against, run `vagrant up`.
After the VM is ready edit the [inventory.ini](./inventory.ini) file and set the correct IP address under the `ansible_host=` variable so Ansible knows how to communicate with the host.
Run the following commands to configure the Windows host:

```bash
# Make sure vagrant up has been called and inventory.ini has the host IP set.
uv venv
uv pip install -r requirements.txt
uv run ansible-galaxy collection install -r requirements.yml -p collections
uv run ansible-playbook setup.yml
```

This will create a certificate `.pfx` and place it in the [ee](./ee) directory for use when creating the EE image and also configure the Windows host with an App Control policy that will trust software signed by that `.pfx`.
If you try and run Ansible against that host after the policy is active it will fail.
You can even see that PowerShell is in Constrained Language Mode (`CLM`) and will fail to run code not allowed in CLM.

```bash
vagrant winrm --no-tty --command '$ExecutionContext.SessionState.LanguageMode'
# ConstrainedLanguage

vagrant winrm --no-tty --command '[Console]::WriteLine("test")'
# Cannot invoke method. Method invocation is supported only on core types in this language mode.
# At line:1 char:1
# + [Console]::WriteLine("test")
# + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#     + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
#     + FullyQualifiedErrorId : MethodInvocationNotSupportedInConstrainedLanguage

uv run ansible windows -m ansible.windows.win_ping
# win | FAILED! =>
#     changed: false
#     module_stderr: |-
#         Cannot invoke method. Method invocation is supported only on core types in this language mode.
#             + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
#             + FullyQualifiedErrorId : MethodInvocationNotSupportedInConstrainedLanguage
#     module_stdout: ''
#     msg: |-
#         MODULE FAILURE: No start of json char found
#         See stdout/stderr for the exact error
#     rc: 1
```

This setup is only designed for testing purposes, in a real environment you should be using a certificate issued by a proper authority, like Active Directory Certificate Services.
You should also look at using supplemental policies and using tools like the [WDAC Wizard](https://webapp-wdac-wizard.azurewebsites.net) to craft policies specific to your environment and signing the policy binaries.
To cleanup the environment, run `vagrant destroy` and it will shut down the VM and removeand files it created.
If you wish to remove the App Control policy you need to delete the file at `C:\Windows\System32\CodeIntegrity\SiPolicy.p7b` and reboot the Windows host.

### Build Execution Environment
To build the EE you will need to ensure the `.pfx` and password for that PFX are in `ee/cert.pfx` and `ee/cert_pass` respectively.
If you have used the environment setup above, it will automatically create these files for you.

Once the files have been copied you can build the EE with the following command, feel free to add `-vvv` if you wish to see the progress of each stage:

```bash
pushd ee
uv run ansible-builder \
    build \
    --tag windows-app-control-ee \
    --extra-build-cli-args="--secret id=PFX_PASS,src=$( pwd )/cert_pass" -vvv
popd
```

### Testing Setup
Before testing we will take a copy of the `test-src` directory and sign the content inside it with the `cert.pfx` file.
This new `test` directory will be used in our test to verify that user supplied content outside of a collection can still be run in an App Control enforced host.
It contains a signed and unsigned module file and PowerShell script to use for testing signed PowerShell content outside of a collection.

The first step is to make a copy of the `test-src` directory and copy the cfg/inventory file with the following:

```bash
cp -R test-src test
cp inventory.ini test/
cp ansible.cfg test/
```

Once copied we can use `pwsh` and the `OpenAuthenticode` module to sign the content using the `ee/cert.pfx` trusted by the target Windows host.
Run the following in a new `pwsh` shell to sign the content:

```powershell
if (-not (Get-Module -Name OpenAuthenticode -ListAvailable | Where-Object Version -ge '0.5.0')) {
    Install-PSResource -Name OpenAuthenticode -TrustRepository -Version '[0.5.0,)'
}

$certPath = "ee/cert.pfx"
$certPass = (Get-Content ee/cert_pass -Raw).TrimEnd()
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certPath, $certPass)

$signingParams = @{
    Certificate = $cert
    HashAlgorithm = 'SHA256'
    TimeStampServer = 'http://timestamp.acs.microsoft.com'
}
@(
    'test/files/script_signed.ps1'
    'test/library/module_signed.ps1'
) | Set-OpenAuthenticodeSignature @signingParams
```

Looking at the files being signed at `test/files/script_signed.ps1` and `test/library/module_signed.ps1` we can see that they no have an Authenticode signature at the end of the file in the format:

```
# SIG # Begin signature block
# MIId5gYJKoZIhvcNAQcCoIId1zCCHdMCAQMxDTALBglghkgBZQMEAgEwewYKKwYB
# ...
# SIG # End signature block
```

### Testing Ansible and App Control
Now that our environment is all setup we can enter the EE to try it all out.
In a proper environment you will most likely be using the EE with tools like `ansible-navigator` or Ansible Controller/Tower/AWX to run our built EE but in this case we will just open an interactive shell inside our EE with our test directory mounted.

```bash
podman run \
    --interactive \
    --rm \
    --tty \
    --volume "$( pwd )/test:/app-control" \
    --workdir /app-control \
    windows-app-control-ee
```

We can verify that our collections has been signed by verifying the files at `/usr/share/ansible/collections/ansible_collections/${NAMESPACE}/${NAME}/meta/powershell_signatures.ps1` contain the Authenticode signature footer like so:

```
cat /usr/share/ansible/collections/ansible_collections/ansible/windows/meta/powershell_signatures.ps1

#AnsibleVersion 1

@{
    HashList = @(
        ...
    )
}

# SIG # Begin signature block
# MIId5gYJKoZIhvcNAQcCoIId1zCCHdMCAQMxDTALBglghkgBZQMEAgEwewYKKwYB
# ...
# SIG # End signature block
```

We can then run our test playbook that shows how signed collection content, signed local content, and unsigned local content run against a Windows host with App Control.

```bash
ansible-playbook main.yml -v
```

```yaml
PLAY [run App Control tests] ***********************************************************************************************************************************************************************

TASK [run collection module that has been signed] **************************************************************************************************************************************************
ok: [win] =>
    changed: false
    ping: pong

TASK [run library adjacent module that has been inline signed] *************************************************************************************************************************************
ok: [win] =>
    changed: false
    language_mode: FullLanguage
    whoami: vagrant
    ünicode: café

TASK [run library module that is unsigned] *********************************************************************************************************************************************************
ok: [win] =>
    changed: false
    language_mode: ConstrainedLanguage
    whoami: vagrant
    ünicode: café

TASK [expect failure when running unsigned module with module_utils] *******************************************************************************************************************************
An exception occurred during task execution. To see the full traceback, use -vvv. The error was: at <ScriptBlock>, <No file>: line 39
fatal: [win]: FAILED! =>
    changed: false
    msg: 'failure during exec_wrapper: Cannot run untrusted PowerShell script ''ansible.modules.ansible.legacy.module_unsigned_with_util.ps1''
        in ConstrainedLanguage mode with module util imports.'
...ignoring

TASK [run script that has been signed] *************************************************************************************************************************************************************
changed: [win] =>
    changed: true
    rc: 0
    stderr: ''
    stderr_lines: <omitted>
    stdout: |-
        {
            "language_mode":  "FullLanguage",
            "whoami":  "vagrant",
            "ünicode":  "café"
        }
    stdout_lines: <omitted>

TASK [run script that is unsigned] *****************************************************************************************************************************************************************
changed: [win] =>
    changed: true
    rc: 0
    stderr: ''
    stderr_lines: <omitted>
    stdout: |-
        {
            "language_mode":  "ConstrainedLanguage",
            "whoami":  "vagrant",
            "ünicode":  "café"
        }
    stdout_lines: <omitted>

TASK [run signed content through win_powershell] ***************************************************************************************************************************************************
changed: [win] =>
    changed: true
    debug: []
    error: []
    host_err: ''
    host_out: ''
    information: []
    output:
    -   language_mode: FullLanguage
        whoami: vagrant
        ünicode: café
    result: {}
    verbose: []
    warning: []

TASK [run unsigned content through win_powershell] *************************************************************************************************************************************************
changed: [win] =>
    changed: true
    debug: []
    error: []
    host_err: ''
    host_out: ''
    information: []
    output:
    -   language_mode: ConstrainedLanguage
        whoami: vagrant
        ünicode: -Value
    result: {}
    verbose: []
    warning: []

TASK [run content through win_shell under CLM] *****************************************************************************************************************************************************
changed: [win] =>
    changed: true
    cmd: |-
        @{
            language_mode = $ExecutionContext.SessionState.LanguageMode.ToString()
            whoami = [Environment]::UserName
        } | ConvertTo-Json
    delta: '0:00:01.718758'
    end: '2025-04-06 18:59:34.708183'
    rc: 0
    start: '2025-04-06 18:59:32.989425'
    stderr: ''
    stderr_lines: <omitted>
    stdout: |-
        {
            "language_mode":  "ConstrainedLanguage",
            "whoami":  "vagrant"
        }
    stdout_lines: <omitted>
```

In this output we can see that:

+ `ansible.windows.win_ping` ran successfully proving our collection has been signed and verified
+ PowerShell scripts with inline signatures will run in `FullLanguage` mode `FLM`
+ PowerShell scripts without any signature (or a signature that isn't trusted) will run in `ConstrainedLanguage` mode `CLM`
+ PowerShell modules with inline signatures will run in `FLM`
+ PowerShell modules without any signature (or a signature that isn't trusted) will run in `CLM`
+ PowerShell modules without any signature (or a signature that isn't trusted) with module util references will fail even if those utils are trusted
+ We can still use `ansible.windows.win_powershell` to run arbitrary scripts but the script is run in `FLM` vs `CLM` depending on whether it is signed or not
+ We can still use `ansible.windows.win_shell` (or `win_command`) but scripts are always run in `CLM` regardless of whether they are signed or not

Any other module inside the 4 Ansible Windows collections inside the EE can also be run and tested with your own playbooks.
The only exception right now is the `ansible.windows.win_updates` module which is not currently supported in App Control and will fail when attempting to do so

```bash
ansible windows -m ansible.windows.win_updates -a 'state=searched'
```

```yaml
An exception occurred during task execution. To see the full traceback, use -vvv. The error was:    at System.Management.Automation.MshCommandRuntime.ThrowTerminatingError(ErrorRecord errorRecord)
win | FAILED! =>
    changed: false
    failed_update_count: 0
    filtered_updates: {}
    found_update_count: 0
    installed_update_count: 0
    msg: 'failure during exec_wrapper: Provided script for ''ansible_collections.ansible.windows.plugins.modules.win_updates.ps1''
        is marked as unsupported in CLM mode.'
    updates: {}
```
