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

## Setup
This setup is only designed for testing purposes.
In a real environment you should be using a certificate issued by a proper authority, like Active Directory Certificate Services.
The App Control policy is also designed for testing purposes, using a tool like the [WDAC Wizard](https://webapp-wdac-wizard.azurewebsites.net) and signing the policy binaries should be done in a real environment.

The following PowerShell script will:

+ Generate a CA certificate and adds it to `Cert:\LocalMachine\Root`
+ Generates a code signing certificate signed by the CA and adds it to `Cert:\LocalMachine\TrustedPublisher`
+ Generates a PFX file with a random password stored in the current directory:
    + `cert.pfx` - The password protected PFX file that should be

```bash
pip install -r requirements.txt
ansible-galaxy collection install -r requirements.yml -p collections
ansible-playbook setup.yml
```

## Build
To build the EE you will need to copy the certificate PFX to the current directory under `cert.pfx`, create a file called `cert_pass` that contains the password for the PFX and then run the following command:

```bash
ansible-builder build --extra-build-cli-args="--secret id=PFX_PASS,src=$( pwd )/cert_pass"
```
