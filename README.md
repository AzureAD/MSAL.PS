# MSAL.PS

[![PSGallery Version](https://img.shields.io/powershellgallery/v/MSAL.PS.svg?style=flat&logo=powershell&label=PSGallery%20Version)](https://www.powershellgallery.com/packages/MSAL.PS) [![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/MSAL.PS.svg?style=flat&logo=powershell&label=PSGallery%20Downloads)](https://www.powershellgallery.com/packages/MSAL.PS) [![PSGallery Platform](https://img.shields.io/powershellgallery/p/MSAL.PS.svg?style=flat&logo=powershell&label=PSGallery%20Platform)](https://www.powershellgallery.com/packages/MSAL.PS)

The MSAL.PS PowerShell module wraps MSAL.NET functionality into PowerShell-friendly cmdlets and is not supported by Microsoft. Microsoft support does not extend beyond the underlying MSAL.NET library. For any inquiries regarding the PowerShell module itself, you may contact the author on GitHub or PowerShell Gallery.
MSAL.NET (Microsoft.Identity.Client) is an authentication library which enables you to acquire tokens from Azure AD, to access protected Web APIs (Microsoft APIs or applications registered with Azure Active Directory).

## Install from the PowerShell Gallery
```PowerShell
Install-Module MSAL.PS
```

If you see the warning, `You are installing the modules from an untrusted repository. If you trust this repository, change its InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to install the modules from 'PSGallery'?`, ensure the repository is PSGallery and select Yes.

The signing certificate for MSAL.PS is changing to use Microsoft's code signing process. When upgrading to version 4.37.0.x from a previous version, you will see the following error, `PackageManagement\Install-Package : Authenticode issuer 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' of the new module 'MSAL.PS' with version 'x.x.x.x' from root certificate authority 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' is not matching with the authenticode issuer 'CN=Jason Thompson, O=Jason Thompson, L=Cincinnati, S=Ohio, C=US' of the previously-installed module 'MSAL.PS' with version 'x.x.x.x' from root certificate authority 'CN=DigiCert Assured ID Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US'. If you still want to install or update, use -SkipPublisherCheck parameter.`, which can be resolved using the following command.

```PowerShell
Install-Module MSAL.PS -SkipPublisherCheck -Force
```

If you encounter the error, `WARNING: The specified module 'MSAL.PS' with PowerShellGetFormatVersion '2.0' is not supported by the current version of PowerShellGet. Get the latest version of the PowerShellGet module to install this module, 'MSAL.PS'`, then run the following commands before attempting the MSAL.PS installation again.

```PowerShell
## Update Nuget Package and PowerShellGet Module
Install-PackageProvider NuGet -Scope CurrentUser -Force
Install-Module PowerShellGet -Scope CurrentUser -Force -AllowClobber
## Remove old modules from existing session
Remove-Module PowerShellGet,PackageManagement -Force -ErrorAction Ignore
## Import updated module
Import-Module PowerShellGet -MinimumVersion 2.0 -Force
Import-PackageProvider PowerShellGet -MinimumVersion 2.0 -Force
```

If you encounter the error, `WARNING: The version '1.4.7' of module 'PackageManagement' is currently in use. Retry the operation after closing the applications.` then try closing your PowerShell console and reopen.

If at any point you see the error, `<Path> cannot be loaded because running scripts is disabled on this system. For more information, see about_Execution_Policies at http://go.microsoft.com/fwlink/?LinkID=135170.`, you must enable local scripts to be run.

```PowerShell
## Set globally on device
Set-ExecutionPolicy RemoteSigned
## Or set for just for current PowerShell session.
Set-ExecutionPolicy RemoteSigned -Scope Process
```

## Usage and Examples
The built-in help commands in PowerShell can be used to learn about each command in the module.
```PowerShell
## View usage examples.
Get-Help Get-MsalToken -Examples

## View full help.
Get-Help Get-MsalToken -Full
```
### Confidential Client Example

AAD P1 licenses required. More info found on [MS Docs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-manage-inactive-user-accounts).
```PowerShell
Import-Module MSAL.PS
$clientId = "YOURCLIENTID"
$clientSecret = "YOURCLIENTSECRET"
$tenantId = "YOURTENANTID"

$ConfidentialClientOptions = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = $clientId; ClientSecret = $clientSecret; TenantId = $tenantId }
$ConfidentialClient = $ConfidentialClientOptions | New-MsalClientApplication
$tokenObj = Get-MsalToken -Scope 'https://graph.microsoft.com/.default' -ConfidentialClientApplication $ConfidentialClient
$apiUrl = "https://graph.microsoft.com/beta/users?filter=signInActivity/lastSignInDateTime le 2021-06-21T00:00:00Z&`$select=userPrincipalName,displayName,mail,signInActivity"
$res = Invoke-RestMethod -Headers @{Authorization = "Bearer $($tokenObj.AccessToken)"} -Uri $apiUrl -Method Get
```

## Contents

| File/folder       | Description                                             |
|-------------------|---------------------------------------------------------|
| `build`           | Scripts to package, test, sign, and publish the module. |
| `src`             | Module source code.                                     |
| `tests`           | Test scripts for module.                                |
| `.gitignore`      | Define what to ignore at commit time.                   |
| `README.md`       | This README file.                                       |
| `LICENSE`         | The license for the module.                             |

## Getting Started

Dependencies: [MSAL.NET (Microsoft.Identity.Client)](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki)

<!-- ## Build and Test

TODO: Describe and show how to build your code and run the tests. -->

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

<!-- If you want to learn more about creating good readme files then refer the following [guidelines](https://www.visualstudio.com/en-us/docs/git/create-a-readme). -->
