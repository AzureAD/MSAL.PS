# MSAL.PS

[![PSGallery Version](https://img.shields.io/powershellgallery/v/MSAL.PS.svg?style=flat&logo=powershell&label=PSGallery%20Version)](https://www.powershellgallery.com/packages/MSAL.PS) [![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/MSAL.PS.svg?style=flat&logo=powershell&label=PSGallery%20Downloads)](https://www.powershellgallery.com/packages/MSAL.PS) [![PSGallery Platform](https://img.shields.io/powershellgallery/p/MSAL.PS.svg?style=flat&logo=powershell&label=PSGallery%20Platform)](https://www.powershellgallery.com/packages/MSAL.PS)

The MSAL.PS PowerShell module wraps MSAL.NET functionality into PowerShell-friendly cmdlets and is not supported by Microsoft. Microsoft support does not extend beyond the underlying MSAL.NET library. For any inquiries regarding the PowerShell module itself, you may contact the author on GitHub or PowerShell Gallery.
MSAL.NET (Microsoft.Identity.Client) is an authentication library which enables you to acquire tokens from Azure AD, to access protected Web APIs (Microsoft APIs or applications registered with Azure Active Directory).

## Install from the PowerShell Gallery
```PowerShell
Install-Module MSAL.PS
```

If you encounter the error, `WARNING: The specified module 'MSAL.PS' with PowerShellGetFormatVersion '2.0' is not supported by the current version of PowerShellGet. Get the latest version of the PowerShellGet module to install this module, 'MSAL.PS'` then run the following commands to proceed with the installation.

```PowerShell
## Update Nuget Package and PowerShellGet Module
Install-PackageProvider NuGet -Force
Install-Module PowerShellGet -Force
```

If you encounter the error, `WARNING: The version '1.4.7' of module 'PackageManagement' is currently in use. Retry the operation after closing the applications.`. then run the following commands to proceed with the installation.


```PowerShell
Update-Module -Name PowerShellGet -RequiredVersion XX.XX.X
# Example: Update-Module -Name PowerShellGet -RequiredVersion 2.2.5

## In a new PowerShell process, install the MSAL.PS Module. Restart PowerShell console if this fails.
&(Get-Process -Id $pid).Path -Command { Install-Module MSAL.PS }
Import-Module MSAL.PS
```

## Usage and Examples
The built-in help commands in PowerShell can be used to learn about each command in the module.
```PowerShell
## View usage examples.
Get-Help Get-MsalToken -Examples

## View full help.
Get-Help Get-MsalToken -Full
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
