Set-StrictMode -Version 2.0

#Write-Warning 'The MSAL.PS PowerShell module wraps MSAL.NET functionality into PowerShell-friendly cmdlets and is not supported by Microsoft. Microsoft support does not extend beyond the underlying MSAL.NET library. For any inquiries regarding the PowerShell module itself, you may contact the author on GitHub or PowerShell Gallery.'

## PowerShell Desktop 5.1 does not dot-source ScriptsToProcess when a specific version is specified on import. This is a bug.
# if ($PSEdition -eq 'Desktop') {
#     $ModuleManifest = Import-PowershellDataFile (Join-Path $PSScriptRoot $MyInvocation.MyCommand.Name.Replace('.psm1','.psd1'))
#     if ($ModuleManifest.ContainsKey('ScriptsToProcess')) {
#         foreach ($Path in $ModuleManifest.ScriptsToProcess) {
#             . (Join-Path $PSScriptRoot $Path)
#         }
#     }
# }

## Azure Automation module import fails when ScriptsToProcess is specified in manifest. Referencing import script directly.
. (Join-Path $PSScriptRoot $MyInvocation.MyCommand.Name.Replace('.psm1','.ps1'))

## Global Variables
[System.Collections.Generic.List[Microsoft.Identity.Client.IPublicClientApplication]] $PublicClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IPublicClientApplication]'
[System.Collections.Generic.List[Microsoft.Identity.Client.IConfidentialClientApplication]] $ConfidentialClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IConfidentialClientApplication]'
