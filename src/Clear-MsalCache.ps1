<#
.SYNOPSIS
    Clear all client applications from local session cache.
.DESCRIPTION
    This cmdlet clear all client application objects from the local session cache.
.EXAMPLE
    PS C:\>Clear-MsalCache
    Clear all client applications from local session cache.
#>
function Clear-MsalCache {
    [CmdletBinding()]
    param()

    $script:PublicClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IPublicClientApplication]'
    $script:ConfidentialClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IConfidentialClientApplication]'
}
