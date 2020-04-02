param
(
	# Path to Module
    [parameter(Mandatory=$false)]
    [string] $ModulePath = ".\release\MSAL.PS\4.10.0.2",
    # API Key for PowerShell Gallery
    [Parameter(Mandatory=$true)]
    [string] $NuGetApiKey
)

Publish-Module -Path $ModulePath -NuGetApiKey $NuGetApiKey
