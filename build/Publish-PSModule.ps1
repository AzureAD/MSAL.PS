param
(
	# Path to Module
    [Parameter(Mandatory=$false)]
    [string] $ModulePath = ".\release\MSAL.PS\4.7.1.2",
    # API Key for PowerShell Gallery
    [Parameter(Mandatory=$true)]
    [string] $NuGetApiKey
)

Publish-Module -Path $ModulePath -NuGetApiKey $NuGetApiKey
