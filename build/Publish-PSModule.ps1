param
(
	# Path to Module
    [parameter(Mandatory=$false)]
    [string] $ModulePath = ".\release\MSAL.PS\4.2.1.3",
    # API Key for PowerShell Gallery
    [parameter(Mandatory=$true)]
    [string] $NuGetApiKey
)

Publish-Module -Path $ModulePath -NuGetApiKey $NuGetApiKey
