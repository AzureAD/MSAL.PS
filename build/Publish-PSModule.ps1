param
(
	# Path to Module
<<<<<<< HEAD
    [parameter(Mandatory=$false)]
    [string] $ModulePath = ".\release\MSAL.PS\4.8.2.1",
=======
    [Parameter(Mandatory=$false)]
    [string] $ModulePath = ".\release\MSAL.PS\4.7.1.2",
>>>>>>> db3bd28c6a9969971daa7b80af34705d8c2e3aaf
    # API Key for PowerShell Gallery
    [Parameter(Mandatory=$true)]
    [string] $NuGetApiKey
)

Publish-Module -Path $ModulePath -NuGetApiKey $NuGetApiKey
