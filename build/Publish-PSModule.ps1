param
(
	#
    [parameter(Mandatory=$false)]
    [string] $ModulePath = ".\release\MSAL.PS\2.5.0.1",
    #
    [parameter(Mandatory=$true)]
    [string] $NuGetApiKey
)

Publish-Module -Path $ModulePath -NuGetApiKey $NuGetApiKey
