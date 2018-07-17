param
(
	#
    [parameter(Mandatory=$false)]
    [string] $ModulePath = ".\release\MSAL.PS\1.1.4.1",
    #
    [parameter(Mandatory=$true)]
    [string] $NuGetApiKey
)

Publish-Module -Path $ModulePath -NuGetApiKey $NuGetApiKey
