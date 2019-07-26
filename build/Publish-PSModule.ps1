param
(
	#
    [parameter(Mandatory=$false)]
    [string] $ModulePath = ".\release\MSAL.PS\4.2.1.1",
    #
    [parameter(Mandatory=$true)]
    [string] $NuGetApiKey
)

Publish-Module -Path $ModulePath -NuGetApiKey $NuGetApiKey
