param
(
	# 
    [parameter(Mandatory=$false)]
    [string] $ModulePath = ".\release\ADAL.PS\3.19.4.2",
    # 
    [parameter(Mandatory=$true)]
    [string] $NuGetApiKey
)

Publish-Module -Path $ModulePath -NuGetApiKey $NuGetApiKey
