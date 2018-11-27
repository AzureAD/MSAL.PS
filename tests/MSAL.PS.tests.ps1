
Remove-Module MSAL.PS -ErrorAction SilentlyContinue
Import-Module ..\src\MSAL.PS.psd1

[string] $TenantId = 'jasoth.onmicrosoft.com'
[pscredential] $PublicClient = Get-Credential '00000000-0000-0000-0000-000000000000',(ConvertTo-SecureString 'null' -AsPlainText -Force)
if (!$ConfidentialClient) { [pscredential] $ConfidentialClient = Get-Credential -UserName '00000000-0000-0000-0000-000000000000' }
[string[]] $Scopes = @(
    'https://graph.microsoft.com/.default'
)

## Test Public Client
Get-MSALToken -TenantId $TenantId -ClientId $PublicClient.UserName -Scopes $Scopes

## Test Confidential Client
Get-MSALToken -TenantId $TenantId -ClientId $ConfidentialClient.UserName -ClientSecret $ConfidentialClient.Password -Scopes $Scopes

## Get Application and Users
$ClientApplication = Get-MSALClientApplication -ClientId $PublicClient.UserName
Get-MSALAccount -ClientApplication $ClientApplication
