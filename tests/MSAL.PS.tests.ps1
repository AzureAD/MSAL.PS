
Import-Module ..\**\CommonFunctions.psm1

Remove-Module MSAL.PS -ErrorAction SilentlyContinue
Import-Module ..\src\MSAL.PS.psd1

### Parameters
[string] $TenantId = 'jasoth.onmicrosoft.com'
[uri] $RedirectUri = 'https://login.microsoftonline.com/common/oauth2/nativeclient'

### Test PublicClient
[string] $PublicClientId = 'e94dfd9b-a9f6-42df-8350-f56105097891'
[string[]] $Scopes = @(
    #'https://graph.microsoft.com/.default'
    'https://graph.microsoft.com/Directory.AccessAsUser.All'
    'https://graph.microsoft.com/Directory.Read.All'
)

## Test Public Client Automatic
$MsalToken = Get-MsalToken -TenantId $TenantId -ClientId $PublicClientId -Scopes $Scopes -Verbose
## Test Public Client Interactive
Get-MsalToken -TenantId $TenantId -ClientId $PublicClientId -Scopes $Scopes -Interactive -Verbose
## Test Public Client IntegratedWindowsAuth
Get-MsalToken -TenantId $TenantId -ClientId $PublicClientId -Scopes $Scopes -IntegratedWindowsAuth -Verbose
## Test Public Client Silent
Get-MsalToken -TenantId $TenantId -ClientId $PublicClientId -Scopes $Scopes -Silent -Verbose

## Get Application and Users
$ClientApplication = Get-MsalClientApplication -ClientId $PublicClientId
Get-MsalAccount -ClientApplication $ClientApplication


### Test ConfidentialClient
[string] $ConfidentialClientId = 'e001258f-ee21-4c08-9205-9031a3a1cfbd'
[securestring] $ConfidentialClientSecret = Convertto-SecureString 'SuperSecretString' -AsPlainText -Force
[System.Security.Cryptography.X509Certificates.X509Certificate2] $ConfidentialClientCertificate = Get-Item Cert:\CurrentUser\My\b12afe95f226d94dd01d3f61ae3dbb1c4947ef62
[string[]] $Scopes = @(
    'https://graph.microsoft.com/.default'
    #'https://graph.microsoft.com/User.Read.All'
)

if ($MsalToken.AccessToken) {
    ## Create New Confidential Client?
    [string] $ConfidentialClientId = New-AzureADApplicationConfidentialClient $MsalToken | Select-Object appId
    ## Reset ClientSecret?
    [securestring] $ConfidentialClientSecret = Add-AzureADApplicationClientSecret $MsalToken $ConfidentialClientId
    ## Reset ClientCertificate?
    $ConfidentialClientCertificate = Add-AzureADApplicationClientCertificate $MsalToken $ConfidentialClientId
}

## Test Confidential Client Secret
Get-MsalToken -TenantId $TenantId -ClientId $ConfidentialClientId -ClientSecret $ConfidentialClientSecret -Scopes $Scopes -Verbose
## Test Confidential Client Certificate
Get-MsalToken -TenantId $TenantId -ClientId $ConfidentialClientId -ClientCertificate $ConfidentialClientCertificate -Scopes $Scopes -Verbose


### Cleanup
## Clear Consent
Get-AzureADServicePrincipal -Filter "AppId eq '$PublicClientId'" | Get-AzureADServicePrincipalOAuth2PermissionGrant | Remove-AzureADOAuth2PermissionGrant

## Remove Certificates from Certificate Store
Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -eq "CN=ConfidentialClient" | Remove-Item
