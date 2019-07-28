<#
.SYNOPSIS
    Get client application from local session cache.
.DESCRIPTION
    This cmdlet will return a client application object from the local session cache. If it does not yet exist, a new client application will be created and added to the cache.
.EXAMPLE
    PS C:\>Get-MsalClientApplication -ClientId '00000000-0000-0000-0000-000000000000'
    Get public client application using default settings.
.EXAMPLE
    PS C:\>$ConfidentialClientOptions = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Properties @{ ClientId = '00000000-0000-0000-0000-000000000000' }
    PS C:\>$ConfidentialClientOptions | Get-MsalClientApplication -ClientSecret (ConvertTo-SecureString 'SuperSecretString' -AsPlainText -Force) -TenantId '00000000-0000-0000-0000-000000000000'
    Pipe in confidential client options object to get a confidential client application using a client secret and target a specific tenant.
.EXAMPLE
    PS C:\>$ClientCertificate = Get-Item Cert:\CurrentUser\My\0000000000000000000000000000000000000000
    PS C:\>$ConfidentialClientOptions = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Properties @{ ClientId = '00000000-0000-0000-0000-000000000000'; TenantId = '00000000-0000-0000-0000-000000000000' }
    PS C:\>$ConfidentialClientOptions | Get-MsalClientApplication -ClientCertificate $ClientCertificate
    Pipe in confidential client options object to get a confidential client application using a client certificate and target a specific tenant.
#>
function Get-MsalClientApplication {
    [CmdletBinding(DefaultParameterSetName='PublicClient')]
    [OutputType([Microsoft.Identity.Client.PublicClientApplication],[Microsoft.Identity.Client.ConfidentialClientApplication])]
    param
    (
        # Identifier of the client requesting the token.
        [parameter(Mandatory=$true, ParameterSetName='PublicClient')]
        [parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        [parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret')]
        [parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate')]
        [parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [string] $ClientId,
        # Secure secret of the client requesting the token.
        [parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret')]
        [parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [securestring] $ClientSecret,
        # Client assertion certificate of the client requesting the token.
        [parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate')]
        [parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate,
        # Address to return to upon receiving a response from the authority.
        [parameter(Mandatory=$false)]
        [uri] $RedirectUri,
        # Tenant identifier of the authority to issue token.
        [parameter(Mandatory=$false)]
        [string] $TenantId,
        # Address of the authority to issue token.
        [parameter(Mandatory=$false)]
        [uri] $Authority,
        # Public client application options
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='PublicClient-InputObject', Position=0)]
        [Microsoft.Identity.Client.PublicClientApplicationOptions] $PublicClientOptions,
        # Confidential client application options
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ConfidentialClient-InputObject', Position=0)]
        [Microsoft.Identity.Client.ConfidentialClientApplicationOptions] $ConfidentialClientOptions,
        # Create application in cache if it does not already exist
        [parameter(Mandatory=$false)]
        [switch] $CreateIfMissing
    )

    [hashtable] $paramMsalClientApplication = $PSBoundParameters
    if ($paramMsalClientApplication.ContainsKey('CreateIfMissing')) { [void] $paramMsalClientApplication.Remove('CreateIfMissing') }
    $NewClientApplication = New-MsalClientApplication -ErrorAction Stop @paramMsalClientApplication
    switch -Wildcard ($PSCmdlet.ParameterSetName) {
        "PublicClient*" {
            [Microsoft.Identity.Client.IPublicClientApplication] $ClientApplication = $PublicClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri -and $_.AppConfig.TenantId -eq $NewClientApplication.AppConfig.TenantId } | Select-Object -First 1
            break
        }
        "ConfidentialClientSecret" {
            [Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.ClientSecret -eq $NewClientApplication.AppConfig.ClientSecret -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri -and $_.AppConfig.TenantId -eq $NewClientApplication.AppConfig.TenantId } | Select-Object -First 1
            break
        }
        "ConfidentialClientCertificate" {
            [Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.ClientCredentialCertificate -eq $NewClientApplication.AppConfig.ClientCredentialCertificate -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri -and $_.AppConfig.TenantId -eq $NewClientApplication.AppConfig.TenantId } | Select-Object -First 1
            break
        }
        "ConfidentialClient-InputObject" {
            if ($NewClientApplication.AppConfig.ClientSecret) {
                [Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.ClientSecret -eq $NewClientApplication.AppConfig.ClientSecret -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri -and $_.AppConfig.TenantId -eq $NewClientApplication.AppConfig.TenantId } | Select-Object -First 1
            }
            else {
                [Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $NewClientApplication.ClientId -and $_.AppConfig.ClientCredentialCertificate -eq $NewClientApplication.AppConfig.ClientCredentialCertificate -and $_.AppConfig.RedirectUri -eq $NewClientApplication.AppConfig.RedirectUri -and $_.AppConfig.TenantId -eq $NewClientApplication.AppConfig.TenantId } | Select-Object -First 1
            }
            break
        }
    }

    if (!$ClientApplication) {
        if ($CreateIfMissing) {
            $ClientApplication = $NewClientApplication
            Write-Verbose ('Adding Application with ClientId [{0}] and RedirectUri [{1}] to cache.' -f $ClientApplication.AppConfig.ClientId, $ClientApplication.AppConfig.RedirectUri)
            if ($ClientApplication -is [Microsoft.Identity.Client.IPublicClientApplication]) {
                $PublicClientApplications.Add($ClientApplication)
            }
            else {
                $ConfidentialClientApplications.Add($ClientApplication)
            }
        }
    }
    else {
        Write-Debug ('Application with ClientId [{0}] and RedirectUri [{1}] already exists. Using application from cache.' -f $ClientApplication.AppConfig.ClientId, $ClientApplication.AppConfig.RedirectUri)
    }

    return $ClientApplication
}
