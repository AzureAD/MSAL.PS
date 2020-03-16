<#
.SYNOPSIS
    Create new client application.
.DESCRIPTION
    This cmdlet will return a new client application object which can be used with the Get-MsalToken cmdlet.
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
function New-MsalClientApplication {
    [CmdletBinding(DefaultParameterSetName='PublicClient')]
    [OutputType([Microsoft.Identity.Client.PublicClientApplication],[Microsoft.Identity.Client.ConfidentialClientApplication])]
    param
    (
        # Identifier of the client requesting the token.
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientClaims', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientAssertion', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [string] $ClientId,
        # Secure secret of the client requesting the token.
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [securestring] $ClientSecret,
        # Client assertion certificate of the client requesting the token.
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientClaims')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate,
        # Set the specific client claims to sign. ClientCertificate must also be specified.
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientClaims')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [hashtable] $ClientClaims,
        # Set client assertion used to prove the identity of the application to Azure AD. This is a Base-64 encoded JWT.
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientAssertion')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [string] $ClientAssertion,
        # Address to return to upon receiving a response from the authority.
        [Parameter(Mandatory=$false)]
        [uri] $RedirectUri,
        # Tenant identifier of the authority to issue token.
        [Parameter(Mandatory=$false)]
        [string] $TenantId,
        # Address of the authority to issue token.
        [Parameter(Mandatory=$false)]
        [uri] $Authority,
        # Sets Extra Query Parameters for the query string in the HTTP authentication request.
        [Parameter(Mandatory=$false)]
        [hashtable] $ExtraQueryParameters,
        # Allows usage of experimental features and APIs.
        [Parameter(Mandatory=$false)]
        [switch] $EnableExperimentalFeatures,
        # Add TokenCache to list of  PowerShell sessions.
        [Parameter(Mandatory=$false)]
        [switch] $AddTokenCacheToModuleCache,
        # Read and save encrypted TokenCache for persistance across PowerShell sessions.
        [Parameter(Mandatory=$false)]
        [switch] $UseTokenCacheOnDisk,
        # Public client application options
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient-InputObject', Position=0, ValueFromPipeline=$true)]
        [Microsoft.Identity.Client.PublicClientApplicationOptions] $PublicClientOptions,
        # Confidential client application options
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClient-InputObject', Position=0, ValueFromPipeline=$true)]
        [Microsoft.Identity.Client.ConfidentialClientApplicationOptions] $ConfidentialClientOptions
    )

    switch -Wildcard ($PSCmdlet.ParameterSetName) {
        "PublicClient*" {
            if ($PublicClientOptions) {
                $ClientApplicationBuilder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::CreateWithApplicationOptions($PublicClientOptions)
            }
            else {
                $ClientApplicationBuilder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($ClientId)
            }

            if ($RedirectUri) { [void] $ClientApplicationBuilder.WithRedirectUri($RedirectUri.AbsoluteUri) }
            elseif (!$PublicClientOptions -or !$PublicClientOptions.RedirectUri) { [void] $ClientApplicationBuilder.WithDefaultRedirectUri() }

            $ClientOptions = $PublicClientOptions
        }
        "ConfidentialClient*" {
            if ($ConfidentialClientOptions) {
                $ClientApplicationBuilder = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::CreateWithApplicationOptions($ConfidentialClientOptions)
            }
            else {
                $ClientApplicationBuilder = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($ClientId)
            }

            if ($ClientSecret) { [void] $ClientApplicationBuilder.WithClientSecret((ConvertFrom-SecureStringAsPlainText $ClientSecret -Force)) }
            if ($ClientAssertion) { [void] $ClientApplicationBuilder.WithClientAssertion($ClientAssertion) }
            if ($ClientClaims) { [void] $ClientApplicationBuilder.WithClientClaims($ClientCertificate,(ConvertTo-Dictionary $ClientClaims -KeyType ([string]) -ValueType ([string]))) }
            elseif ($ClientCertificate) { [void] $ClientApplicationBuilder.WithCertificate($ClientCertificate) }
            if ($RedirectUri) { [void] $ClientApplicationBuilder.WithRedirectUri($RedirectUri.AbsoluteUri) }

            $ClientOptions = $ConfidentialClientOptions
        }
        "*" {
            if ($ClientId) { [void] $ClientApplicationBuilder.WithClientId($ClientId) }
            if ($TenantId) { [void] $ClientApplicationBuilder.WithTenantId($TenantId) }
            if ($Authority) { [void] $ClientApplicationBuilder.WithAuthority($Authority) }
            if (!$ClientOptions -or !($ClientOptions.ClientName -or $ClientOptions.ClientVersion)) {
                [void] $ClientApplicationBuilder.WithClientName("PowerShell $($PSVersionTable.PSEdition)")
                [void] $ClientApplicationBuilder.WithClientVersion($PSVersionTable.PSVersion)
            }
            if ($ExtraQueryParameters) { [void] $ClientApplicationBuilder.WithExtraQueryParameters((ConvertTo-Dictionary $ExtraQueryParameters -KeyType ([string]) -ValueType ([string]))) }
            if ($PSBoundParameters.ContainsKey('EnableExperimentalFeatures')) { [void] $ClientApplicationBuilder.WithExperimentalFeatures($EnableExperimentalFeatures) }
            #[void] $ClientApplicationBuilder.WithLogging($null, [Microsoft.Identity.Client.LogLevel]::Verbose, $false, $true)

            $ClientApplication = $ClientApplicationBuilder.Build()
            break
        }
    }

    ## Enable custom serialization of TokenCache to disk
    if ($UseTokenCacheOnDisk) {
        if ([System.Environment]::OSVersion.Platform -eq 'Win32NT' -and $PSVersionTable.PSVersion -lt [version]'6.0') {
            if ($ClientApplicationBuilder -is [Microsoft.Identity.Client.ConfidentialClientApplication]) {
                [TokenCacheHelper]::EnableSerialization($ClientApplication.AppTokenCache)
            }
            [TokenCacheHelper]::EnableSerialization($ClientApplication.UserTokenCache)
        }
        else {
            Write-Warning 'The -UseTokenCacheOnDisk parameter only works on Windows platform using Windows PowerShell. The token cache will stored in memory and not persisted on disk.'
        }
    }

    return $ClientApplication
}
