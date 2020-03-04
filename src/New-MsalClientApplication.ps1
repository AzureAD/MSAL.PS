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
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [string] $ClientId,
        # Secure secret of the client requesting the token.
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [securestring] $ClientSecret,
        # Client assertion certificate of the client requesting the token.
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate,
        # Address to return to upon receiving a response from the authority.
        [Parameter(Mandatory=$false)]
        [uri] $RedirectUri,
        # Tenant identifier of the authority to issue token.
        [Parameter(Mandatory=$false)]
        [string] $TenantId,
        # Address of the authority to issue token.
        [Parameter(Mandatory=$false)]
        [uri] $Authority,
        # Public client application options
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='PublicClient-InputObject', Position=0)]
        [Microsoft.Identity.Client.PublicClientApplicationOptions] $PublicClientOptions,
        # Confidential client application options
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ConfidentialClient-InputObject', Position=0)]
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
            elseif (!$PublicClientOptions) { [void] $ClientApplicationBuilder.WithDefaultRedirectUri() }

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
            if ($ClientCertificate) { [void] $ClientApplicationBuilder.WithCertificate($ClientCertificate) }
            if ($RedirectUri) { [void] $ClientApplicationBuilder.WithRedirectUri($RedirectUri) }

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
            $ClientApplication = $ClientApplicationBuilder.Build()
            break
        }
    }

    return $ClientApplication
}
