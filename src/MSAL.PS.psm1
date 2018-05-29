Set-StrictMode -Version 2.0

## Global Variables
[Microsoft.Identity.Client.TokenCache] $TokenCache = New-Object Microsoft.Identity.Client.TokenCache
[System.Collections.Generic.Dictionary[string,Microsoft.Identity.Client.PublicClientApplication]] $PublicClientApplications = New-Object 'System.Collections.Generic.Dictionary[string,Microsoft.Identity.Client.PublicClientApplication]'
[System.Collections.Generic.Dictionary[string,Microsoft.Identity.Client.ConfidentialClientApplication]] $ConfidentialClientApplications = New-Object 'System.Collections.Generic.Dictionary[string,Microsoft.Identity.Client.ConfidentialClientApplication]'

function ConvertFrom-SecureStringAsPlainText {
    [CmdletBinding()]
    param (
        # Secure String Value
        [Parameter(Mandatory=$true)]
        [securestring] $SecureString
    )

    try
    {
        [IntPtr] $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        Write-Output ([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR))
    }
    finally
    {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

function Get-MSALClientApplication {
    [CmdletBinding(DefaultParameterSetName='PublicClient')]
    param
    (
        # Identifier of the client requesting the token.
        [parameter(Mandatory=$true)]
        [string] $ClientId,
        # Secure secret of the client requesting the token.
        [parameter(Mandatory=$true, ParameterSetName="ConfidentialClientSecret")]
        [securestring] $ClientSecret,
        # Client assertion certificate of the client requesting the token.
        [parameter(Mandatory=$true, ParameterSetName="ConfidentialClientAssertionCertificate")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientAssertionCertificate,
        # Address to return to upon receiving a response from the authority.
        [parameter(Mandatory=$false)]
        [uri] $RedirectUri,
        # Address of the authority to issue token.
        [parameter(Mandatory=$false)]
        [string] $Authority = 'https://login.microsoftonline.com/common'
    )

    if ($PSCmdlet.ParameterSetName -eq "PublicClient") {
        if (!$PublicClientApplications.ContainsKey($ClientId)) {
            $PublicClientApplications[$ClientId] = New-Object Microsoft.Identity.Client.PublicClientApplication -ArgumentList $ClientId, $Authority, $TokenCache
        }
        if ($RedirectUri) { $PublicClientApplications[$ClientId].RedirectUri = $RedirectUri }
        return $PublicClientApplications[$ClientId]
    }
    else {
        if (!$ConfidentialClientApplications.ContainsKey($ClientId)) {
            switch ($PSCmdlet.ParameterSetName)
            {
                'ConfidentialClientSecret' {
                    [Microsoft.Identity.Client.ClientCredential] $ClientCredential = New-MSALClientCredential -ClientSecret $ClientSecret
                }
                'ConfidentialClientAssertionCertificate' {
                    [Microsoft.Identity.Client.ClientCredential] $ClientCredential = New-MSALClientCredential -ClientAssertionCertificate $ClientAssertionCertificate
                }
            }
            $ConfidentialClientApplications[$ClientId] = New-Object Microsoft.Identity.Client.ConfidentialClientApplication -ArgumentList $ClientId, $Authority, $RedirectUri, $ClientCredential, $TokenCache, $TokenCache
        }
        if ($RedirectUri) { $ConfidentialClientApplications[$ClientId].RedirectUri = $RedirectUri }
        return $ConfidentialClientApplications[$ClientId]
    }
}

function Get-MSALUser {
    param
    (
        # 
        [parameter(Mandatory=$true, ParameterSetName='ClientApplication')]
        [Microsoft.Identity.Client.IClientApplicationBase] $ClientApplication,
        # Information of a single user.
        [parameter(Mandatory=$true, ParameterSetName='Users')]
        [Microsoft.Identity.Client.IUser[]] $Users,
        # The displayable value in UserPrincipalName (UPN) format.
        [parameter(Mandatory=$false)]
        [string] $DisplayableId
    )

    if ($PSCmdlet.ParameterSetName -eq 'ClientApplication') {
        [Microsoft.Identity.Client.IUser[]] $Users = $ClientApplication.Users
    }

    return $Users | where DisplayableId -eq $DisplayableId
}

function New-MSALClientCredential {
    [CmdletBinding(DefaultParameterSetName='ClientSecret')]
    param
    (
        # Secure secret or client assertion certificate of the client requesting the token.
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='InputObject', Position=1)]
        [object] $InputObject,
        # Secure secret of the client requesting the token.
        [parameter(Mandatory=$true, ParameterSetName='ClientSecret', Position=1)]
        [securestring] $ClientSecret,
        # Client assertion certificate of the client requesting the token.
        [parameter(Mandatory=$true, ParameterSetName="ClientAssertionCertificate", Position=1)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientAssertionCertificate
    )

    ## InputObject Casting
    if($InputObject -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientAssertionCertificate = $InputObject
    }
    elseif($InputObject -is [pscredential]) {
        [securestring] $ClientSecret = $InputObject.Password
    }
    elseif($InputObject -is [System.Net.NetworkCredential]) {
        [securestring] $ClientSecret = $InputObject.SecurePassword
    }
    elseif ($InputObject -is [securestring]) {
        [securestring] $ClientSecret = $InputObject
    }

    ## New ClientCredential
    if ($ClientSecret) {
        [Microsoft.Identity.Client.ClientCredential] $ClientCredential = (New-Object Microsoft.Identity.Client.ClientCredential -ArgumentList (ConvertFrom-SecureStringAsPlainText $ClientSecret))
    }
    elseif ($ClientAssertionCertificate) {
        [Microsoft.Identity.Client.ClientCredential] $ClientCredential = (New-Object Microsoft.Identity.Client.ClientCredential -ArgumentList $ClientAssertionCertificate)
    }

    return $ClientCredential
}

function Get-MSALToken {
    [CmdletBinding(DefaultParameterSetName='Implicit')]
    param
    (
        # Tenant identifier of the authority to issue token.
        [parameter(Mandatory=$false)]
        [string] $TenantId = "common",

        # Address of the authority to issue token. This value overrides TenantId.
        [parameter(Mandatory=$false)]
        [string] $Authority = "https://login.microsoftonline.com/$TenantId",

        # Identifier of the client requesting the token.
        [parameter(Mandatory=$true)]
        [string] $ClientId,

        # Secure secret of the client requesting the token.
        [parameter(Mandatory=$true, ParameterSetName='ClientSecret')]
        [parameter(Mandatory=$true, ParameterSetName='ClientSecret-AuthorizationCode')]
        [parameter(Mandatory=$true, ParameterSetName='ClientSecret-OnBehalfOf')]
        [securestring] $ClientSecret,

        # Client assertion certificate of the client requesting the token.
        [parameter(Mandatory=$true, ParameterSetName='ClientAssertionCertificate')]
        [parameter(Mandatory=$true, ParameterSetName='ClientAssertionCertificate-AuthorizationCode')]
        [parameter(Mandatory=$true, ParameterSetName='ClientAssertionCertificate-OnBehalfOf')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientAssertionCertificate,

        # The authorization code received from service authorization endpoint.
        [parameter(Mandatory=$true, ParameterSetName='ClientSecret-AuthorizationCode')]
        [parameter(Mandatory=$true, ParameterSetName='ClientAssertionCertificate-AuthorizationCode')]
        [string] $AuthorizationCode,

        # Assertion representing the user.
        [parameter(Mandatory=$true, ParameterSetName='ClientSecret-OnBehalfOf')]
        [parameter(Mandatory=$true, ParameterSetName='ClientAssertionCertificate-OnBehalfOf')]
        [string] $UserAssertion,

        # Type of the assertion representing the user.
        [parameter(Mandatory=$false, ParameterSetName='ClientSecret-OnBehalfOf')]
        [parameter(Mandatory=$false, ParameterSetName='ClientAssertionCertificate-OnBehalfOf')]
        [string] $UserAssertionType,

        # Address to return to upon receiving a response from the authority.
        [Parameter(Mandatory=$false, ParameterSetName='Implicit')]
        [parameter(Mandatory=$false, ParameterSetName='ClientSecret-AuthorizationCode')]
        [parameter(Mandatory=$false, ParameterSetName='ClientAssertionCertificate-AuthorizationCode')]
        [uri] $RedirectUri = 'urn:ietf:wg:oauth:2.0:oob',

        # Array of scopes requested for resource
        [Parameter(Mandatory=$true)]
        [string[]] $Scopes,

        # Array of scopes for which a developer can request consent upfront.
        [Parameter(Mandatory=$false, ParameterSetName='Implicit')]
        [string[]] $ExtraScopesToConsent,

        # Identifier of the user. Generally a UPN.
        [Parameter(Mandatory=$false, ParameterSetName='Implicit')]
        [string] $LoginHint,

        # Indicates how AcquireToken should prompt the user.
        [Parameter(Mandatory=$false, ParameterSetName='Implicit')]
        [Microsoft.Identity.Client.UIBehavior] $UIBehavior,

        # This parameter will be appended as is to the query string in the HTTP authentication request to the authority.
        [Parameter(Mandatory=$false, ParameterSetName='Implicit')]
        [string] $extraQueryParameters
    )    

    switch -Wildcard ($PSCmdlet.ParameterSetName)
    {
        "Implicit" {
            [Microsoft.Identity.Client.PublicClientApplication] $PublicClientApplication = Get-MSALClientApplication -ClientId $ClientId -RedirectUri $RedirectUri
            [Microsoft.Identity.Client.IUser] $User = Get-MSALUser -ClientApplication $PublicClientApplication -DisplayableId $LoginHint
            break
        }
        "ClientSecret*" {
            [Microsoft.Identity.Client.ConfidentialClientApplication] $ConfidentialClientApplication = Get-MSALClientApplication -ClientId $ClientId -ClientSecret $ClientSecret -RedirectUri $RedirectUri -Authority $Authority
            break
        }
        "ClientAssertionCertificate*" {
            [Microsoft.Identity.Client.ConfidentialClientApplication] $ConfidentialClientApplication = Get-MSALClientApplication -ClientId $ClientId -ClientAssertionCertificate $ClientAssertionCertificate -RedirectUri $RedirectUri -Authority $Authority
            break
        }
    }
    
    switch -Wildcard ($PSCmdlet.ParameterSetName)
    {
        "Implicit" {
            if ($User) {
                if ($UIBehavior) {
                    [Microsoft.Identity.Client.AuthenticationResult] $AuthenticationResult = $PublicClientApplication.AcquireTokenAsync($Scopes,$User,$UIBehavior,$extraQueryParameters,$ExtraScopesToConsent,$Authority).GetAwaiter().GetResult();
                }
                else {
                    [Microsoft.Identity.Client.AuthenticationResult] $AuthenticationResult = $PublicClientApplication.AcquireTokenSilentAsync($Scopes,$User,$Authority,$false).GetAwaiter().GetResult();
                }
            }
            else {
                if (!$UIBehavior) { $UIBehavior = [Microsoft.Identity.Client.UIBehavior]::SelectAccount }
                [Microsoft.Identity.Client.AuthenticationResult] $AuthenticationResult = $PublicClientApplication.AcquireTokenAsync($Scopes,$LoginHint,$UIBehavior,$extraQueryParameters,$ExtraScopesToConsent,$Authority).GetAwaiter().GetResult();
            }
            break
        }
        "ClientSecret" {
            [Microsoft.Identity.Client.AuthenticationResult] $AuthenticationResult = $ConfidentialClientApplication.AcquireTokenForClientAsync($Scopes).GetAwaiter().GetResult();
            break
        }
        "ClientAssertionCertificate" {
            [Microsoft.Identity.Client.AuthenticationResult] $AuthenticationResult = $ConfidentialClientApplication.AcquireTokenForClientAsync($Scopes).GetAwaiter().GetResult();
            break
        }
        "*AuthorizationCode" {
            [Microsoft.Identity.Client.AuthenticationResult] $AuthenticationResult = $ConfidentialClientApplication.AcquireTokenByAuthorizationCodeAsync($AuthorizationCode,$Scopes).GetAwaiter().GetResult();
            break
        }
        "*OnBehalfOf" {
            [Microsoft.Identity.Client.UserAssertion] $UserAssertionObj = New-Object Microsoft.Identity.Client.UserAssertion -ArgumentList $UserAssertion, $UserAssertionType
            [Microsoft.Identity.Client.AuthenticationResult] $AuthenticationResult = $ConfidentialClientApplication.AcquireTokenOnBehalfOfAsync($Scopes,$UserAssertionObj).GetAwaiter().GetResult();
            break
        }
    }

    return $AuthenticationResult
}

#function Clear-MSALTokenCache {
#    $TokenCache.Clear()
#}
