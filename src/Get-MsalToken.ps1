<#
.SYNOPSIS
    Acquire a token using MSAL.NET library.
.DESCRIPTION
    This command will acquire OAuth tokens for both public and confidential clients. Public clients authentication can be interactive, integrated Windows auth, or silent (aka refresh token authentication).
.EXAMPLE
    PS C:\>Get-MsalToken -ClientId '00000000-0000-0000-0000-000000000000' -Scope 'https://graph.microsoft.com/User.Read','https://graph.microsoft.com/Files.ReadWrite'
    Get AccessToken (with MS Graph permissions User.Read and Files.ReadWrite) and IdToken using client id from application registration (public client).
.EXAMPLE
    PS C:\>Get-MsalToken -Interactive -TenantId '00000000-0000-0000-0000-000000000000' -ClientId '00000000-0000-0000-0000-000000000000' -Scope 'https://graph.microsoft.com/User.Read' -LoginHint user@domain.com
    Force interactive authentication to get AccessToken (with MS Graph permissions User.Read) and IdToken for specific Azure AD tenant and UPN using client id from application registration (public client).
.EXAMPLE
    PS C:\>Get-MsalToken -TenantId '00000000-0000-0000-0000-000000000000' -ClientId '00000000-0000-0000-0000-000000000000' -ClientSecret (ConvertTo-SecureString 'SuperSecretString' -AsPlainText -Force) -Scope 'https://graph.microsoft.com/.default'
    Get AccessToken (with MS Graph permissions User.Read) and IdToken for specific Azure AD tenant using client id and secret from application registration (confidential client).
#>
function Get-MsalToken {
    [CmdletBinding(DefaultParameterSetName = 'PublicClient')]
    [OutputType([Microsoft.Identity.Client.AuthenticationResult])]
    param
    (
        # Interactive request to acquire a token for the specified scopes.
        [parameter(Mandatory = $true, ParameterSetName = 'PublicClient-Interactive')]
        [switch] $Interactive,

        # Non-interactive request to acquire a security token for the signed-in user in Windows, via Integrated Windows Authentication.
        [parameter(Mandatory = $true, ParameterSetName = 'PublicClient-IntegratedWindowsAuth')]
        [switch] $IntegratedWindowsAuth,

        # Attempts to acquire an access token from the user token cache.
        [parameter(Mandatory = $true, ParameterSetName = 'PublicClient-Silent')]
        [parameter(Mandatory = $false, ParameterSetName = 'ClientSecret-OnBehalfOf')]
        [parameter(Mandatory = $false, ParameterSetName = 'ClientCertificate-OnBehalfOf')]
        [switch] $Silent,

        # Acquires a security token on a device without a Web browser, by letting the user authenticate on another device.
        #[parameter(Mandatory = $true, ParameterSetName = 'PublicClient-DeviceCode')]
        #[switch] $DeviceCode,

        # Tenant identifier of the authority to issue token. It can also contain the value "consumers" or "organizations".
        [parameter(Mandatory = $false)]
        [string] $TenantId,

        # Address of the authority to issue token. This value overrides TenantId.
        [parameter(Mandatory = $false)]
        [string] $Authority,

        # Identifier of the client requesting the token.
        [parameter(Mandatory = $true)]
        [string] $ClientId,

        # Secure secret of the client requesting the token.
        [parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [parameter(Mandatory = $true, ParameterSetName = 'ClientSecret-AuthorizationCode')]
        [parameter(Mandatory = $true, ParameterSetName = 'ClientSecret-OnBehalfOf')]
        [securestring] $ClientSecret,

        # Client assertion certificate of the client requesting the token.
        [parameter(Mandatory = $true, ParameterSetName = 'ClientCertificate')]
        [parameter(Mandatory = $true, ParameterSetName = 'ClientCertificate-AuthorizationCode')]
        [parameter(Mandatory = $true, ParameterSetName = 'ClientCertificate-OnBehalfOf')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate,

        # The authorization code received from service authorization endpoint.
        [parameter(Mandatory = $true, ParameterSetName = 'ClientSecret-AuthorizationCode')]
        [parameter(Mandatory = $true, ParameterSetName = 'ClientCertificate-AuthorizationCode')]
        [string] $AuthorizationCode,

        # Assertion representing the user.
        [parameter(Mandatory = $true, ParameterSetName = 'ClientSecret-OnBehalfOf')]
        [parameter(Mandatory = $true, ParameterSetName = 'ClientCertificate-OnBehalfOf')]
        [string] $UserAssertion,

        # Type of the assertion representing the user.
        [parameter(Mandatory = $false, ParameterSetName = 'ClientSecret-OnBehalfOf')]
        [parameter(Mandatory = $false, ParameterSetName = 'ClientCertificate-OnBehalfOf')]
        [string] $UserAssertionType,

        # Address to return to upon receiving a response from the authority.
        [Parameter(Mandatory = $false)]
        #[Parameter(Mandatory=$false, ParameterSetName='PublicClient')]
        #[parameter(Mandatory=$false, ParameterSetName='ClientSecret-AuthorizationCode')]
        #[parameter(Mandatory=$false, ParameterSetName='ClientCertificate-AuthorizationCode')]
        [uri] $RedirectUri,

        # Array of scopes requested for resource
        [Parameter(Mandatory = $false)]
        [string[]] $Scopes = 'https://graph.microsoft.com/.default',

        # Array of scopes for which a developer can request consent upfront.
        [Parameter(Mandatory = $false, ParameterSetName = 'PublicClient')]
        [Parameter(Mandatory = $false, ParameterSetName = 'PublicClient-Interactive')]
        [string[]] $ExtraScopesToConsent,

        # Identifier of the user. Generally a UPN.
        [Parameter(Mandatory = $false, ParameterSetName = 'PublicClient')]
        [Parameter(Mandatory = $false, ParameterSetName = 'PublicClient-Interactive')]
        [Parameter(Mandatory = $false, ParameterSetName = 'PublicClient-IntegratedWindowsAuth')]
        [Parameter(Mandatory = $false, ParameterSetName = 'PublicClient-Silent')]
        [string] $LoginHint,

        # Specifies the what the interactive experience is for the user.
        [Parameter(Mandatory = $false, ParameterSetName = 'PublicClient')]
        [Parameter(Mandatory = $false, ParameterSetName = 'PublicClient-Interactive')]
        [Microsoft.Identity.Client.Prompt] $Prompt,

        # Identifier of the user with associated password.
        [Parameter(Mandatory = $true, ParameterSetName = 'PublicClient-UsernamePassword')]
        [pscredential]
        [System.Management.Automation.Credential()]
        $UserCredential,

        # Correlation id to be used in the authentication request.
        [Parameter(Mandatory = $false)]
        [guid] $CorrelationId,

        # This parameter will be appended as is to the query string in the HTTP authentication request to the authority.
        [Parameter(Mandatory = $false)]
        [string] $extraQueryParameters
    )

    switch -Wildcard ($PSCmdlet.ParameterSetName) {
        "PublicClient*" {
            [Microsoft.Identity.Client.PublicClientApplication] $PublicClientApplication = Get-MsalClientApplication -ClientId $ClientId -RedirectUri $RedirectUri -TenantId $TenantId -Authority $Authority
            break
        }
        "ClientSecret*" {
            [Microsoft.Identity.Client.IConfidentialClientApplication] $ConfidentialClientApplication = Get-MsalClientApplication -ClientId $ClientId -ClientSecret $ClientSecret -RedirectUri $RedirectUri -Authority $Authority
            break
        }
        "ClientCertificate*" {
            [Microsoft.Identity.Client.IConfidentialClientApplication] $ConfidentialClientApplication = Get-MsalClientApplication -ClientId $ClientId -ClientCertificate $ClientCertificate -RedirectUri $RedirectUri -Authority $Authority
            break
        }
    }

    [Microsoft.Identity.Client.AuthenticationResult] $AuthenticationResult = $null
    switch -Wildcard ($PSCmdlet.ParameterSetName) {
        "PublicClient" {
            try {
                $AuthenticationResult = Get-MsalToken -Silent @PSBoundParameters
            }
            catch [Microsoft.Identity.Client.MsalUiRequiredException] {
                try {
                    $AuthenticationResult = Get-MsalToken -IntegratedWindowsAuth @PSBoundParameters
                }
                catch {
                    $AuthenticationResult = Get-MsalToken -Interactive @PSBoundParameters
                }
            }
            break
        }
        "PublicClient-Interactive" {
            $AquireTokenParameters = $PublicClientApplication.AcquireTokenInteractive($Scopes)
            #if ($Account) { [void] $AquireTokenParameters.WithAccount($Account) }
            if ($Authority) { [void] $AquireTokenParameters.WithAuthority($Authority) }
            if ($CorrelationId) { [void] $AquireTokenParameters.WithCorrelationId($CorrelationId) }
            if ($extraQueryParameters) { [void] $AquireTokenParameters.WithExtraQueryParameters($extraQueryParameters) }
            if ($extraScopesToConsent) { [void] $AquireTokenParameters.WithExtraScopesToConsent($extraScopesToConsent) }
            if ($LoginHint) { [void] $AquireTokenParameters.WithLoginHint($LoginHint) }
            if ($Prompt) { [void] $AquireTokenParameters.WithPrompt($Prompt) }
            $AuthenticationResult = $AquireTokenParameters.ExecuteAsync().GetAwaiter().GetResult()
            break
        }
        "PublicClient-IntegratedWindowsAuth" {
            $AquireTokenParameters = $PublicClientApplication.AcquireTokenByIntegratedWindowsAuth($Scopes)
            if ($Authority) { [void] $AquireTokenParameters.WithAuthority($Authority) }
            if ($CorrelationId) { [void] $AquireTokenParameters.WithCorrelationId($CorrelationId) }
            if ($extraQueryParameters) { [void] $AquireTokenParameters.WithExtraQueryParameters($extraQueryParameters) }
            if ($LoginHint) { [void] $AquireTokenParameters.WithUsername($LoginHint) }
            $AuthenticationResult = $AquireTokenParameters.ExecuteAsync().GetAwaiter().GetResult()
            break
        }
        "PublicClient-Silent" {
            if ($LoginHint) {
                $AquireTokenParameters = $PublicClientApplication.AcquireTokenSilent($Scopes, $LoginHint)
            }
            else {
                [Microsoft.Identity.Client.IAccount[]] $Accounts = $PublicClientApplication.GetAccountsAsync().GetAwaiter().GetResult()
                if ($Accounts.Count) {
                    $AquireTokenParameters = $PublicClientApplication.AcquireTokenSilent($Scopes, $Accounts[0])
                }
                else { throw (New-Object Microsoft.Identity.Client.MsalUiRequiredException -ArgumentList 0, "No account was found in the token cache.") } # ToDo: Revisit proper creation of exception
            }
            if ($Authority) { [void] $AquireTokenParameters.WithAuthority($Authority) }
            if ($CorrelationId) { [void] $AquireTokenParameters.WithCorrelationId($CorrelationId) }
            if ($extraQueryParameters) { [void] $AquireTokenParameters.WithExtraQueryParameters($extraQueryParameters) }
            $AuthenticationResult = $AquireTokenParameters.ExecuteAsync().GetAwaiter().GetResult()
            break
        }
        "PublicClient-UsernamePassword" {
            $AquireTokenParameters = $PublicClientApplication.AcquireTokenByUsernamePassword($Scopes, $UserCredential.UserName, $UserCredential.Password)
            if ($Authority) { [void] $AquireTokenParameters.WithAuthority($Authority) }
            if ($CorrelationId) { [void] $AquireTokenParameters.WithCorrelationId($CorrelationId) }
            if ($extraQueryParameters) { [void] $AquireTokenParameters.WithExtraQueryParameters($extraQueryParameters) }
            $AuthenticationResult = $AquireTokenParameters.ExecuteAsync().GetAwaiter().GetResult()
            break
        }
        "PublicClient-DeviceCode" {
            # ToDo: Get callback working in the right runspace
            # Some links that might be helpful:
            # https://powershell.github.io/Polaris/docs/api/New-ScriptblockCallback.html
            # https://github.com/PowerShell/Polaris/blob/master/Public/New-ScriptblockCallback.ps1

            $deviceCodeResultCallback = [System.Func[Microsoft.Identity.Client.DeviceCodeResult, System.Threading.Tasks.Task]] {
                param([Microsoft.Identity.Client.DeviceCodeResult]$deviceCodeResult)
                Write-Console $deviceCodeResult.Message
                return $Task.FromResult(0)
            }

            $AquireTokenParameters = $PublicClientApplication.AcquireTokenWithDeviceCode($Scopes, $deviceCodeResultCallback) # This is not working
            if ($Authority) { [void] $AquireTokenParameters.WithAuthority($Authority) }
            if ($CorrelationId) { [void] $AquireTokenParameters.WithCorrelationId($CorrelationId) }
            if ($extraQueryParameters) { [void] $AquireTokenParameters.WithExtraQueryParameters($extraQueryParameters) }
            $AuthenticationResult = $AquireTokenParameters.ExecuteAsync().GetAwaiter().GetResult()
            break
        }
        "ClientSecret" {
            $AquireTokenParameters = $ConfidentialClientApplication.AcquireTokenForClient($Scopes)
            if ($Authority) { [void] $AquireTokenParameters.WithAuthority($Authority) }
            if ($CorrelationId) { [void] $AquireTokenParameters.WithCorrelationId($CorrelationId) }
            if ($extraQueryParameters) { [void] $AquireTokenParameters.WithExtraQueryParameters($extraQueryParameters) }
            $AuthenticationResult = $AquireTokenParameters.ExecuteAsync().GetAwaiter().GetResult()
            break
        }
        "ClientCertificate" {
            $AquireTokenParameters = $ConfidentialClientApplication.AcquireTokenForClient($Scopes)
            if ($Authority) { [void] $AquireTokenParameters.WithAuthority($Authority) }
            if ($CorrelationId) { [void] $AquireTokenParameters.WithCorrelationId($CorrelationId) }
            if ($extraQueryParameters) { [void] $AquireTokenParameters.WithExtraQueryParameters($extraQueryParameters) }
            $AuthenticationResult = $AquireTokenParameters.ExecuteAsync().GetAwaiter().GetResult()
            break
        }
        "*AuthorizationCode" {
            $AquireTokenParameters = $ConfidentialClientApplication.AcquireTokenByAuthorizationCode($Scopes, $AuthorizationCode)
            if ($Authority) { [void] $AquireTokenParameters.WithAuthority($Authority) }
            if ($CorrelationId) { [void] $AquireTokenParameters.WithCorrelationId($CorrelationId) }
            if ($extraQueryParameters) { [void] $AquireTokenParameters.WithExtraQueryParameters($extraQueryParameters) }
            $AuthenticationResult = $AquireTokenParameters.ExecuteAsync().GetAwaiter().GetResult()
            break
        }
        "*OnBehalfOf" {
            if ($UserAssertionType) { [Microsoft.Identity.Client.UserAssertion] $UserAssertionObj = New-Object Microsoft.Identity.Client.UserAssertion -ArgumentList $UserAssertion, $UserAssertionType }
            else { [Microsoft.Identity.Client.UserAssertion] $UserAssertionObj = New-Object Microsoft.Identity.Client.UserAssertion -ArgumentList $UserAssertion }
            if ($Silent) {
                $AquireTokenParameters = $ConfidentialClientApplication.AcquireTokenSilent($Scopes, $UserAssertionObj)
                if ($Authority) { [void] $AquireTokenParameters.WithAuthority($Authority) }
                if ($CorrelationId) { [void] $AquireTokenParameters.WithCorrelationId($CorrelationId) }
                if ($extraQueryParameters) { [void] $AquireTokenParameters.WithExtraQueryParameters($extraQueryParameters) }
                $AuthenticationResult = $AquireTokenParameters.ExecuteAsync().GetAwaiter().GetResult()
            }
            else {
                $AquireTokenParameters = $ConfidentialClientApplication.AcquireTokenOnBehalfOf($Scopes, $UserAssertionObj)
                if ($Authority) { [void] $AquireTokenParameters.WithAuthority($Authority) }
                if ($CorrelationId) { [void] $AquireTokenParameters.WithCorrelationId($CorrelationId) }
                if ($extraQueryParameters) { [void] $AquireTokenParameters.WithExtraQueryParameters($extraQueryParameters) }
                $AuthenticationResult = $AquireTokenParameters.ExecuteAsync().GetAwaiter().GetResult()
            }
            break
        }
    }

    return $AuthenticationResult
}
