<#
.SYNOPSIS
    Acquire a token using MSAL.NET library.
.DESCRIPTION
    This command will acquire OAuth tokens for both public and confidential clients. Public clients authentication can be interactive, integrated Windows auth, or silent (aka refresh token authentication).
.EXAMPLE
    PS C:\>Get-MsalToken -ClientId '00000000-0000-0000-0000-000000000000' -Scope 'https://graph.microsoft.com/User.Read','https://graph.microsoft.com/Files.ReadWrite'
    Get AccessToken (with MS Graph permissions User.Read and Files.ReadWrite) and IdToken using client id from application registration (public client).
.EXAMPLE
    PS C:\>Get-MsalToken -ClientId '00000000-0000-0000-0000-000000000000' -TenantId '00000000-0000-0000-0000-000000000000' -Interactive -Scope 'https://graph.microsoft.com/User.Read' -LoginHint user@domain.com
    Force interactive authentication to get AccessToken (with MS Graph permissions User.Read) and IdToken for specific Azure AD tenant and UPN using client id from application registration (public client).
.EXAMPLE
    PS C:\>Get-MsalToken -ClientId '00000000-0000-0000-0000-000000000000' -ClientSecret (ConvertTo-SecureString 'SuperSecretString' -AsPlainText -Force) -TenantId '00000000-0000-0000-0000-000000000000' -Scope 'https://graph.microsoft.com/.default'
    Get AccessToken (with MS Graph permissions .Default) and IdToken for specific Azure AD tenant using client id and secret from application registration (confidential client).
.EXAMPLE
    PS C:\>$ClientCertificate = Get-Item Cert:\CurrentUser\My\0000000000000000000000000000000000000000
    PS C:\>$MsalClientApplication = Get-MsalClientApplication -ClientId '00000000-0000-0000-0000-000000000000' -ClientCertificate $ClientCertificate -TenantId '00000000-0000-0000-0000-000000000000'
    PS C:\>$MsalClientApplication | Get-MsalToken -Scope 'https://graph.microsoft.com/.default'
    Pipe in confidential client options object to get a confidential client application using a client certificate and target a specific tenant.
#>
function Get-MsalToken {
    [CmdletBinding(DefaultParameterSetName='PublicClient')]
    [OutputType([Microsoft.Identity.Client.AuthenticationResult])]
    param
    (
        # Identifier of the client requesting the token.
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient')]
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient-Interactive')]
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient-IntegratedWindowsAuth')]
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient-Silent')]
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient-UsernamePassword')]
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient-DeviceCode')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret-AuthorizationCode')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret-OnBehalfOf')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate-AuthorizationCode')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate-OnBehalfOf')]
        [string] $ClientId,

        # Secure secret of the client requesting the token.
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret-AuthorizationCode')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret-OnBehalfOf')]
        [securestring] $ClientSecret,

        # Client assertion certificate of the client requesting the token.
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate-AuthorizationCode')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate-OnBehalfOf')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate,

        # # Client assertion certificate of the client requesting the token.
        # [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate')]
        # [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate-AuthorizationCode')]
        # [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate-OnBehalfOf')]
        # [switch] $SendX5C,

        # The authorization code received from service authorization endpoint.
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret-AuthorizationCode')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate-AuthorizationCode')]
        [string] $AuthorizationCode,

        # Assertion representing the user.
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientSecret-OnBehalfOf')]
        [Parameter(Mandatory=$true, ParameterSetName='ConfidentialClientCertificate-OnBehalfOf')]
        [string] $UserAssertion,

        # Type of the assertion representing the user.
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientSecret-OnBehalfOf')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientCertificate-OnBehalfOf')]
        [string] $UserAssertionType,

        # Address to return to upon receiving a response from the authority.
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-Interactive')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-IntegratedWindowsAuth')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-Silent')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-UsernamePassword')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-DeviceCode')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientSecret')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientSecret-AuthorizationCode')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientSecret-OnBehalfOf')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientCertificate')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientCertificate-AuthorizationCode')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientCertificate-OnBehalfOf')]
        [uri] $RedirectUri,

        # Tenant identifier of the authority to issue token. It can also contain the value "consumers" or "organizations".
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-Interactive')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-IntegratedWindowsAuth')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-Silent')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-UsernamePassword')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-DeviceCode')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientSecret')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientSecret-AuthorizationCode')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientSecret-OnBehalfOf')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientCertificate')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientCertificate-AuthorizationCode')]
        [Parameter(Mandatory=$false, ParameterSetName='ConfidentialClientCertificate-OnBehalfOf')]
        [string] $TenantId,

        # Address of the authority to issue token.
        [Parameter(Mandatory=$false)]
        [uri] $Authority,

        # Public client application
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='PublicClient-InputObject', Position=0)]
        [Microsoft.Identity.Client.PublicClientApplication] $PublicClientApplication,

        # Confidential client application
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ConfidentialClient-InputObject', Position=1)]
        [Microsoft.Identity.Client.ConfidentialClientApplication] $ConfidentialClientApplication,

        # Interactive request to acquire a token for the specified scopes.
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient-Interactive')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        [switch] $Interactive,

        # Non-interactive request to acquire a security token for the signed-in user in Windows, via Integrated Windows Authentication.
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient-IntegratedWindowsAuth')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        [switch] $IntegratedWindowsAuth,

        # Attempts to acquire an access token from the user token cache.
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient-Silent')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        [switch] $Silent,

        # Acquires a security token on a device without a Web browser, by letting the user authenticate on another device.
        # [Parameter(Mandatory=$true, ParameterSetName='PublicClient-DeviceCode')]
        # [Parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        # [switch] $DeviceCode,

        # Array of scopes requested for resource
        [Parameter(Mandatory=$false)]
        [string[]] $Scopes = 'https://graph.microsoft.com/.default',

        # Array of scopes for which a developer can request consent upfront.
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-Interactive')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        [string[]] $ExtraScopesToConsent,

        # Identifier of the user. Generally a UPN.
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-Interactive')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-IntegratedWindowsAuth')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-Silent')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        [string] $LoginHint,

        # Specifies the what the interactive experience is for the user. To force an interactive authentication, use the -Interactive switch.
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-Interactive')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        [ArgumentCompleter({
            param ( $commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters )
            [Microsoft.Identity.Client.Prompt].DeclaredFields | Where-Object { $_.IsPublic -eq $true -and $_.IsStatic -eq $true -and $_.Name -like "$wordToComplete*" } | Select-Object -ExpandProperty Name
        })]
        [string] $Prompt,

        # Identifier of the user with associated password.
        [Parameter(Mandatory=$true, ParameterSetName='PublicClient-UsernamePassword')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        [pscredential]
        [System.Management.Automation.Credential()]
        $UserCredential,

        # Correlation id to be used in the authentication request.
        [Parameter(Mandatory=$false)]
        [guid] $CorrelationId,

        # This parameter will be appended as is to the query string in the HTTP authentication request to the authority.
        [Parameter(Mandatory=$false)]
        [string] $extraQueryParameters,

        # Ignore any access token in the user token cache and attempt to acquire new access token using the refresh token for the account if one is available.
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-Silent')]
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        [parameter(Mandatory=$false, ParameterSetName='ConfidentialClientSecret')]
        [parameter(Mandatory=$false, ParameterSetName='ConfidentialClientCertificate')]
        [parameter(Mandatory=$false, ParameterSetName='ConfidentialClient-InputObject')]
        [switch] $ForceRefresh,

        # Specifies if the public client application should used an embedded web browser or the system default browser
        [Parameter(Mandatory=$false, ParameterSetName='PublicClient')]
        [parameter(Mandatory=$false, ParameterSetName='PublicClient-Interactive')]
        [parameter(Mandatory=$false, ParameterSetName='PublicClient-InputObject')]
        [switch] $UseEmbeddedWebView
    )

    switch -Wildcard ($PSCmdlet.ParameterSetName) {
         "PublicClient-InputObject" {
            [Microsoft.Identity.Client.IPublicClientApplication] $ClientApplication = $PublicClientApplication
            break
         }
         "ConfidentialClient-InputObject" {
            [Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplication
            break
         }
        "PublicClient*" {
            [Microsoft.Identity.Client.IPublicClientApplication] $PublicClientApplication = Get-MsalClientApplication -ClientId $ClientId -RedirectUri $RedirectUri -TenantId $TenantId -Authority $Authority -CreateIfMissing
            [Microsoft.Identity.Client.IPublicClientApplication] $ClientApplication = $PublicClientApplication
            break
        }
        "ConfidentialClientSecret*" {
            [Microsoft.Identity.Client.IConfidentialClientApplication] $ConfidentialClientApplication = Get-MsalClientApplication -ClientId $ClientId -ClientSecret $ClientSecret -RedirectUri $RedirectUri -TenantId $TenantId -Authority $Authority -CreateIfMissing
            [Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplication
            break
        }
        "ConfidentialClientCertificate*" {
            [Microsoft.Identity.Client.IConfidentialClientApplication] $ConfidentialClientApplication = Get-MsalClientApplication -ClientId $ClientId -ClientCertificate $ClientCertificate -RedirectUri $RedirectUri -TenantId $TenantId -Authority $Authority -CreateIfMissing
            [Microsoft.Identity.Client.IConfidentialClientApplication] $ClientApplication = $ConfidentialClientApplication
            break
        }
    }

    [Microsoft.Identity.Client.AuthenticationResult] $AuthenticationResult = $null
    switch -Wildcard ($PSCmdlet.ParameterSetName) {
        "PublicClient*" {
            if ($PSBoundParameters.ContainsKey("UserCredential") -and $UserCredential) {
                $AquireTokenParameters = $PublicClientApplication.AcquireTokenByUsernamePassword($Scopes, $UserCredential.UserName, $UserCredential.Password)
            }
            elseif ($PSBoundParameters.ContainsKey("DeviceCode") -and $DeviceCode) {
                # ToDo: Get callback working in the right runspace
                # Some links that might be helpful:
                # https://powershell.github.io/Polaris/docs/api/New-ScriptblockCallback.html
                # https://github.com/PowerShell/Polaris/blob/master/Public/New-ScriptblockCallback.ps1
                # https://stackoverflow.com/questions/49737016/powershell-runspace-delegates

                [System.Func[Microsoft.Identity.Client.DeviceCodeResult, System.Threading.Tasks.Task]] $deviceCodeResultCallback = {
                    param([Microsoft.Identity.Client.DeviceCodeResult]$deviceCodeResult)
                    Write-Console $deviceCodeResult.Message
                    return [System.Threading.Tasks.Task]::FromResult(0)
                }

                $AquireTokenParameters = $PublicClientApplication.AcquireTokenWithDeviceCode($Scopes, $deviceCodeResultCallback) # This is not working. No Runspace error.
            }
            elseif ($PSBoundParameters.ContainsKey("Interactive") -and $Interactive) {
                $AquireTokenParameters = $PublicClientApplication.AcquireTokenInteractive($Scopes)
                [IntPtr] $ParentWindow = [System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle
                if ($ParentWindow) { [void] $AquireTokenParameters.WithParentActivityOrWindow($ParentWindow) }
                #if ($Account) { [void] $AquireTokenParameters.WithAccount($Account) }
                if ($extraScopesToConsent) { [void] $AquireTokenParameters.WithExtraScopesToConsent($extraScopesToConsent) }
                if ($LoginHint) { [void] $AquireTokenParameters.WithLoginHint($LoginHint) }
                if ($Prompt) { [void] $AquireTokenParameters.WithPrompt([Microsoft.Identity.Client.Prompt]::$Prompt) }
                if ($PSBoundParameters.ContainsKey('UseEmbeddedWebView')) { [void] $AquireTokenParameters.WithUseEmbeddedWebView($UseEmbeddedWebView) }
            }
            elseif ($PSBoundParameters.ContainsKey("IntegratedWindowsAuth") -and $IntegratedWindowsAuth) {
                $AquireTokenParameters = $PublicClientApplication.AcquireTokenByIntegratedWindowsAuth($Scopes)
                if ($LoginHint) { [void] $AquireTokenParameters.WithUsername($LoginHint) }
            }
            elseif ($PSBoundParameters.ContainsKey("Silent") -and $Silent) {
                if ($LoginHint) {
                    $AquireTokenParameters = $PublicClientApplication.AcquireTokenSilent($Scopes, $LoginHint)
                    if ($ForceRefresh) { [void] $AquireTokenParameters.WithForceRefresh($ForceRefresh) }
                }
                else {
                    [Microsoft.Identity.Client.IAccount[]] $Accounts = $PublicClientApplication.GetAccountsAsync().GetAwaiter().GetResult()
                    if ($Accounts.Count) {
                        $AquireTokenParameters = $PublicClientApplication.AcquireTokenSilent($Scopes, $Accounts[0])
                        if ($ForceRefresh) { [void] $AquireTokenParameters.WithForceRefresh($ForceRefresh) }
                    }
                    else { throw (New-Object Microsoft.Identity.Client.MsalUiRequiredException -ArgumentList 0, "No account was found in the token cache.") } # ToDo: Revisit proper creation of exception
                }
            }
            else {
                try {
                    $paramGetMsalTokenSilent = Select-PsBoundParameters -NamedParameter $PSBoundParameters -CommandName 'Get-MsalToken' -CommandParameterSet 'PublicClient-Silent','PublicClient-InputObject' -ExcludeParameters 'Silent','Prompt','UseEmbeddedWebView'
                    $AuthenticationResult = Get-MsalToken -Silent @paramGetMsalTokenSilent
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
        }
        "ConfidentialClient*" {
            if ($PSBoundParameters.ContainsKey("AuthorizationCode")) {
                $AquireTokenParameters = $ConfidentialClientApplication.AcquireTokenByAuthorizationCode($Scopes, $AuthorizationCode)
            }
            elseif ($PSBoundParameters.ContainsKey("UserAssertion")) {
                if ($UserAssertionType) { [Microsoft.Identity.Client.UserAssertion] $UserAssertionObj = New-Object Microsoft.Identity.Client.UserAssertion -ArgumentList $UserAssertion, $UserAssertionType }
                else { [Microsoft.Identity.Client.UserAssertion] $UserAssertionObj = New-Object Microsoft.Identity.Client.UserAssertion -ArgumentList $UserAssertion }
                $AquireTokenParameters = $ConfidentialClientApplication.AcquireTokenOnBehalfOf($Scopes, $UserAssertionObj)
            }
            else {
                $AquireTokenParameters = $ConfidentialClientApplication.AcquireTokenForClient($Scopes)
                #if ($SendX5C) { [void] $AquireTokenParameters.WithSendX5C($SendX5C) }
                if ($ForceRefresh) { [void] $AquireTokenParameters.WithForceRefresh($ForceRefresh) }
            }
        }
        "*" {
            if ($Authority) { [void] $AquireTokenParameters.WithAuthority($Authority.AbsoluteUri) }
            if ($CorrelationId) { [void] $AquireTokenParameters.WithCorrelationId($CorrelationId) }
            if ($extraQueryParameters) { [void] $AquireTokenParameters.WithExtraQueryParameters($extraQueryParameters) }
            Write-Verbose ('Aquiring Token for Application with ClientId [{0}]' -f $ClientApplication.ClientId)
            $AuthenticationResult = $AquireTokenParameters.ExecuteAsync().GetAwaiter().GetResult()
            break
        }
    }

    return $AuthenticationResult
}
