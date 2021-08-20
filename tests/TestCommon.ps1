
<#
.SYNOPSIS
    Convert Byte Array or Plain Text String to Base64 String.
.EXAMPLE
    PS C:\>ConvertTo-Base64String "A string with base64 encoding"
    Convert String with Default Encoding to Base64 String.
.EXAMPLE
    PS C:\>"ASCII string with base64url encoding" | ConvertTo-Base64String -Base64Url -Encoding Ascii
    Convert String with Ascii Encoding to Base64Url String.
.EXAMPLE
    PS C:\>ConvertTo-Base64String ([guid]::NewGuid())
    Convert GUID to Base64 String.
.INPUTS
    System.Object
#>
function ConvertTo-Base64String {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # Value to convert
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [object] $InputObjects,
        # Use base64url variant
        [Parameter (Mandatory = $false)]
        [switch] $Base64Url,
        # Output encoding to use for text strings
        [Parameter (Mandatory = $false)]
        [ValidateSet('Ascii', 'UTF32', 'UTF7', 'UTF8', 'BigEndianUnicode', 'Unicode')]
        [string] $Encoding = 'Default'
    )

    begin {
        function Transform ([byte[]]$InputBytes) {
            [string] $outBase64String = [System.Convert]::ToBase64String($InputBytes)
            if ($Base64Url) { $outBase64String = $outBase64String.Replace('+', '-').Replace('/', '_').Replace('=', '') }
            return $outBase64String
        }

        ## Create list to capture byte stream from piped input.
        [System.Collections.Generic.List[byte]] $listBytes = New-Object System.Collections.Generic.List[byte]
    }

    process {
        if ($InputObjects -is [byte[]]) {
            Write-Output (Transform $InputObjects)
        }
        else {
            foreach ($InputObject in $InputObjects) {
                [byte[]] $InputBytes = $null
                if ($InputObject -is [byte]) {
                    ## Populate list with byte stream from piped input.
                    if ($listBytes.Count -eq 0) {
                        Write-Verbose 'Creating byte array from byte stream.'
                        Write-Warning ('For better performance when piping a single byte array, use "Write-Output $byteArray -NoEnumerate | {0}".' -f $MyInvocation.MyCommand)
                    }
                    $listBytes.Add($InputObject)
                }
                elseif ($InputObject -is [byte[]]) {
                    $InputBytes = $InputObject
                }
                elseif ($InputObject -is [string]) {
                    $InputBytes = [Text.Encoding]::$Encoding.GetBytes($InputObject)
                }
                elseif ($InputObject -is [bool] -or $InputObject -is [char] -or $InputObject -is [single] -or $InputObject -is [double] -or $InputObject -is [int16] -or $InputObject -is [int32] -or $InputObject -is [int64] -or $InputObject -is [uint16] -or $InputObject -is [uint32] -or $InputObject -is [uint64]) {
                    $InputBytes = [System.BitConverter]::GetBytes($InputObject)
                }
                elseif ($InputObject -is [guid]) {
                    $InputBytes = $InputObject.ToByteArray()
                }
                elseif ($InputObject -is [System.IO.FileSystemInfo]) {
                    if ($PSVersionTable.PSVersion -ge [version]'6.0') {
                        $InputBytes = Get-Content $InputObject.FullName -Raw -AsByteStream
                    }
                    else {
                        $InputBytes = Get-Content $InputObject.FullName -Raw -Encoding Byte
                    }
                }
                else {
                    ## Non-Terminating Error
                    $Exception = New-Object ArgumentException -ArgumentList ('Cannot convert input of type {0} to Base64 string.' -f $InputObject.GetType())
                    Write-Error -Exception $Exception -Category ([System.Management.Automation.ErrorCategory]::ParserError) -CategoryActivity $MyInvocation.MyCommand -ErrorId 'ConvertBase64StringFailureTypeNotSupported' -TargetObject $InputObject
                }

                if ($null -ne $InputBytes -and $InputBytes.Count -gt 0) {
                    Write-Output (Transform $InputBytes)
                }
            }
        }
    }

    end {
        ## Output captured byte stream from piped input.
        if ($listBytes.Count -gt 0) {
            Write-Output (Transform $listBytes.ToArray())
        }
    }
}

<#
.SYNOPSIS
    Convert/Decrypt SecureString to Plain Text String.
.EXAMPLE
    PS C:\>ConvertFrom-SecureStringAsPlainText (ConvertTo-SecureString 'SuperSecretString' -AsPlainText -Force) -Force
    Convert plain text to SecureString and then convert it back.
.INPUTS
    System.Security.SecureString
#>
function ConvertFrom-SecureStringAsPlainText {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # Secure String Value
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [securestring] $SecureString,
        # Confirms that you understand the implications of using the AsPlainText parameter and still want to use it.
        [Parameter(Mandatory = $true, Position = 1)]
        [switch] $Force
    )

    try {
        [IntPtr] $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        Write-Output ([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR))
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

<#
.SYNOPSIS
    Remove sensitive data from object or string.
.EXAMPLE
    PS C:\>$MyString = 'My password is: "SuperSecretString"'
    PS C:\>Remove-SensitiveData ([ref]$MyString) -FilterValues "Super","String"
    This removes the word "Super" and "String" from the input string with no output.
.EXAMPLE
    PS C:\>Remove-SensitiveData 'My password is: "SuperSecretString"' -FilterValues "Super","String" -PassThru
    This removes the word "Super" and "String" from the input string and return the result.
.INPUTS
    System.Object
#>
function Remove-SensitiveData {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        # Object from which to remove sensitive data.
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [object] $InputObjects,
        # Sensitive string values to remove from input object.
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string[]] $FilterValues,
        # Replacement value for senstive data.
        [Parameter(Mandatory = $false)]
        [string] $ReplacementValue = '********',
        # Copy the input object rather than remove data directly from input.
        [Parameter(Mandatory = $false)]
        [switch] $Clone,
        # Output object with sensitive data removed.
        [Parameter(Mandatory = $false)]
        [switch] $PassThru
    )

    process {
        if ($InputObjects.GetType().FullName.StartsWith('System.Management.Automation.PSReference')) {
            if ($Clone) { $OutputObjects = $InputObjects.Value.Clone() }
            else { $OutputObjects = $InputObjects }
        }
        else {
            if ($Clone) { $OutputObjects = [ref]$InputObjects.Clone() }
            else {
                if ($InputObjects -is [System.ValueType] -or $InputObjects -is [string]) { Write-Warning ('The input of type [{0}] was not passed by reference. Senstive data will not be removed from the original input.' -f $InputObjects.GetType()) }
                $OutputObjects = [ref]$InputObjects
            }
        }

        if ($OutputObjects.Value -is [string]) {
            foreach ($FilterValue in $FilterValues) {
                if ($OutputObjects.Value -and $FilterValue) { $OutputObjects.Value = $OutputObjects.Value.Replace($FilterValue, $ReplacementValue) }
            }
        }
        elseif ($OutputObjects.Value -is [array] -or $OutputObjects.Value -is [System.Collections.ArrayList] -or $OutputObjects.Value.GetType().FullName.StartsWith('System.Collections.Generic.List')) {
            for ($ii = 0; $ii -lt $OutputObjects.Value.Count; $ii++) {
                if ($null -ne $OutputObjects.Value[$ii] -and $OutputObjects.Value[$ii] -isnot [ValueType]) {
                    $OutputObjects.Value[$ii] = Remove-SensitiveData ([ref]$OutputObjects.Value[$ii]) -FilterValues $FilterValues -PassThru
                }
            }
        }
        elseif ($OutputObjects.Value -is [hashtable] -or $OutputObjects.Value -is [System.Collections.Specialized.OrderedDictionary] -or $OutputObjects.Value.GetType().FullName.StartsWith('System.Collections.Generic.Dictionary')) {
            [array] $KeyNames = $OutputObjects.Value.Keys
            for ($ii = 0; $ii -lt $KeyNames.Count; $ii++) {
                if ($null -ne $OutputObjects.Value[$KeyNames[$ii]] -and $OutputObjects.Value[$KeyNames[$ii]] -isnot [ValueType]) {
                    $OutputObjects.Value[$KeyNames[$ii]] = Remove-SensitiveData ([ref]$OutputObjects.Value[$KeyNames[$ii]]) -FilterValues $FilterValues -PassThru
                }
            }
        }
        elseif ($OutputObjects.Value -is [object] -and $OutputObjects.Value -isnot [ValueType]) {
            [array] $PropertyNames = $OutputObjects.Value | Get-Member -MemberType Property, NoteProperty
            for ($ii = 0; $ii -lt $PropertyNames.Count; $ii++) {
                $PropertyName = $PropertyNames[$ii].Name
                if ($null -ne $OutputObjects.Value.$PropertyName -and $OutputObjects.Value.$PropertyName -isnot [ValueType]) {
                    $OutputObjects.Value.$PropertyName = Remove-SensitiveData ([ref]$OutputObjects.Value.$PropertyName) -FilterValues $FilterValues -PassThru
                }
            }
        }
        else {
            ## Non-Terminating Error
            $Exception = New-Object ArgumentException -ArgumentList ('Cannot remove senstive data from input of type {0}.' -f $OutputObjects.Value.GetType())
            Write-Error -Exception $Exception -Category ([System.Management.Automation.ErrorCategory]::ParserError) -CategoryActivity $MyInvocation.MyCommand -ErrorId 'RemoveSensitiveDataFailureTypeNotSupported' -TargetObject $OutputObjects.Value
            continue
        }

        if ($PassThru -or $Clone) {
            ## Return the object with sensitive data removed.
            if ($OutputObjects.Value -is [array] -or $OutputObjects.Value -is [System.Collections.ArrayList] -or $OutputObjects.Value.GetType().FullName.StartsWith('System.Collections.Generic.List')) {
                Write-Output $OutputObjects.Value -NoEnumerate
            }
            else {
                Write-Output $OutputObjects.Value
            }
        }
    }
}

function New-OAuthClientAssertionJwt {
    [CmdletBinding()]
    param
    (
        #
        [Parameter(Mandatory = $true)]
        [hashtable] $Payload,
        #
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate,
        #
        [Parameter(Mandatory = $false)]
        [ValidateSet('RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512')]
        [string] $Algorithm = "RS256"
    )

    $JwtHeader = ConvertTo-Json @{
        alg = $Algorithm
        kid = ConvertTo-Base64String $ClientCertificate.GetCertHash() -Base64Url
    }
    $JwtPayload = ConvertTo-Json $Payload
    $JwtData = (ConvertTo-Base64String $JwtHeader, $JwtPayload -Base64Url) -join '.'

    [Security.Cryptography.HashAlgorithmName] $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::"SHA$($Algorithm.Substring(2,3))"
    switch ($Algorithm.Substring(0, 2)) {
        'RS' {
            $RSAPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($ClientCertificate)
            [byte[]] $Signature = $RSAPrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JwtData), $HashAlgorithm, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        }
        'PS' {
            $RSAPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($ClientCertificate)
            [byte[]] $Signature = $RSAPrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JwtData), $HashAlgorithm, [Security.Cryptography.RSASignaturePadding]::Pss)
        }
        'ES' {
            $ECDsaPrivateKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($ClientCertificate)
            [byte[]] $Signature = $ECDsaPrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JwtData), $HashAlgorithm)
        }
    }
    $JwtSignature = ConvertTo-Base64String $Signature -Base64Url

    $ClientAssertion = $JwtData, $JwtSignature -join '.'
    return $ClientAssertion
}

function Get-OAuthToken {
    [CmdletBinding(DefaultParameterSetName = "ClientCredential")]
    param
    (
        #
        [Parameter(Mandatory = $true)]
        [uri] $Endpoint,
        #
        [Parameter(Mandatory = $true)]
        [string] $ClientId,
        #
        [Parameter(Mandatory = $false)]
        [uri] $RedirectUri = "urn:ietf:wg:oauth:2.0:oob",
        #
        [Parameter(Mandatory = $false)]
        [string[]] $Scope,
        #
        [Parameter(Mandatory = $false, ParameterSetName = "ClientCredential")]
        [Parameter(Mandatory = $false, ParameterSetName = "AuthorizationCode")]
        [Parameter(Mandatory = $false, ParameterSetName = "RefreshToken")]
        [Parameter(Mandatory = $false, ParameterSetName = "PasswordCredential")]
        [Parameter(Mandatory = $false)]
        [securestring] $ClientSecret,
        #
        [Parameter(Mandatory = $true, ParameterSetName = "AuthorizationCode")]
        [string] $AuthorizationCode,
        #
        [Parameter(Mandatory = $true, ParameterSetName = "RefreshToken")]
        [string] $RefreshToken,
        #
        [Parameter(Mandatory = $true, ParameterSetName = "PasswordCredential")]
        [pscredential] $UserCredential,
        #
        [Parameter(Mandatory = $false)]
        [string] $Assertion,
        #
        [Parameter(Mandatory = $false)]
        [string] $ClientAssertion,
        #
        [Parameter(Mandatory = $false)]
        [string] $ClientAssertionType,
        #
        [Parameter(Mandatory = $false)]
        [string] $CodeVerifier,
        #
        [Parameter(Mandatory = $false)]
        [string] $CodeChallenge,
        #
        [Parameter(Mandatory = $false)]
        [string] $CodeChallengeMethod,
        #
        [Parameter(Mandatory = $false)]
        [hashtable] $Parameters = @{ }
    )

    [hashtable] $PostParameters = $Parameters.Clone()
    if ($ClientId) { $PostParameters.Add('client_id', $ClientId) }
    if ($RedirectUri) { $PostParameters.Add('redirect_uri', $RedirectUri.AbsoluteUri) }
    if ($Scope) { $PostParameters.Add('scope', $Scope -join ' ') }

    [string] $GrantType = $null
    if (!$GrantType) {
        if ($PSCmdlet.ParameterSetName -eq 'AuthorizationCode') { $GrantType = 'authorization_code' }
        elseif ($PSCmdlet.ParameterSetName -eq 'RefreshToken') { $GrantType = 'refresh_token' }
        elseif ($PSCmdlet.ParameterSetName -eq 'PasswordCredential') { $GrantType = 'password' }
        elseif ($PSCmdlet.ParameterSetName -eq 'ClientCredential') { $GrantType = 'client_credentials' }
        elseif ($ClientSecret) { $GrantType = 'client_credentials' }
    }
    if ($GrantType) { $PostParameters.Add('grant_type', $GrantType) }
    if ($AuthorizationCode) { $PostParameters.Add('code', $AuthorizationCode) }
    if ($RefreshToken) { $PostParameters.Add('refresh_token', $RefreshToken) }
    if ($UserCredential) {
        $PostParameters.Add('username', $UserCredential.UserName)
        $PostParameters.Add('password', (ConvertFrom-SecureStringAsPlainText $UserCredential.Password -Force))
    }
    if ($ClientSecret) { $PostParameters.Add('client_secret', (ConvertFrom-SecureStringAsPlainText $ClientSecret -Force)) }
    if ($Assertion) { $PostParameters.Add('assertion', $Assertion) }
    if ($ClientAssertion) { $PostParameters.Add('client_assertion', $ClientAssertion) }
    if ($ClientAssertionType) { $PostParameters.Add('client_assertion_type', $ClientAssertionType) }
    if ($CodeVerifier) { $PostParameters.Add('code_verifier', $CodeVerifier) }
    if ($CodeChallenge) { $PostParameters.Add('code_challenge', $CodeChallenge) }
    if ($CodeChallengeMethod) { $PostParameters.Add('code_challenge_method', $CodeChallengeMethod) }

    $Headers = @{
        Authorization = 'Basic {0}' -f (ConvertTo-Base64String ('{0}:{1}' -f $ClientId, ''))
    }
    if ($ClientSecret) { $Headers["Authorization"] = 'Basic {0}' -f (ConvertTo-Base64String ('{0}:{1}' -f $ClientId, (ConvertFrom-SecureStringAsPlainText $ClientSecret -Force))) }

    Write-Verbose ('Invoking POST to URI [{0}]' -f $Endpoint.AbsoluteUri)
    Write-Verbose ('Headers: {0}' -f (ConvertTo-Json (Remove-SensitiveData $Headers -FilterValues $Headers['Authorization'].Substring(20) -Clone)))
    Write-Verbose ('Post Parameters: {0}' -f (ConvertTo-Json (Remove-SensitiveData $PostParameters -FilterValues $PostParameters['password'], $PostParameters['client_secret'] -Clone)))
    $TokenResponse = Invoke-RestMethod -Method Post -Uri $Endpoint.AbsoluteUri -ContentType "application/x-www-form-urlencoded" -Headers $Headers -Body $PostParameters
    if ($TokenResponse) {
        $TokenResponse | Add-Member "_issued_at" -MemberType NoteProperty -Value (Get-Date)
        if ($TokenResponse.expires_in) {
            $TokenResponse | Add-Member "_expires_on" -MemberType NoteProperty -Value $TokenResponse._issued_at.AddSeconds($TokenResponse.expires_in)
        }
        if ($TokenResponse.refresh_token) {
            $TokenResponse | Add-Member "_refresh_token" -MemberType NoteProperty -Value $TokenResponse.refresh_token
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'RefreshToken') {
            $TokenResponse | Add-Member "_refresh_token" -MemberType NoteProperty -Value $RefreshToken
        }
    }
    return $TokenResponse
}

<#
.SYNOPSIS
    Generate Client Certificate on local machine for application registration or service principal in Azure AD.
.EXAMPLE
    PS C:\>New-AzureAdClientCertificate -ApplicationName MyApp
    Generates a new client certificate for application named "MyApp".
.EXAMPLE
    PS C:\>New-AzureAdClientCertificate -ApplicationName MyApp -MakePrivateKeyExportable -Lifetime (New-TimeSpan -End (Get-Date).AddYears(3))
    Generates a new exportable client certificate valid for 3 years.
#>
function New-AzureAdClientCertificate {
    [CmdletBinding()]
    [OutputType([securestring])]
    param (
        # Name of Application.
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string] $ApplicationName,
        # Allows certificate private key to be exported from local machine.
        [Parameter(Mandatory = $false)]
        [switch] $MakePrivateKeyExportable,
        # Valid lifetime of client certificate.
        [Parameter(Mandatory = $false)]
        [timespan] $Lifetime
    )

    begin {
        ## Initialize
        [string] $KeyExportPolicy = 'NonExportable'
        if ($MakePrivateKeyExportable) { $KeyExportPolicy = 'ExportableEncrypted' }

        [datetime] $StartTime = Get-Date
        if (!$Lifetime) { $Lifetime = New-TimeSpan -End $StartTime.AddYears(1) }
        [datetime] $EndTime = $StartTime.Add($Lifetime)
    }

    process {
        if ($PSEdition -eq 'Desktop') {
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate = New-SelfSignedCertificate -Subject ('CN={0}' -f $ApplicationName) -KeyFriendlyName $ApplicationName -HashAlgorithm sha256 -KeySpec Signature -KeyLength 2048 -Type Custom -NotBefore $StartTime -NotAfter $EndTime -KeyExportPolicy $KeyExportPolicy -CertStoreLocation Cert:\CurrentUser\My
        }
        else {
            $UniqueId = New-Guid
            #. (Join-Path $PSScriptRoot makecert.exe) -r -n ('CN={0} ({1})' -f $ApplicationName,$UniqueId) -a sha256 -sky Signature -len 2048 -b $StartTime.ToString('MM/dd/yyyy') -e $EndTime.ToString('MM/dd/yyyy') -sr CurrentUser -ss My | Out-Null
            $ScriptBlock = {
                param ([string]$ApplicationName, [datetime]$StartTime, [datetime]$EndTime, [string]$KeyExportPolicy)
                [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate = New-SelfSignedCertificate -Subject ('CN={0}' -f $ApplicationName) -KeyFriendlyName $ApplicationName -HashAlgorithm sha256 -KeySpec Signature -KeyLength 2048 -Type Custom -NotBefore $StartTime -NotAfter $EndTime -KeyExportPolicy $KeyExportPolicy -CertStoreLocation Cert:\CurrentUser\My
            }
            $strScriptBlock = 'Invoke-Command -ScriptBlock {{ {0} }} -ArgumentList {1}' -f $ScriptBlock, "'$ApplicationName ($UniqueId)',([datetime]'$($StartTime.ToString('O'))'),([datetime]'$($EndTime.ToString('O'))'),'$KeyExportPolicy'"
            Start-Process powershell -ArgumentList ('-NoProfile', '-EncodedCommand', [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($strScriptBlock))) -NoNewWindow -Wait
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate = Get-ChildItem -LiteralPath Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey -and $_.Subject -eq ('CN={0} ({1})' -f $ApplicationName, $UniqueId) -and $_.Issuer -eq ('CN={0} ({1})' -f $ApplicationName, $UniqueId) } | Select-Object -First 1
        }
        Write-Output $ClientCertificate
    }
}

function Get-MSGraphToken {
    [CmdletBinding()]
    param(
        # Specifies the ID of a tenant.
        [Parameter(Mandatory = $false)]
        [string] $TenantId = 'common',
        #
        [Parameter(Mandatory = $true)]
        [string] $ClientId,
        #
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate,
        #
        [Parameter(Mandatory = $false)]
        [uri] $RedirectUri = "http://localhost/"
    )

    process {
        [hashtable] $TestAutomationApp = @{
            Endpoint            = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            ClientId            = $ClientId
            ClientAssertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            ClientAssertion     = New-OAuthClientAssertionJwt -ClientCertificate $ClientCertificate -Payload @{
                aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                exp = [DateTimeOffset]::Now.AddMinutes(1).ToUnixTimeSeconds()
                iss = $ClientId
                jti = New-Guid
                nbf = [DateTimeOffset]::Now.ToUnixTimeSeconds()
                sub = $ClientId
            }
            RedirectUri         = $RedirectUri
            Scope               = 'https://graph.microsoft.com/.default'
        }
        $MSGraphToken = Get-OAuthToken @TestAutomationApp

        [hashtable] $MSGraphHeaders = @{
            Authorization = '{0} {1}' -f $MSGraphToken.token_type, $MSGraphToken.access_token
        }

        return $MSGraphToken
    }
}

function New-TestAzureAdPublicClient {
    [CmdletBinding()]
    param(
        # Specifies the display name of the application.
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string] $DisplayName = 'MSAL.PS Test Public Client',
        # Do not create a corresponding service principal.
        [Parameter(Mandatory = $false)]
        [switch] $NoServicePrincipal,
        # Automatic admin consent
        [Parameter(Mandatory = $false)]
        [switch] $AdminConsent,
        # Specifies the access token to use for Microsoft Graph.
        [Parameter(Mandatory = $true)]
        [psobject] $MSGraphToken
    )

    begin {
        [hashtable] $MSGraphHeaders = @{
            Authorization = '{0} {1}' -f $MSGraphToken.token_type, $MSGraphToken.access_token
        }
    }

    process {
        $Application = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/applications" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json -Depth 4 @{
                displayName            = $DisplayName
                signInAudience         = "AzureADMyOrg"
                isFallbackPublicClient = $true
                publicClient           = @{
                    redirectUris = @(
                        "urn:ietf:wg:oauth:2.0:oob"
                        "https://login.microsoftonline.com/common/oauth2/nativeclient"
                        "http://localhost/"
                    )
                }
                web                    = $null
                requiredResourceAccess = @(
                    @{
                        resourceAppId  = "00000003-0000-0000-c000-000000000000"
                        resourceAccess = @(
                            @{
                                id   = "14dad69e-099b-42c9-810b-d002981feec1"
                                type = "Scope"
                            }
                            @{
                                id   = "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0"
                                type = "Scope"
                            }
                            @{
                                id   = "37f7f235-527c-4136-accd-4a02d197296e"
                                type = "Scope"
                            }
                            @{
                                id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
                                type = "Scope"
                            }
                            @{
                                id   = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"
                                type = "Scope"
                            }
                        )
                    }
                )
                tags                   = @(
                    "Test"
                )
            })
        Write-Output $Application

        if (!$NoServicePrincipal) {
            $ServicePrincipal = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json -Depth 4 @{
                    appId = $Application.appId
                })
            Write-Output $ServicePrincipal

            if ($AdminConsent) {
                $spMicrosoftGraph = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'" -Headers $MSGraphHeaders
                $ServicePrincipalConsent = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/oAuth2Permissiongrants" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json -Depth 4 @{
                        clientId    = $ServicePrincipal.Id
                        consentType = 'AllPrincipals'
                        expiryTime  = (Get-Date).AddDays(1).ToString('O')
                        resourceId  = $spMicrosoftGraph.value[0].id
                        scope       = 'User.Read User.ReadBasic.All email offline_access openid profile'
                    })
            }
        }
    }
}

function New-TestAzureAdConfidentialClient {
    [CmdletBinding()]
    param(
        # Specifies the display name of the application.
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string] $DisplayName = 'MSAL.PS Test Confidential Client',
        # Do not create a corresponding service principal.
        [Parameter(Mandatory = $false)]
        [switch] $NoServicePrincipal,
        # Automatic admin consent
        [Parameter(Mandatory = $false)]
        [switch] $AdminConsent,
        # Add client apps as pre-authorized.
        [Parameter(Mandatory = $false)]
        [string[]] $PreauthorizedApps,
        # Specifies the access token to use for Microsoft Graph.
        [Parameter(Mandatory = $true)]
        [psobject] $MSGraphToken
    )

    begin {
        [hashtable] $MSGraphHeaders = @{
            Authorization = '{0} {1}' -f $MSGraphToken.token_type, $MSGraphToken.access_token
        }
    }

    process {
        $permissionId = [guid]::NewGuid()
        $Application = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/applications" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json -Depth 4 @{
                displayName            = $DisplayName
                signInAudience         = "AzureADMyOrg"
                isFallbackPublicClient = $false
                publicClient           = $null
                web                    = @{
                    redirectUris = @(
                        "urn:ietf:wg:oauth:2.0:oob"
                        "https://login.microsoftonline.com/common/oauth2/nativeclient"
                        "http://localhost/"
                    )
                }
                requiredResourceAccess = @(
                    @{
                        resourceAppId  = "00000003-0000-0000-c000-000000000000"
                        resourceAccess = @(
                            @{
                                id   = "14dad69e-099b-42c9-810b-d002981feec1"
                                type = "Scope"
                            }
                            @{
                                id   = "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0"
                                type = "Scope"
                            }
                            @{
                                id   = "37f7f235-527c-4136-accd-4a02d197296e"
                                type = "Scope"
                            }
                            @{
                                id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
                                type = "Scope"
                            }
                            @{
                                id   = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"
                                type = "Scope"
                            }
                            @{
                                id   = "b340eb25-3456-403f-be2f-af7a0d370277"
                                type = "Scope"
                            }
                        )
                    }
                )
                api                    = @{
                    knownClientApplications = @(
                        $PreauthorizedApps
                    )
                    oauth2PermissionScopes = @(
                        @{
                            id                      = $permissionId
                            value                   = "user_impersonation"
                            type                    = "User"
                            adminConsentDescription = "Allow the application to access $DisplayName on behalf of the signed-in user."
                            adminConsentDisplayName = "Access $DisplayName"
                            userConsentDescription  = "Allow the application to access $DisplayName on your behalf."
                            userConsentDisplayName  = "Access $DisplayName"
                            isEnabled               = $true
                        }
                    )
                    preAuthorizedApplications = @(
                        foreach ($appId in $PreauthorizedApps) {
                            @{
                                appId         = $appId
                                delegatedPermissionIds = @(
                                    $permissionId
                                )
                            }
                        }
                    )
                }
                tags                   = @(
                    "Test"
                )
            })
        Write-Output $Application

        if (!$NoServicePrincipal) {
            $ServicePrincipal = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json -Depth 4 @{
                    appId = $Application.appId
                })
            Write-Output $ServicePrincipal

            if ($AdminConsent) {
                $spMicrosoftGraph = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'" -Headers $MSGraphHeaders
                $ServicePrincipalConsent = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/oAuth2Permissiongrants" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json -Depth 4 @{
                        clientId    = $ServicePrincipal.Id
                        consentType = 'AllPrincipals'
                        expiryTime  = (Get-Date).AddDays(1).ToString('O')
                        resourceId  = $spMicrosoftGraph.value[0].id
                        scope       = 'User.Read email offline_access openid profile'
                    })
            }
        }
    }
}

function Add-AzureAdClientSecret {
    [CmdletBinding()]
    [OutputType([securestring])]
    param(
        # Specifies the object id of the application or service principal.
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ObjectId')]
        [string] $Id,
        # Specifies the access token to use for Microsoft Graph.
        [Parameter(Mandatory = $true)]
        [psobject] $MSGraphToken
    )

    begin {
        [hashtable] $MSGraphHeaders = @{
            Authorization = '{0} {1}' -f $MSGraphToken.token_type, $MSGraphToken.access_token
        }
    }

    process {
        $AzureADObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$Id" -Headers $MSGraphHeaders

        switch ($AzureADObject.'@odata.type') {
            '#microsoft.graph.application' {
                $PasswordCredential = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/applications/$($AzureADObject.id)/addPassword" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json @{
                        passwordCredential = @{
                            endDateTime = (Get-Date).AddDays(1).ToString('O')
                            displayName = "MSAL.PS"
                        }
                    })
                break
            }
            '#microsoft.graph.servicePrincipal' {
                $PasswordCredential = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($AzureADObject.id)/addPassword" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json @{
                        passwordCredential = @{
                            endDateTime = (Get-Date).AddDays(1).ToString('O')
                            displayName = "MSAL.PS"
                        }
                    })
                break
            }
        }

        Write-Output $PasswordCredential
        Write-Output (ConvertTo-SecureString $PasswordCredential.secretText -AsPlainText -Force)
    }
}

function Add-AzureAdClientCertificate {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        # Specifies the object id of the application or service principal.
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ObjectId')]
        [string] $Id,
        # Specifies the access token to use for Microsoft Graph.
        [Parameter(Mandatory = $true)]
        [psobject] $MSGraphToken
    )

    begin {
        [hashtable] $MSGraphHeaders = @{
            Authorization = '{0} {1}' -f $MSGraphToken.token_type, $MSGraphToken.access_token
        }
    }

    process {
        $AzureADObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$Id" -Headers $MSGraphHeaders

        $ClientCertificate = New-AzureAdClientCertificate -ApplicationName $AzureADObject.displayName -Lifetime (New-TimeSpan -Days 1)

        switch ($AzureADObject.'@odata.type') {
            '#microsoft.graph.application' {
                Invoke-RestMethod -Method Patch -Uri "https://graph.microsoft.com/v1.0/applications/$($AzureADObject.id)" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json @{
                        keyCredentials = @(
                            $AzureADObject.keyCredentials
                            @{
                                type        = "AsymmetricX509Cert"
                                usage       = "Verify"
                                key         = ConvertTo-Base64String $ClientCertificate.GetRawCertData()
                                displayName = "MSAL.PS"
                            }
                        )
                    }) | Out-Null
                $AzureADObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/applications/$($AzureADObject.id)" -Headers $MSGraphHeaders
                break
            }
            '#microsoft.graph.servicePrincipal' {
                Invoke-RestMethod -Method Patch -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($AzureADObject.id)" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json @{
                        keyCredentials = @(
                            $AzureADObject.keyCredentials
                            @{
                                type        = "AsymmetricX509Cert"
                                usage       = "Verify"
                                key         = ConvertTo-Base64String $ClientCertificate.GetRawCertData()
                                displayName = "MSAL.PS"
                            }
                        )
                    }) | Out-Null
                $AzureADObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($AzureADObject.id)" -Headers $MSGraphHeaders
                break
            }
        }

        Write-Output ($AzureADObject.keyCredentials | Where-Object customKeyIdentifier -eq $ClientCertificate.Thumbprint)
        Write-Output $ClientCertificate
    }
}

function Remove-AzureAdClientSecret {
    [CmdletBinding()]
    [OutputType([securestring])]
    param(
        # Specifies the object id of the application or service principal.
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ObjectId')]
        [string] $Id,
        # Specifies the key id of the credential to remove.
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $KeyId,
        # Specifies the access token to use for Microsoft Graph.
        [Parameter(Mandatory = $true)]
        [psobject] $MSGraphToken
    )

    begin {
        [hashtable] $MSGraphHeaders = @{
            Authorization = '{0} {1}' -f $MSGraphToken.token_type, $MSGraphToken.access_token
        }
    }

    process {
        $AzureADObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$Id" -Headers $MSGraphHeaders

        switch ($AzureADObject.'@odata.type') {
            '#microsoft.graph.application' {
                Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/applications/$($AzureADObject.id)/removePassword" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json @{
                        keyId = $KeyId
                    })
                break
            }
            '#microsoft.graph.servicePrincipal' {
                Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($AzureADObject.id)/removePassword" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json @{
                        keyId = $KeyId
                    })
                break
            }
        }
    }
}

function Remove-AzureAdClientCertificate {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        # Specifies the object id of the application or service principal.
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ObjectId')]
        [string] $Id,
        # Specifies the key id of the credential to remove.
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $KeyId,
        # Specifies the access token to use for Microsoft Graph.
        [Parameter(Mandatory = $true)]
        [psobject] $MSGraphToken
    )

    begin {
        [hashtable] $MSGraphHeaders = @{
            Authorization = '{0} {1}' -f $MSGraphToken.token_type, $MSGraphToken.access_token
        }
    }

    process {
        $AzureADObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$Id" -Headers $MSGraphHeaders

        switch ($AzureADObject.'@odata.type') {
            '#microsoft.graph.application' {
                $KeyCredential = Invoke-RestMethod -Method Patch -Uri "https://graph.microsoft.com/v1.0/applications/$($AzureADObject.id)" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json @{
                        keyCredentials = @(
                            $AzureADObject.keyCredentials | Where-Object keyId -ne $KeyId
                        )
                    })
                break
            }
            '#microsoft.graph.servicePrincipal' {
                $KeyCredential = Invoke-RestMethod -Method Patch -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($AzureADObject.id)" -Headers $MSGraphHeaders -ContentType 'application/json' -Body (ConvertTo-Json @{
                        keyCredentials = @(
                            $AzureADObject.keyCredentials | Where-Object keyId -ne $KeyId
                        )
                    })
                break
            }
        }
    }
}

function Remove-TestAzureAdApplication {
    [CmdletBinding()]
    param(
        # Specifies the object id of the application.
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ObjectId')]
        [string] $Id,
        # Delete the application permanently.
        [Parameter(Mandatory = $false)]
        [switch] $Permanently,
        # Specifies the access token to use for Microsoft Graph.
        [Parameter(Mandatory = $true)]
        [psobject] $MSGraphToken
    )

    begin {
        [hashtable] $MSGraphHeaders = @{
            Authorization = '{0} {1}' -f $MSGraphToken.token_type, $MSGraphToken.access_token
        }
    }

    process {
        Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/v1.0/applications/$Id" -Headers $MSGraphHeaders | Out-Null
        if ($Permanently) {
            Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/v1.0/directory/deleteditems/$Id" -Headers $MSGraphHeaders | Out-Null
        }
    }
}

function AutoEnumerate ($Output) {
    if ($null -eq $Output) { }
    elseif ($Output -is [array] -or $Output -is [System.Collections.ArrayList] -or $Output.GetType().FullName.StartsWith('System.Collections.Generic.List')) { Write-Output $Output -NoEnumerate }
    else { Write-Output $Output }
}

function GetInput ([hashtable[]]$TestIO, [type]$AssertType) {
    if ($TestIO.Count -gt 1) {
        $Input = New-Object object[] $TestIO.Count
        for ($i = 0; $i -lt $TestIO.Count; $i++) {
            $Input[$i] = $TestIO[$i].Input
            if ($AssertType) { AutoEnumerate $Input[$i] | Should -BeOfType $AssertType }
        }
        Write-Output $Input -NoEnumerate
    }
    else {
        if ($AssertType) { AutoEnumerate $TestIO[0].Input | Should -BeOfType $AssertType }
        AutoEnumerate $TestIO[0].Input
    }
}

function Test-ComparisionAssertions ($Reference, $Difference, [switch]$ArrayBaseTypeMatch) {
    ## Check Type
    # if ($Reference -is [array] -or $Reference -is [System.Collections.ArrayList] -or $Reference.GetType().FullName.StartsWith('System.Collections.Generic.List')) {
    #     Write-Output $Difference -NoEnumerate | Should -BeOfType $Reference.GetType()
    # }
    # else {
    #     $Difference | Should -BeOfType $Reference.GetType()
    # }
    if ($null -ne $Reference) {
        if ($ArrayBaseTypeMatch) {
            AutoEnumerate $Difference | Should -BeOfType $Reference.GetType().BaseType
        }
        else {
            AutoEnumerate $Difference | Should -BeOfType $Reference.GetType()
        }
    }

    ## Check Content
    if ($null -eq $Reference) {
        $null -eq $Difference | Should -BeTrue
    }
    elseif ($Reference -is [array] -or $Reference -is [System.Collections.ArrayList] -or $Reference.GetType().FullName.StartsWith('System.Collections.Generic.List')) {
        $Difference | Should -HaveCount $Reference.Count
        for ($i = 0; $i -lt $Reference.Count; $i++) {
            Test-ComparisionAssertions $Reference[$i] $Difference[$i]
        }
    }
    elseif ($Reference -is [hashtable] -or $Reference -is [System.Collections.Specialized.OrderedDictionary] -or $Reference.GetType().FullName.StartsWith('System.Collections.Generic.Dictionary')) {
        $Difference.Keys | Should -HaveCount $Reference.Keys.Count
        foreach ($Item in $Reference.GetEnumerator()) {
            Test-ComparisionAssertions $Item.Value $Difference[$Item.Key]
        }
    }
    elseif ($Reference -is [xml]) {
        $Difference.OuterXml | Should -BeExactly $Reference.OuterXml
    }
    elseif ($Reference -is [psobject]) {
        $ReferenceProperty = $Reference | Get-Member -MemberType Property, NoteProperty
        $DifferenceProperty = $Difference | Get-Member -MemberType Property, NoteProperty
        $ReferenceProperty | Should -HaveCount $DifferenceProperty.Count
        for ($i = 0; $i -lt $ReferenceProperty.Count; $i++) {
            $ReferencePropertyName = $ReferenceProperty[$i].Name
            $DifferencePropertyName = $DifferenceProperty[$i].Name
            Test-ComparisionAssertions $Reference.$ReferencePropertyName $Difference.$DifferencePropertyName
        }
    }
    elseif ($Reference -is [Single] -or $Reference -is [Double]) {
        ## Depending on the random floating point number choosen, sometimes the values are slightly off?
        $Difference.ToString() | Should -BeExactly $Reference.ToString()
    }
    else {
        $Difference | Should -BeExactly $Reference
    }
}

function Test-ErrorOutput ($ErrorRecord, [switch]$SkipCategory, [switch]$SkipErrorId, [switch]$SkipTargetObject) {
    $ErrorRecord | Should -BeOfType [System.Management.Automation.ErrorRecord]
    $ErrorRecord.Exception | Should -Not -BeOfType [Microsoft.PowerShell.Commands.WriteErrorException]
    $ErrorRecord.Exception.Message | Should -Not -BeNullOrEmpty
    if ($PSVersionTable.PSVersion -ge [version]'6.0') { $ErrorRecord.CategoryInfo.Activity | Should -Not -BeExactly 'Write-Error' }
    if (!$SkipCategory) { $ErrorRecord.CategoryInfo.Category | Should -Not -BeExactly ([System.Management.Automation.ErrorCategory]::NotSpecified) }
    if (!$SkipErrorId) { $ErrorRecord.FullyQualifiedErrorId | Should -Not -BeLike ("{0}*" -f $ErrorRecord.Exception.GetType().FullName) }
    if (!$SkipTargetObject) { $ErrorRecord.TargetObject | Should -Not -BeNullOrEmpty }
}

# It 'Non-Terminating Errors' {
#     $ScriptBlock = { ([int]127),([decimal]127),([long]127) | ConvertTo-HexString -ErrorAction SilentlyContinue }
#     $ScriptBlock | Should -Not -Throw
#     $Output = Invoke-Expression $ScriptBlock.ToString() -ErrorVariable ErrorObjects
#     $ErrorObjects | Should -HaveCount 1
#     $Output | Should -HaveCount (3 - $ErrorObjects.Count)
#     foreach ($ErrorObject in $ErrorObjects) {
#         [System.Management.Automation.ErrorRecord] $ErrorRecord = $null
#         if ($ErrorObject -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord = $ErrorObject }
#         else { $ErrorRecord = $ErrorObject.ErrorRecord }

#         Test-ErrorOutput $ErrorRecord
#     }
# }

function TestGroup ([type]$TestClass, [int]$StartIndex = 0) {
    Context $TestClass.Name {
        $TestValues = New-Object $TestClass.Name -ErrorAction Stop
        $BoundParameters = $TestValues.BoundParameters

        for ($i = $StartIndex; $i -lt $TestValues.IO.Count; $i++) {
            $TestIO = $TestValues.IO[$i]

            It ('Single Input [Index:{0}] of Type [{1}] as Positional Parameter{2}' -f $i, $TestIO.Input.GetType().Name, $(if ($TestIO.Error.Count -gt 0) { ' with Error' })) {
                $Input = GetInput $TestIO -AssertType $TestValues.ExpectedInputType
                $Output = & $TestValues.CommandName $Input -ErrorAction SilentlyContinue -ErrorVariable ErrorObjects @BoundParameters
                $ErrorObjects | Should -HaveCount $TestIO.Error.Count
                AutoEnumerate $Output | Should -HaveCount (1 - $TestIO.Error.Count)
                if ($TestIO.ContainsKey('Error')) {
                    Test-ErrorOutput $ErrorObjects
                }
                else {
                    AutoEnumerate $Output | Should -BeOfType $TestIO.Output.GetType()
                    #$Output | Should -BeExactly $TestIO.Output
                    Test-ComparisionAssertions $TestIO.Output $Output
                }
            }

            It ('Single Input [Index:{0}] of Type [{1}] as Pipeline Input{2}' -f $i, $TestIO.Input.GetType().Name, $(if ($TestIO.Error.Count -gt 0) { ' with Error' })) {
                $Input = GetInput $TestIO -AssertType $TestValues.ExpectedInputType
                $Output = $Input | & $TestValues.CommandName -ErrorAction SilentlyContinue -ErrorVariable ErrorObjects @BoundParameters
                $ErrorObjects | Should -HaveCount $TestIO.Error.Count
                AutoEnumerate $Output | Should -HaveCount (1 - $TestIO.Error.Count)
                if ($TestIO.ContainsKey('Error')) {
                    Test-ErrorOutput $ErrorObjects
                }
                else {
                    AutoEnumerate $Output | Should -BeOfType $TestIO.Output.GetType()
                    #$Output | Should -BeExactly $TestIO.Output
                    Test-ComparisionAssertions $TestIO.Output $Output
                }
            }
        }

        if ($TestValues.IO.Count -gt 1) {
            $TestIO = $TestValues.IO

            It ('Multiple Inputs [Total:{0}] as Positional Parameter{1}' -f $TestIO.Count, $(if ($TestIO.Error.Count -gt 0) { ' with Error' })) {
                $Input = GetInput $TestIO -AssertType $TestValues.ExpectedInputType
                $Output = & $TestValues.CommandName $Input -ErrorAction SilentlyContinue -ErrorVariable ErrorObjects @BoundParameters
                $ErrorObjects | Should -HaveCount $TestIO.Error.Count
                $Output | Should -HaveCount ($TestIO.Count - $TestIO.Error.Count)
                [int] $iError = 0
                for ($i = 0; $i -lt $TestIO.Count; $i++) {
                    if ($TestIO[$i].ContainsKey('Error')) {
                        Test-ErrorOutput $ErrorObjects[$iError]
                        $iError++
                    }
                    else {
                        AutoEnumerate $Output[$i - $iError] | Should -BeOfType $TestIO[$i].Output.GetType()
                        #$Output[$i] | Should -BeExactly $TestIO[$i].Output
                        Test-ComparisionAssertions $TestIO[$i].Output $Output[$i - $iError]
                    }
                }
            }

            It ('Multiple Inputs [Total:{0}] as Pipeline Input{1}' -f $TestIO.Count, $(if ($TestIO.Error.Count -gt 0) { ' with Error' })) {
                $Input = GetInput $TestIO -AssertType $TestValues.ExpectedInputType
                $Output = $Input | & $TestValues.CommandName -ErrorAction SilentlyContinue -ErrorVariable ErrorObjects @BoundParameters
                $ErrorObjects | Should -HaveCount $TestIO.Error.Count
                $Output | Should -HaveCount ($TestIO.Count - $TestIO.Error.Count)
                [int] $iError = 0
                for ($i = 0; $i -lt $TestIO.Count; $i++) {
                    if ($TestIO[$i].ContainsKey('Error')) {
                        Test-ErrorOutput $ErrorObjects[$iError]
                        $iError++
                    }
                    else {
                        AutoEnumerate $Output[$i - $iError] | Should -BeOfType $TestIO[$i].Output.GetType()
                        #$Output[$i] | Should -BeExactly $TestIO[$i].Output
                        Test-ComparisionAssertions $TestIO[$i].Output $Output[$i - $iError]
                    }
                }
            }
        }
    }
}
