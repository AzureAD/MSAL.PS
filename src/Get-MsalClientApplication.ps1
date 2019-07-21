
## Global Variables
[System.Collections.Generic.List[Microsoft.Identity.Client.IPublicClientApplication]] $PublicClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IPublicClientApplication]'
[System.Collections.Generic.List[Microsoft.Identity.Client.IConfidentialClientApplication]] $ConfidentialClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IConfidentialClientApplication]'

function Get-MsalClientApplication {
    [CmdletBinding(DefaultParameterSetName = 'PublicClient')]
    param
    (
        # Client application options
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'InputObject', Position = 1)]
        [object] $InputObject,
        # Identifier of the client requesting the token.
        [parameter(Mandatory = $false, ParameterSetName = "InputObject")]
        [parameter(Mandatory = $true, ParameterSetName = "PublicClient")]
        [parameter(Mandatory = $true, ParameterSetName = "ConfidentialClientSecret")]
        [parameter(Mandatory = $true, ParameterSetName = "ConfidentialClientCertificate")]
        [string] $ClientId,
        # Secure secret of the client requesting the token.
        [parameter(Mandatory = $false, ParameterSetName = "InputObject")]
        [parameter(Mandatory = $true, ParameterSetName = "ConfidentialClientSecret")]
        [securestring] $ClientSecret,
        # Client assertion certificate of the client requesting the token.
        [parameter(Mandatory = $false, ParameterSetName = "InputObject")]
        [parameter(Mandatory = $true, ParameterSetName = "ConfidentialClientCertificate")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate,
        # Address to return to upon receiving a response from the authority.
        [parameter(Mandatory = $false)]
        [uri] $RedirectUri,
        # Tenant identifier of the authority to issue token.
        [parameter(Mandatory = $false)]
        [string] $TenantId,
        # Address of the authority to issue token.
        [parameter(Mandatory = $false)]
        [uri] $Authority
    )

    ## Initialization
    switch ($PSCmdlet.ParameterSetName) {
        "InputObject" {
            ## InputObject Casting
            if ($InputObject -is [Microsoft.Identity.Client.PublicClientApplicationOptions]) {
                [Microsoft.Identity.Client.PublicClientApplicationOptions] $ApplicationOptions = $InputObject
            }
            elseif ($InputObject -is [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]) {
                [Microsoft.Identity.Client.ConfidentialClientApplicationOptions] $ApplicationOptions = $InputObject
            }
            elseif ($InputObject -is [hashtable]) {
                if ($InputObject.ContainsKey('ClientSecret') -or $ClientSecret -or $ClientCertificate) {
                    [Microsoft.Identity.Client.ConfidentialClientApplicationOptions] $ApplicationOptions = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property $InputObject
                }
                else {
                    [Microsoft.Identity.Client.PublicClientApplicationOptions] $ApplicationOptions = New-Object Microsoft.Identity.Client.PublicClientApplicationOptions -Property $InputObject
                }
            }
            elseif ($InputObject -is [pscredential]) {
                [Microsoft.Identity.Client.ConfidentialClientApplicationOptions] $ApplicationOptions = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{
                    ClientId     = $InputObject.UserName
                    ClientSecret = ConvertFrom-SecureStringAsPlainText $InputObject.Password
                }
            }
            elseif ($InputObject -is [string]) {
                if ($ClientSecret -or $ClientCertificate) {
                    [Microsoft.Identity.Client.ConfidentialClientApplicationOptions] $ApplicationOptions = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{
                        ClientId = $InputObject
                    }
                }
                else {
                    [Microsoft.Identity.Client.PublicClientApplicationOptions] $ApplicationOptions = New-Object Microsoft.Identity.Client.PublicClientApplicationOptions -Property @{
                        ClientId = $InputObject
                    }
                }
            }
        }
        "PublicClient" {
            [Microsoft.Identity.Client.PublicClientApplicationOptions] $ApplicationOptions = New-Object Microsoft.Identity.Client.PublicClientApplicationOptions -Property @{
                ClientId = $ClientId
            }
        }
        "ConfidentialClientSecret" {
            [Microsoft.Identity.Client.ConfidentialClientApplicationOptions] $ApplicationOptions = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{
                ClientId     = $ClientId
                ClientSecret = (ConvertFrom-SecureStringAsPlainText $ClientSecret)
            }
        }
        "ConfidentialClientCertificate" {
            [Microsoft.Identity.Client.ConfidentialClientApplicationOptions] $ApplicationOptions = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{
                ClientId = $ClientId
                # No Client Certificate Option
            }
        }
    }

    ## Retrieve or Build Application
    if ($ApplicationOptions -is [Microsoft.Identity.Client.PublicClientApplicationOptions]) {
        [Microsoft.Identity.Client.IPublicClientApplication] $PublicClientApplication = $PublicClientApplications | Where-Object { $_.ClientId -eq $ApplicationOptions.ClientId -and (!$RedirectUri -or $_.AppConfig.RedirectUri -eq $RedirectUri) -and $_.AppConfig.TenantId -eq $TenantId } | Select-Object -First 1
        if (!$PublicClientApplication) {
            Write-Verbose ('Caching New Public Client Application [{0}]' -f $ApplicationOptions.ClientId)
            $PublicClientApplicationBuilder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::CreateWithApplicationOptions($ApplicationOptions)
            if (!$ApplicationOptions.ClientName -and !$ApplicationOptions.ClientVersion) {
                [void] $PublicClientApplicationBuilder.WithClientName("PowerShell $($PSVersionTable.PSEdition)")
                [void] $PublicClientApplicationBuilder.WithClientVersion($PSVersionTable.PSVersion)
            }
            if ($RedirectUri) { [void] $PublicClientApplicationBuilder.WithRedirectUri($RedirectUri.AbsoluteUri) }
            else { [void] $PublicClientApplicationBuilder.WithDefaultRedirectUri() }
            #if ($Authority) { [void] $PublicClientApplicationBuilder.WithAuthority($Authority) }
            if ($TenantId) { [void] $PublicClientApplicationBuilder.WithTenantId($TenantId) }
            $PublicClientApplication = $PublicClientApplicationBuilder.Build()
            $PublicClientApplications.Add($PublicClientApplication)
        }
        return $PublicClientApplication
    }
    else {
        switch ($PSCmdlet.ParameterSetName) {
            "ConfidentialClientSecret" { [Microsoft.Identity.Client.IConfidentialClientApplication] $ConfidentialClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $ApplicationOptions.ClientId -and $_.AppConfig.ClientSecret -eq (ConvertFrom-SecureStringAsPlainText $ClientSecret) -and (!$RedirectUri -or $_.AppConfig.RedirectUri -eq $RedirectUri.AbsoluteUri) -and $_.AppConfig.TenantId -eq $TenantId } | Select-Object -First 1 }
            "ConfidentialClientCertificate" { [Microsoft.Identity.Client.IConfidentialClientApplication] $ConfidentialClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $ApplicationOptions.ClientId -and $_.AppConfig.ClientCredentialCertificate -eq $ClientCertificate -and (!$RedirectUri -or $_.AppConfig.RedirectUri -eq $RedirectUri.AbsoluteUri) -and $_.AppConfig.TenantId -eq $TenantId } | Select-Object -First 1 }
            Default { [Microsoft.Identity.Client.IConfidentialClientApplication] $ConfidentialClientApplication = $ConfidentialClientApplications | Where-Object { $_.ClientId -eq $ApplicationOptions.ClientId -and (!$ClientSecret -or $_.AppConfig.ClientSecret -eq (ConvertFrom-SecureStringAsPlainText $ClientSecret)) -and (!$ClientCertificate -or $_.AppConfig.ClientCredentialCertificate -eq $ClientCertificate) -and (!$RedirectUri -or $_.AppConfig.RedirectUri -eq $RedirectUri.AbsoluteUri) -and $_.AppConfig.TenantId -eq $TenantId } | Select-Object -First 1 }
        }
        if (!$ConfidentialClientApplication) {
            Write-Verbose ('Caching New Confidential Client Application [{0}]' -f $ApplicationOptions.ClientId)
            #$ConfidentialClientApplicationBuilder = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::CreateWithApplicationOptions($ApplicationOptions) # Only works when client secret is present
            $ConfidentialClientApplicationBuilder = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($ApplicationOptions.ClientId)
            if ($ClientSecret) { [void] $ConfidentialClientApplicationBuilder.WithClientSecret((ConvertFrom-SecureStringAsPlainText $ClientSecret)) }
            if ($ClientCertificate) { [void] $ConfidentialClientApplicationBuilder.WithCertificate($ClientCertificate) }
            if (!$ApplicationOptions.ClientName -and !$ApplicationOptions.ClientVersion) {
                [void] $ConfidentialClientApplicationBuilder.WithClientName("PowerShell $($PSVersionTable.PSEdition)")
                [void] $ConfidentialClientApplicationBuilder.WithClientVersion($PSVersionTable.PSVersion)
            }
            if ($RedirectUri) { [void] $ConfidentialClientApplicationBuilder.WithRedirectUri($RedirectUri.AbsoluteUri) }
            #if ($Authority) { [void] $ConfidentialClientApplicationBuilder.WithAuthority($Authority) }
            if ($TenantId) { [void] $ConfidentialClientApplicationBuilder.WithTenantId($TenantId) }
            $ConfidentialClientApplication = $ConfidentialClientApplicationBuilder.Build()
            $ConfidentialClientApplications.Add($ConfidentialClientApplication)
        }
        return $ConfidentialClientApplication
    }
}
