function Get-MsalAccount {
    param
    (
        #
        [parameter(Mandatory = $true, ParameterSetName = 'ClientApplication')]
        [Microsoft.Identity.Client.IClientApplicationBase] $ClientApplication,
        # Information of a single account.
        [parameter(Mandatory = $true, ParameterSetName = 'Accounts')]
        [Microsoft.Identity.Client.IAccount[]] $Accounts,
        # The username in UserPrincipalName (UPN) format.
        [parameter(Mandatory = $false)]
        [string] $Username
    )

    if ($PSCmdlet.ParameterSetName -eq 'ClientApplication') {
        [Microsoft.Identity.Client.IAccount[]] $Accounts = $ClientApplication.GetAccountsAsync().GetAwaiter().GetResult()
    }

    if ($Username) {
        return $Accounts | Where-Object Username -eq $Username
    }
    else {
        return $Accounts
    }
}
