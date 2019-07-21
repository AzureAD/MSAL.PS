Set-StrictMode -Version 2.0

<#
.SYNOPSIS
    Convert/Decrypt SecureString to Plain Text String.
.DESCRIPTION

.EXAMPLE
    PS C:\>ConvertFrom-SecureStringAsPlainText (ConvertTo-SecureString 'SuperSecretString' -AsPlainText -Force)
    Convert plain text to SecureString and then convert it back.
.INPUTS
    System.Security.SecureString
#>
function ConvertFrom-SecureStringAsPlainText {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # Secure String Value
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [securestring] $SecureString
    )

    try {
        [IntPtr] $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        Write-Output ([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR))
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}
