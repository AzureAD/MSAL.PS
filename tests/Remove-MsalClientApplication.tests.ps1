[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string] $ModulePath = "..\src\*.psd1"
)

Import-Module $ModulePath -Force

## Load Test Helper Functions
. (Join-Path $PSScriptRoot 'TestCommon.ps1')

## Perform Tests
Describe 'Remove-MsalClientApplication' {

    Context 'Public Client' {
        Write-Host
        It 'PublicClientApplication as Positional Parameter' {
            $Input = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create('da616bc2-4047-43c7-9e1d-3fda870e8e7b').Build() | Add-MsalClientApplication -PassThru
            $Output = Remove-MsalClientApplication $Input
        }

        It 'PublicClientApplication as Pipeline Input' {
            $Input = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create('da616bc2-4047-43c7-9e1d-3fda870e8e7b').Build() | Add-MsalClientApplication -PassThru
            $Output = $Input | Remove-MsalClientApplication
        }
    }

    Context 'Confidential Client' {
        Write-Host
        It 'ConfidentialClientApplication as Positional Parameter' {
            $Input = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create('70558b77-ccf2-4bef-9e04-e90f01c88bb1').WithClientSecret('supersecretstring').Build() | Add-MsalClientApplication -PassThru
            $Output = Remove-MsalClientApplication $Input
        }

        It 'ConfidentialClientApplication as Pipeline Input' {
            $Input = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create('70558b77-ccf2-4bef-9e04-e90f01c88bb1').WithClientSecret('supersecretstring').Build() | Add-MsalClientApplication -PassThru
            $Output = $Input | Remove-MsalClientApplication
        }
    }
}
