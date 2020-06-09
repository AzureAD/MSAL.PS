[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string] $ModulePath = "..\src\*.psd1"
)

Import-Module $ModulePath -Force

## Load Test Helper Functions
. (Join-Path $PSScriptRoot 'TestCommon.ps1')

## Perform Tests
Describe 'Enable-MsalTokenCacheOnDisk' {

    Context 'Public Client' {
        Write-Host
        It 'PublicClientApplication as Positional Parameter' {
            $Input = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create('da616bc2-4047-43c7-9e1d-3fda870e8e7b').Build()
            $Output = Enable-MsalTokenCacheOnDisk $Input -PassThru
            $Output | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplication]
            $Output.ClientId | Should -Be 'da616bc2-4047-43c7-9e1d-3fda870e8e7b'
        }

        It 'PublicClientApplication as Pipeline Input' {
            $Input = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create('da616bc2-4047-43c7-9e1d-3fda870e8e7b').Build()
            $Output = $Input | Enable-MsalTokenCacheOnDisk -PassThru
            $Output | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplication]
            $Output.ClientId | Should -Be 'da616bc2-4047-43c7-9e1d-3fda870e8e7b'
        }
    }

    Context 'Confidential Client' {
        Write-Host
        It 'ConfidentialClientApplication as Positional Parameter' {
            $Input = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create('70558b77-ccf2-4bef-9e04-e90f01c88bb1').WithClientSecret('supersecretstring').Build()
            $Output = Enable-MsalTokenCacheOnDisk $Input -PassThru
            $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
            $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
        }

        It 'ConfidentialClientApplication as Pipeline Input' {
            $Input = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create('70558b77-ccf2-4bef-9e04-e90f01c88bb1').WithClientSecret('supersecretstring').Build()
            $Output = $Input | Enable-MsalTokenCacheOnDisk -PassThru
            $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
            $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
        }
    }
}
