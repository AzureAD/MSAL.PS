[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string] $ModulePath = "..\src\*.psd1"
)

Import-Module $ModulePath -Force

## Load Test Helper Functions
. (Join-Path $PSScriptRoot 'TestCommon.ps1')

## Get Test Automation Token
[hashtable] $AppConfigAutomation = @{
    ClientId          = 'ada4b466-ae54-45f8-98fc-13b22708b978'
    ClientCertificate = (Get-ChildItem Cert:\CurrentUser\My\7103A1080D8611BD2CE8A5026D148938F787B12C)
    RedirectUri       = 'http://localhost/'
    TenantId          = 'jasoth.onmicrosoft.com'
}
$MSGraphToken = Get-MSGraphToken -ErrorAction Stop @AppConfigAutomation

try {
    ## Create applications in tenant for testing.
    $appPublicClient, $spPublicClient = New-TestAzureAdPublicClient -AdminConsent -MSGraphToken $MSGraphToken
    $appConfidentialClient, $spConfidentialClient = New-TestAzureAdConfidentialClient -AdminConsent -MSGraphToken $MSGraphToken
    $appConfidentialClientSecret, $ClientSecret = $appConfidentialClient | Add-AzureAdClientSecret -MSGraphToken $MSGraphToken
    $appConfidentialClientCertificate, $ClientCertificate = $appConfidentialClient | Add-AzureAdClientCertificate -MSGraphToken $MSGraphToken
    $StartDelay = Get-Date

    ## Get Credential for ROPC flow.
    $UserCredential = Get-Credential -Message 'Enter credentials to use for the ROPC flow.'

    ## Add delay to allow time for application configuration and credentials to propogate.
    $RemainingDelay = New-Timespan -Start (Get-Date) -End $StartDelay.AddSeconds(60)
    if ($RemainingDelay.Seconds -gt 0) {
        Write-Host "`nWaiting for application configuration and credentials to propogate..."
        Start-Sleep -Seconds $RemainingDelay.Seconds
    }

    ## Perform Tests
    Describe 'Get-MsalToken' {

        Context 'Public Client' {
            Write-Host
            It 'Inline as Positional Parameter' {
                $Output = Get-MsalToken $appPublicClient.appId -TenantId $appPublicClient.publisherDomain
                $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
            }

            It 'Inline with Scope as Positional Parameter' {
                $Output = Get-MsalToken $appPublicClient.appId -TenantId $appPublicClient.publisherDomain -Scopes 'https://graph.microsoft.com/User.Read', 'https://graph.microsoft.com/User.ReadBasic.All' -Interactive
                $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
            }

            It 'Inline with Prompt as Positional Parameter' {
                $Output = Get-MsalToken $appPublicClient.appId -TenantId $appPublicClient.publisherDomain -Prompt ([Microsoft.Identity.Client.Prompt]::NoPrompt)
                $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
            }

            It 'Inline Silent as Positional Parameter' {
                $Output = Get-MsalToken $appPublicClient.appId -TenantId $appPublicClient.publisherDomain -Silent
                $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
            }

            It 'Inline Interactive as Positional Parameter' {
                $Output = Get-MsalToken $appPublicClient.appId -TenantId $appPublicClient.publisherDomain -Interactive
                $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
            }

            It 'Inline IntegratedWindowsAuth as Positional Parameter' -Skip {
                $Output = Get-MsalToken $appPublicClient.appId -TenantId $appPublicClient.publisherDomain -IntegratedWindowsAuth
                $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
            }

            It 'Inline ROPC as Positional Parameter' {
                $Output = Get-MsalToken $appPublicClient.appId -TenantId $appPublicClient.publisherDomain -UserCredential $UserCredential
                $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
            }

            Context 'Public Client from ClientApplication' {
                $ClientApplication = New-MsalClientApplication $appPublicClient.appId -TenantId $appPublicClient.publisherDomain

                It 'ClientApplication as Positional Parameter' {
                    $Output = Get-MsalToken $ClientApplication
                    $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
                }

                It 'ClientApplication as Pipeline Input' {
                    $Output = $ClientApplication | Get-MsalToken
                    $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
                }

                It 'ClientApplication with Scope as Positional Parameter' {
                    $Output = Get-MsalToken $ClientApplication -Scopes 'https://graph.microsoft.com/User.Read', 'https://graph.microsoft.com/User.ReadBasic.All'
                    $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
                }

                It 'ClientApplication with Scope as Pipeline Input' {
                    $Output = $ClientApplication | Get-MsalToken -Scopes 'https://graph.microsoft.com/User.Read', 'https://graph.microsoft.com/User.ReadBasic.All'
                    $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
                }

                It 'ClientApplication ROPC as Positional Parameter' {
                    $Output = Get-MsalToken $ClientApplication -UserCredential $UserCredential
                    $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
                }

                It 'ClientApplication ROPC as Pipeline Input' {
                    $Output = $ClientApplication | Get-MsalToken -UserCredential $UserCredential
                    $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
                }
            }
        }

        Context 'Confidential Client' {
            Write-Host
            It 'Inline ClientSecret as Positional Parameter' {
                $Output = Get-MsalToken $appConfidentialClient.appId -TenantId $appConfidentialClient.publisherDomain -ClientSecret $ClientSecret
                $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
            }

            Context 'Confidential Client from ClientApplication with ClientSecret' {
                $ClientApplication = New-MsalClientApplication $appConfidentialClient.appId -TenantId $appConfidentialClient.publisherDomain -ClientSecret $ClientSecret

                It 'ClientApplication with ClientSecret as Positional Parameter' {
                    $Output = Get-MsalToken $ClientApplication
                    $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
                }

                It 'ClientApplication with ClientSecret as Pipeline Input' {
                    $Output = $ClientApplication | Get-MsalToken
                    $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
                }
            }

            Write-Host
            It 'Inline ClientCertificate as Positional Parameter' {
                $Output = Get-MsalToken $appConfidentialClient.appId -TenantId $appConfidentialClient.publisherDomain -ClientCertificate $ClientCertificate
                $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
            }

            Context 'Confidential Client from ClientApplication with ClientCertificate' {
                $ClientApplication = New-MsalClientApplication $appConfidentialClient.appId -TenantId $appConfidentialClient.publisherDomain -ClientCertificate $ClientCertificate

                It 'ClientApplication with ClientCertificate as Positional Parameter' {
                    $Output = Get-MsalToken $ClientApplication
                    $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
                }

                It 'ClientApplication with ClientCertificate as Pipeline Input' {
                    $Output = $ClientApplication | Get-MsalToken
                    $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
                }

                It 'ClientApplication with ClientCertificate On-Behalf-Of User' {
                    $OnBehalfOfToken = Get-MsalToken $appPublicClient.appId -TenantId $appPublicClient.publisherDomain -Scopes "$($appConfidentialClient.appId)/user_impersonation"
                    $Output = Get-MsalToken $ClientApplication -Scopes 'https://graph.microsoft.com/User.Read' -UserAssertion $OnBehalfOfToken.AccessToken
                    $Output | Should -BeOfType [Microsoft.Identity.Client.AuthenticationResult]
                }
            }
        }

    }
}
finally {
    ## Remove client credentials
    #Write-Host 'Removing client credentials...'
    $ClientCertificate | Remove-Item -Force
    #$appConfidentialClient | Remove-AzureAdClientSecret -KeyId $appConfidentialClientSecret.keyId -MSGraphToken $MSGraphToken
    #$appConfidentialClient | Remove-AzureAdClientCertificate -KeyId $appConfidentialClientCertificate.keyId -MSGraphToken $MSGraphToken

    ## Remove test client applications
    $MSGraphToken = Get-MSGraphToken @AppConfigAutomation
    $appPublicClient, $appConfidentialClient | Remove-TestAzureAdApplication -Permanently -MSGraphToken $MSGraphToken
}
