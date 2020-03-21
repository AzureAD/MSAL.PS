[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string] $ModulePath = "..\src\*.psd1"
)

Import-Module $ModulePath -Force

## Load Test Helper Functions
. (Join-Path $PSScriptRoot 'TestCommon.ps1')

## Perform Tests
Describe 'New-MsalClientApplication' {

    Context 'Public Client' {
        Write-Host
        It 'ClientId as Positional Parameter' {
            $Output = New-MsalClientApplication 'da616bc2-4047-43c7-9e1d-3fda870e8e7b'
            $Output | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplication]
            $Output.ClientId | Should -Be 'da616bc2-4047-43c7-9e1d-3fda870e8e7b'
        }

        It 'ClientId as Pipeline Input' {
            $Output = 'da616bc2-4047-43c7-9e1d-3fda870e8e7b' | New-MsalClientApplication
            $Output | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplication]
            $Output.ClientId | Should -Be 'da616bc2-4047-43c7-9e1d-3fda870e8e7b'
        }

        It 'ClientId as Positional Parameter with Additional Parameters' {
            $Output = New-MsalClientApplication 'da616bc2-4047-43c7-9e1d-3fda870e8e7b' -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
            $Output | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplication]
            $Output.ClientId | Should -Be 'da616bc2-4047-43c7-9e1d-3fda870e8e7b'
            $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
            $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
            Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
            $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
        }

        It 'ClientId as Pipeline Input with Additional Parameters' {
            $Output = 'da616bc2-4047-43c7-9e1d-3fda870e8e7b' | New-MsalClientApplication -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
            $Output | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplication]
            $Output.ClientId | Should -Be 'da616bc2-4047-43c7-9e1d-3fda870e8e7b'
            $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
            $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
            Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
            $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
        }

        It 'PublicClientApplicationOptions as Positional Parameter' {
            $Input = New-Object Microsoft.Identity.Client.PublicClientApplicationOptions -Property @{ ClientId = 'da616bc2-4047-43c7-9e1d-3fda870e8e7b' }
            $Input | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplicationOptions]
            $Output = New-MsalClientApplication $Input
            $Output | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplication]
            $Output.ClientId | Should -Be 'da616bc2-4047-43c7-9e1d-3fda870e8e7b'
        }

        It 'PublicClientApplicationOptions as Pipeline Input' {
            $Input = New-Object Microsoft.Identity.Client.PublicClientApplicationOptions -Property @{ ClientId = 'da616bc2-4047-43c7-9e1d-3fda870e8e7b' }
            $Input | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplicationOptions]
            $Output = $Input | New-MsalClientApplication
            $Output | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplication]
            $Output.ClientId | Should -Be 'da616bc2-4047-43c7-9e1d-3fda870e8e7b'
        }

        It 'PublicClientApplicationOptions as Positional Parameter with Additional Parameters' {
            $Input = New-Object Microsoft.Identity.Client.PublicClientApplicationOptions -Property @{ ClientId = 'da616bc2-4047-43c7-9e1d-3fda870e8e7b' }
            $Input | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplicationOptions]
            $Output = New-MsalClientApplication $Input -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
            $Output | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplication]
            $Output.ClientId | Should -Be 'da616bc2-4047-43c7-9e1d-3fda870e8e7b'
            $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
            $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
            Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
            $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
        }

        It 'PublicClientApplicationOptions as Pipeline Input with Additional Parameters' {
            $Input = New-Object Microsoft.Identity.Client.PublicClientApplicationOptions -Property @{ ClientId = 'da616bc2-4047-43c7-9e1d-3fda870e8e7b' }
            $Input | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplicationOptions]
            $Output = $Input | New-MsalClientApplication -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
            $Output | Should -BeOfType [Microsoft.Identity.Client.PublicClientApplication]
            $Output.ClientId | Should -Be 'da616bc2-4047-43c7-9e1d-3fda870e8e7b'
            $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
            $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
            Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
            $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
        }
    }

    Context 'Confidential Client' {

        Context 'Confidential Client with ClientSecret' {
            $ClientSecret = (ConvertTo-SecureString 'supersecretstring' -AsPlainText -Force)

            Write-Host
            It 'ClientId as Positional Parameter with ClientSecret' {
                $Output = New-MsalClientApplication '70558b77-ccf2-4bef-9e04-e90f01c88bb1' -ClientSecret $ClientSecret
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientSecret | Should -Be 'supersecretstring'
            }

            It 'ClientId as Pipeline Input with ClientSecret' {
                $Output = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' | New-MsalClientApplication -ClientSecret $ClientSecret
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientSecret | Should -Be 'supersecretstring'
            }

            It 'ClientId as Positional Parameter with ClientSecret and Additional Parameters' {
                $Output = New-MsalClientApplication '70558b77-ccf2-4bef-9e04-e90f01c88bb1' -ClientSecret $ClientSecret -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientSecret | Should -Be 'supersecretstring'
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }

            It 'ClientId as Pipeline Input with ClientSecret and Additional Parameters' {
                $Output = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' | New-MsalClientApplication -ClientSecret $ClientSecret -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientSecret | Should -Be 'supersecretstring'
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }

            It 'ConfidentialClientApplicationOptions as Positional Parameter with ClientSecret' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = New-MsalClientApplication $Input -ClientSecret $ClientSecret
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientSecret | Should -Be 'supersecretstring'
            }

            It 'ConfidentialClientApplicationOptions as Pipeline Input with ClientSecret' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = $Input | New-MsalClientApplication -ClientSecret $ClientSecret
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientSecret | Should -Be 'supersecretstring'
            }

            It 'ConfidentialClientApplicationOptions as Positional Parameter with ClientSecret and Additional Parameters' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = New-MsalClientApplication $Input -ClientSecret $ClientSecret -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientSecret | Should -Be 'supersecretstring'
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }

            It 'ConfidentialClientApplicationOptions as Pipeline Input with ClientSecret and Additional Parameters' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = $Input | New-MsalClientApplication -ClientSecret $ClientSecret -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientSecret | Should -Be 'supersecretstring'
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }
        }

        Context 'Confidential Client with ClientCertificate' {
            $ClientCertificate = (Get-ChildItem Cert:\CurrentUser\My | Select-Object -First 1)

            Write-Host
            It 'ClientId as Positional Parameter with ClientCertificate' {
                $Output = New-MsalClientApplication '70558b77-ccf2-4bef-9e04-e90f01c88bb1' -ClientCertificate $ClientCertificate
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
            }

            It 'ClientId as Pipeline Input with ClientCertificate' {
                $Output = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' | New-MsalClientApplication -ClientCertificate $ClientCertificate
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
            }

            It 'ClientId as Positional Parameter with ClientCertificate and Additional Parameters' {
                $Output = New-MsalClientApplication '70558b77-ccf2-4bef-9e04-e90f01c88bb1' -ClientCertificate $ClientCertificate -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }

            It 'ClientId as Pipeline Input with ClientCertificate and Additional Parameters' {
                $Output = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' | New-MsalClientApplication -ClientCertificate $ClientCertificate -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }

            It 'ConfidentialClientApplicationOptions as Positional Parameter with ClientCertificate' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = New-MsalClientApplication $Input -ClientCertificate $ClientCertificate
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
            }

            It 'ConfidentialClientApplicationOptions as Pipeline Input with ClientCertificate' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = $Input | New-MsalClientApplication -ClientCertificate $ClientCertificate
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
            }

            It 'ConfidentialClientApplicationOptions as Positional Parameter with ClientCertificate and Additional Parameters' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = New-MsalClientApplication $Input -ClientCertificate $ClientCertificate -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }

            It 'ConfidentialClientApplicationOptions as Pipeline Input with ClientCertificate and Additional Parameters' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = $Input | New-MsalClientApplication -ClientCertificate $ClientCertificate -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }
        }

        Context 'Confidential Client with ClientClaims' {
            $ClientCertificate = (Get-ChildItem Cert:\CurrentUser\My | Select-Object -First 1)
            $ClientClaims = @{ ipaddress = '127.0.0.1' }

            Write-Host
            It 'ClientId as Positional Parameter with ClientClaims' {
                $Output = New-MsalClientApplication '70558b77-ccf2-4bef-9e04-e90f01c88bb1' -ClientCertificate $ClientCertificate -ClientClaims $ClientClaims
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
                Test-ComparisionAssertions $Output.AppConfig.ClaimsToSign (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('ipaddress','127.0.0.1'); $D })
            }

            It 'ClientId as Pipeline Input with ClientClaims' {
                $Output = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' | New-MsalClientApplication -ClientCertificate $ClientCertificate -ClientClaims $ClientClaims
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
                Test-ComparisionAssertions $Output.AppConfig.ClaimsToSign (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('ipaddress','127.0.0.1'); $D })
            }

            It 'ClientId as Positional Parameter with ClientClaims and Additional Parameters' {
                $Output = New-MsalClientApplication '70558b77-ccf2-4bef-9e04-e90f01c88bb1' -ClientCertificate $ClientCertificate -ClientClaims $ClientClaims -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
                Test-ComparisionAssertions $Output.AppConfig.ClaimsToSign (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('ipaddress','127.0.0.1'); $D })
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }

            It 'ClientId as Pipeline Input with ClientClaims and Additional Parameters' {
                $Output = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' | New-MsalClientApplication -ClientCertificate $ClientCertificate -ClientClaims $ClientClaims -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
                Test-ComparisionAssertions $Output.AppConfig.ClaimsToSign (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('ipaddress','127.0.0.1'); $D })
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }

            It 'ConfidentialClientApplicationOptions as Positional Parameter with ClientClaims' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = New-MsalClientApplication $Input -ClientCertificate $ClientCertificate -ClientClaims $ClientClaims
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
                Test-ComparisionAssertions $Output.AppConfig.ClaimsToSign (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('ipaddress','127.0.0.1'); $D })
            }

            It 'ConfidentialClientApplicationOptions as Pipeline Input with ClientClaims' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = $Input | New-MsalClientApplication -ClientCertificate $ClientCertificate -ClientClaims $ClientClaims
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
                Test-ComparisionAssertions $Output.AppConfig.ClaimsToSign (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('ipaddress','127.0.0.1'); $D })
            }

            It 'ConfidentialClientApplicationOptions as Positional Parameter with ClientClaims and Additional Parameters' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = New-MsalClientApplication $Input -ClientCertificate $ClientCertificate -ClientClaims $ClientClaims -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
                Test-ComparisionAssertions $Output.AppConfig.ClaimsToSign (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('ipaddress','127.0.0.1'); $D })
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }

            It 'ConfidentialClientApplicationOptions as Pipeline Input with ClientClaims and Additional Parameters' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = $Input | New-MsalClientApplication -ClientCertificate $ClientCertificate -ClientClaims $ClientClaims -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.ClientCredentialCertificate | Should -Be $ClientCertificate
                Test-ComparisionAssertions $Output.AppConfig.ClaimsToSign (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('ipaddress','127.0.0.1'); $D })
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }
        }

        Context 'Confidential Client with ClientAssertion' {
            $ClientAssertion = 'Client Assertion Base64-Encoded JWT'

            Write-Host
            It 'ClientId as Positional Parameter with ClientAssertion' {
                $Output = New-MsalClientApplication '70558b77-ccf2-4bef-9e04-e90f01c88bb1' -ClientAssertion $ClientAssertion
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.SignedClientAssertion | Should -Be $ClientAssertion
            }

            It 'ClientId as Pipeline Input with ClientAssertion' {
                $Output = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' | New-MsalClientApplication -ClientAssertion $ClientAssertion
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.SignedClientAssertion | Should -Be $ClientAssertion
            }

            It 'ClientId as Positional Parameter with ClientAssertion and Additional Parameters' {
                $Output = New-MsalClientApplication '70558b77-ccf2-4bef-9e04-e90f01c88bb1' -ClientAssertion $ClientAssertion -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.SignedClientAssertion | Should -Be $ClientAssertion
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }

            It 'ClientId as Pipeline Input with ClientAssertion and Additional Parameters' {
                $Output = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' | New-MsalClientApplication -ClientAssertion $ClientAssertion -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.SignedClientAssertion | Should -Be $ClientAssertion
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }

            It 'ConfidentialClientApplicationOptions as Positional Parameter with ClientAssertion' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = New-MsalClientApplication $Input -ClientAssertion $ClientAssertion
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.SignedClientAssertion | Should -Be $ClientAssertion
            }

            It 'ConfidentialClientApplicationOptions as Pipeline Input with ClientAssertion' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = $Input | New-MsalClientApplication -ClientAssertion $ClientAssertion
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.SignedClientAssertion | Should -Be $ClientAssertion
            }

            It 'ConfidentialClientApplicationOptions as Positional Parameter with ClientAssertion and Additional Parameters' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = New-MsalClientApplication $Input -ClientAssertion $ClientAssertion -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.SignedClientAssertion | Should -Be $ClientAssertion
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }

            It 'ConfidentialClientApplicationOptions as Pipeline Input with ClientAssertion and Additional Parameters' {
                $Input = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions -Property @{ ClientId = '70558b77-ccf2-4bef-9e04-e90f01c88bb1' }
                $Input | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplicationOptions]
                $Output = $Input | New-MsalClientApplication -ClientAssertion $ClientAssertion -RedirectUri 'https://testhost/' -TenantId 'test.onmicrosoft.com' -ExtraQueryParameters @{ state = 'appState' } -EnableExperimentalFeatures
                $Output | Should -BeOfType [Microsoft.Identity.Client.ConfidentialClientApplication]
                $Output.ClientId | Should -Be '70558b77-ccf2-4bef-9e04-e90f01c88bb1'
                $Output.AppConfig.SignedClientAssertion | Should -Be $ClientAssertion
                $Output.AppConfig.RedirectUri | Should -Be 'https://testhost/'
                $Output.AppConfig.TenantId | Should -Be 'test.onmicrosoft.com'
                Test-ComparisionAssertions $Output.AppConfig.ExtraQueryParameters (Invoke-Command { $D = New-Object 'System.Collections.Generic.Dictionary[[string],[string]]'; $D.Add('state','appState'); $D })
                $Output.AppConfig.ExperimentalFeaturesEnabled | Should -Be $true
            }
        }
    }
}
