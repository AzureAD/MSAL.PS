
Remove-Module ADAL.PS -ErrorAction SilentlyContinue
Import-Module ..\src\ADAL.PS.psd1

[pscredential] $credAADv2AuthTest = New-Object pscredential -ArgumentList 'ae2f53fa-5230-4fb4-af5f-b24dbf165e0e',(ConvertTo-SecureString 'tpjsRRJS81%?klbBTN854[;' -AsPlainText -Force)
[pscredential] $credAADPowerShell = New-Object pscredential -ArgumentList '1950a258-227b-4e31-a9cf-717495945fc2',(ConvertTo-SecureString 'null' -AsPlainText -Force)

Get-ADALToken -TenantId "jasothlab.onmicrosoft.com" -Resource 'https://graph.microsoft.com/' -ClientId $credAADv2AuthTest.UserName #-PromptBehavior Always -UserId $User
