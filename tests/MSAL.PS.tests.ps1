
Remove-Module MSAL.PS -ErrorAction SilentlyContinue
Import-Module ..\src\MSAL.PS.psd1

Get-MSALToken -Resource 'https://graph.microsoft.com/' #-PromptBehavior Always -UserId $User
