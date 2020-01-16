param
(
    # Module to Launch
    [parameter(Mandatory=$false)]
    [string] $ModuleManifestPath = ".\src\MSAL.PS.psd1",
    # Import Module into the same session
    [parameter(Mandatory=$false)]
    [switch] $NoNewWindow
)

.\build\Restore-NugetPackages.ps1 -BaseDirectory ".\" -Verbose:$false

if ($NoNewWindow) {
    Import-Module $ModuleManifestPath -PassThru
}
else {
    $strScriptBlock = 'Import-Module {0} -PassThru' -f $ModuleManifestPath
    #$strScriptBlock = '$PSModule = Import-Module {0} -PassThru; Get-Command -Module $PSModule' -f $ModuleManifestPath
    Start-Process powershell -ArgumentList ('-NoExit','-NoProfile','-EncodedCommand',[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Import-Module Microsoft.PowerShell.Management,Microsoft.PowerShell.Security,Microsoft.PowerShell.Utility -MaximumVersion 5.9; ' + $strScriptBlock)))  # Launching PowerShell 5.1 from Pwsh 6+ loads the wrong version of core modules.
    #Start-Process pwsh -ArgumentList ('-NoExit','-NoProfile','-EncodedCommand',[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($strScriptBlock)))
}
