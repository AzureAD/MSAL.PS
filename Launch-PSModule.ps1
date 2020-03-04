param
(
    # Module to Launch
    [Parameter(Mandatory=$false)]
    [string] $ModuleManifestPath = ".\src\*.psd1",
    # Import Module into the same session
<<<<<<< HEAD
    [parameter(Mandatory=$false)]
    [switch] $NoNewWindow #= $true
=======
    [Parameter(Mandatory=$false)]
    [switch] $NoNewWindow
>>>>>>> db3bd28c6a9969971daa7b80af34705d8c2e3aaf
)

.\build\Restore-NugetPackages.ps1 -BaseDirectory ".\" -Verbose:$false

if ($NoNewWindow) {
    Import-Module $ModuleManifestPath -PassThru -Force
}
else {
    $strScriptBlock = 'Import-Module {0} -PassThru' -f $ModuleManifestPath
    #$strScriptBlock = '$PSModule = Import-Module {0} -PassThru; Get-Command -Module $PSModule' -f $ModuleManifestPath
    Start-Process powershell -ArgumentList ('-NoExit','-NoProfile','-EncodedCommand',[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Import-Module Microsoft.PowerShell.Management,Microsoft.PowerShell.Security,Microsoft.PowerShell.Utility -MaximumVersion 5.9; ' + $strScriptBlock)))  # Launching PowerShell 5.1 from Pwsh 6+ loads the wrong version of core modules.
    #Start-Process pwsh -ArgumentList ('-NoExit','-NoProfile','-EncodedCommand',[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($strScriptBlock)))
}
