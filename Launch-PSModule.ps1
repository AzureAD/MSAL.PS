param
(
    # Module to Launch
    [Parameter(Mandatory=$false)]
    [string] $ModuleManifestPath = ".\src\*.psd1",
    # Paths to PowerShell Executables
    [Parameter(Mandatory=$false)]
    [string[]] $PowerShellPaths = @(
        'pwsh'
        'powershell'
        #'D:\Software\PowerShell-6.2.4-win-x64\pwsh.exe'
    ),
    # Import Module into the same session
    [parameter(Mandatory=$false)]
    [switch] $NoNewWindow #= $true
)

.\build\Restore-NugetPackages.ps1 -BaseDirectory ".\" -Verbose:$false

if ($NoNewWindow) {
    Import-Module $ModuleManifestPath -PassThru -Force
}
else {
    $strScriptBlock = 'Import-Module {0} -PassThru' -f $ModuleManifestPath
    #$strScriptBlock = '$PSModule = Import-Module {0} -PassThru; Get-Command -Module $PSModule' -f $ModuleManifestPath

    foreach ($Path in $PowerShellPaths) {
        Start-Process $Path -ArgumentList ('-NoExit','-NoProfile','-EncodedCommand',[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($strScriptBlock)))
    }
}
