param
(
    # Module to Launch
    [Parameter(Mandatory = $false)]
    #[string] $ModuleManifestPath = ".\src\*.psd1",
    [string] $ModuleManifestPath = ".\build\release\*",
    # ScriptBlock to Execute After Module Import
    [Parameter(Mandatory = $false)]
    [scriptblock] $PostImportScriptBlock,
    # Paths to PowerShell Executables
    [Parameter(Mandatory = $false)]
    [string[]] $PowerShellPaths = @(
        #'pwsh'
        #'powershell'
        #'C:\Software\PowerShell-6.0.0-win-x64\pwsh.exe'
        #'C:\Software\PowerShell-6.2.7-win-x64\pwsh.exe'
        #'C:\Software\PowerShell-7.0.0-win-x64\pwsh.exe'
        #'C:\Software\PowerShell-7.0.5-win-x64\pwsh.exe'
        'C:\Software\PowerShell-7.1.0-win-x64\pwsh.exe'
    ),
    # Import Module into the same session
    [Parameter(Mandatory = $false)]
    [switch] $NoNewWindow #= $true
)

#.\build\Restore-NugetPackages.ps1 -BaseDirectory ".\" -Verbose:$false
.\build\Build-PSModule.ps1 -BaseDirectory ".\" -Verbose:$false -OutVariable BuildOutput
if ($ModuleManifestPath.Contains('*')) { $ModuleManifestPath = $BuildOutput[0] }

if ($NoNewWindow) {
    Import-Module $ModuleManifestPath -PassThru -Force
    if ($PostImportScriptBlock) { Invoke-Command -ScriptBlock $PostImportScriptBlock -NoNewScope }
}
else {
    [scriptblock] $ScriptBlock = {
        param ([string]$ModulePath, [scriptblock]$PostImportScriptBlock)
        ## Force WindowsPowerShell to load correct version of built-in modules when launched from PowerShell 6+
        if ($PSVersionTable.PSEdition -eq 'Desktop') { Import-Module 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility', 'CimCmdlets' -MaximumVersion 5.9.9.9 }
        Import-Module $ModulePath -PassThru
        Invoke-Command -ScriptBlock $PostImportScriptBlock -NoNewScope
    }
    $strScriptBlock = 'Invoke-Command -ScriptBlock {{ {0} }} -ArgumentList {1}, {{ {2} }}' -f $ScriptBlock, $ModuleManifestPath, $PostImportScriptBlock
    #$strScriptBlock = 'Import-Module {0} -PassThru' -f $ModuleManifestPath

    foreach ($Path in $PowerShellPaths) {
        Start-Process $Path -ArgumentList ('-NoExit', '-NoProfile', '-EncodedCommand', [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($strScriptBlock)))
    }
}
