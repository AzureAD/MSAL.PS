#region Import Helper Functions
function Get-Config {
    [CmdletBinding()]
    param ()

    $config = [PSCustomObject]@{
        Mode               = 'Strict'
        UserChose          = $false
        ShowedInstructions = $false
    }

    $configPath = Join-Path -Path (Split-Path -Path $profile) -ChildPath 'MSAL.PS.config'
    if (-not (Test-Path -Path $configPath)) { return $config }

    $cfgFileContent = Get-Content -Path $configPath | ConvertFrom-Json

    if ($cfgFileContent.PSObject.Properties.Name -contains 'Mode') { $config.Mode = $cfgFileContent.Mode }
    if ($cfgFileContent.PSObject.Properties.Name -contains 'UserChose') { $config.UserChose = $cfgFileContent.UserChose }
    if ($cfgFileContent.PSObject.Properties.Name -contains 'ShowedInstructions') { $config.ShowedInstructions = $cfgFileContent.ShowedInstructions }

    if ($env:msalps_Mode) {
        $config.Mode = $env:msalps_Mode
        $config.UserChose = $true
    }
    if ($env:msalps_ShowedInstructions) {
        $config.ShowedInstructions = $true
    }

    $config
}

function Set-Config {
    [CmdletBinding()]
    param (
        [ValidateSet('Strict', 'Lenient')]
        [string]
        $Mode,

        [bool]
        $UserChose,

        [bool]
        $ShowedInstructions
    )

    $config = Get-Config
    $configPath = Join-Path -Path (Split-Path -Path $profile) -ChildPath 'MSAL.PS.config'

    if ($PSBoundParameters.Keys -contains 'Mode') { $config.Mode = $Mode }
    if ($PSBoundParameters.Keys -contains 'UserChose') { $config.UserChose = $UserChose }
    if ($PSBoundParameters.Keys -contains 'ShowedInstructions') { $config.ShowedInstructions = $ShowedInstructions }

    $config | ConvertTo-Json | Set-Content -Path $configPath -Force -ErrorAction Ignore
}

function Get-DllImportMode {
    [CmdletBinding()]
    param (
        [string]    
        $AssemblyPath
    )

    # Option 1: Global variable
    if (Get-Variable msalps_DllImportMode -ErrorAction Ignore) {
        switch ($msalps_DllImportMode) {
            'Strict' { return 'Strict' }
            'Lenient' { return 'Lenient' }
            default { return 'Strict' }
        }
    }

    # Option 2: Configuration
    $config = Get-Config
    if ($config.UserChose) {
        return $config.Mode
    }

    # Option 3: Ask
    Write-Host @"
There is already a different version of the file 'Microsoft.Identity.Client.dll' loaded:
$($AssemblyPath)
This MAY break our module, but it also may work just fine.
"@

    $caption = 'Continue Module Import anyway?'
    $choseLenient = $Host.UI.PromptForChoice($caption, $null, @('&Yes', '&No'), 1) -eq 0
    if ($choseLenient) { $mode = 'Lenient' }
    else { $mode = 'Strict' }

    $caption2 = 'Remember Choice?'
    $message2 = "This choice will be persisted in $(Join-Path -Path (Split-Path -Path $profile) -ChildPath 'MSAL.PS.config')"
    $persist = $Host.UI.PromptForChoice($caption2, $message2, @('&Yes', '&No'), 1) -eq 0

    if ($persist) {
        Set-Config -Mode $mode -UserChose $true
    }

    if (-not $config.ShowedInstructions) {
        Write-Host @'
This choice can be suppressed by setting a global variable:
$msalps_DllImportMode = 'Strict' # Stop module import
$msalps_DllImportMode = 'Lenient' # Continue anyway

You can also define an environment variable:
$env:msalps_mode = 'Strict' # Stop module import
$env:msalps_mode = 'Lenient' # Continue anyway
'@
        Set-Config -ShowedInstructions $true
    }
    $mode
}
#endregion Import Helper Functions

## Read Module Manifest
$ModuleManifest = Import-PowershellDataFile (Join-Path $PSScriptRoot 'MSAL.PS.psd1')
[System.Collections.Generic.List[string]] $RequiredAssemblies = New-Object System.Collections.Generic.List[string]

## Select the correct assemblies for the PowerShell platform
if ($PSEdition -eq 'Desktop') {
    foreach ($Path in ($ModuleManifest.FileList -like "*\Microsoft.Identity.Client.*\net45\*.dll")) {
        $RequiredAssemblies.Add((Join-Path $PSScriptRoot $Path))
    }
}
elseif ($PSEdition -eq 'Core') {
    foreach ($Path in ($ModuleManifest.FileList -like "*\Microsoft.Identity.Client.*\netcoreapp2.1\*.dll")) {
        $RequiredAssemblies.Add((Join-Path $PSScriptRoot $Path))
    }
}

## Load correct assemblies for the PowerShell platform
try {
    Add-Type -LiteralPath $RequiredAssemblies | Out-Null
}
catch {
    Write-Warning "Failed to load client assembly 'Microsoft.Identity.Client': $_"

    $msalLib = [System.AppDomain]::CurrentDomain.GetAssemblies().Where{ 'Microsoft.Identity.Client.dll' -eq $_.ManifestModule }
    if (-not $msalLib) { throw }

    $mode = Get-DllImportMode -AssemblyPath $msalLib.Location
    if ($mode -eq 'Strict') {
        throw
    }
    $RequiredAssemblies.Add($msalLib.Location)
}


## Load TokenCacheHelper
if ([System.Environment]::OSVersion.Platform -eq 'Win32NT') {
    foreach ($Path in ($ModuleManifest.FileList -like "*\TokenCacheHelper.cs")) {
        $srcTokenCacheHelper = Join-Path $PSScriptRoot $Path
    }
    if ($PSVersionTable.PSVersion -ge [version]'7.0') {
        # $RequiredAssemblies.AddRange([string[]]@('System.Threading.dll','System.Runtime.Extensions.dll','System.IO.FileSystem.dll','System.Security.Cryptography.ProtectedData.dll'))
        # Add-Type -LiteralPath $srcTokenCacheHelper -ReferencedAssemblies $RequiredAssemblies
    }
    elseif ($PSVersionTable.PSVersion -ge [version]'6.0') {
        # foreach ($Path in ($ModuleManifest.FileList -like "*\System.Security.Cryptography.ProtectedData.*\netstandard1.3\*.dll")) {
        #     $ProtectedData = Join-Path $PSScriptRoot $Path
        # }
        # $RequiredAssemblies.AddRange([string[]]@('System.Threading.dll','System.Runtime.Extensions.dll','System.IO.FileSystem.dll',$ProtectedData))
        # Add-Type -LiteralPath $srcTokenCacheHelper -ReferencedAssemblies $RequiredAssemblies -IgnoreWarnings -WarningAction SilentlyContinue
    }
    elseif ($PSVersionTable.PSVersion -ge [version]'5.1') {
        $RequiredAssemblies.Add('System.Security.dll')
        #try {
        Add-Type -LiteralPath $srcTokenCacheHelper -ReferencedAssemblies $RequiredAssemblies
        #}
        #catch {
        #    Write-Warning 'There was an error loading some dependencies. Storing TokenCache on disk will not function.'
        #}
    }
}

## Load DeviceCodeHelper
foreach ($Path in ($ModuleManifest.FileList -like "*\DeviceCodeHelper.cs")) {
    $srcDeviceCodeHelper = Join-Path $PSScriptRoot $Path
}
if ($PSVersionTable.PSVersion -ge [version]'6.0') {
    $RequiredAssemblies.Add('System.Console.dll')
    #$RequiredAssemblies.Add('System.ComponentModel.Primitives.dll')
    #$RequiredAssemblies.Add('System.Diagnostics.Process.dll')
}
try {
    Add-Type -LiteralPath $srcDeviceCodeHelper -ReferencedAssemblies $RequiredAssemblies -IgnoreWarnings -WarningAction SilentlyContinue
}
catch {
    Write-Warning 'There was an error loading some dependencies. DeviceCode parameter will not function.'
}
