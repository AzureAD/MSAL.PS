
## Read Module Manifest
$ModuleManifest = Import-PowershellDataFile (Join-Path $PSScriptRoot 'MSAL.PS.psd1')
[System.Collections.Generic.List[string]] $RequiredAssemblies = New-Object System.Collections.Generic.List[string]

## Select the correct assemblies for the PowerShell platform
if($PSEdition -eq 'Desktop') {
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
catch { throw }


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
        Add-Type -LiteralPath $srcTokenCacheHelper -ReferencedAssemblies $RequiredAssemblies
    }
}

## Load DeviceCodeHelper
foreach ($Path in ($ModuleManifest.FileList -like "*\DeviceCodeHelper.cs")) {
    $srcDeviceCodeHelper = Join-Path $PSScriptRoot $Path
}
if ($PSVersionTable.PSVersion -ge [version]'6.0') {
    $RequiredAssemblies.Add('System.Console.dll')
}
try {
    Add-Type -LiteralPath $srcDeviceCodeHelper -ReferencedAssemblies $RequiredAssemblies -IgnoreWarnings -WarningAction SilentlyContinue
}
catch {
    Write-Warning 'There was an error loading some dependencies. DeviceCode paramter will not function.'
}
