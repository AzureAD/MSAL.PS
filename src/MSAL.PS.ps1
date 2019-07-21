
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
