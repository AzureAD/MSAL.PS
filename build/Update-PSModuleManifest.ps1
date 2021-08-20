param
(
    # Path to Module Manifest
    [Parameter(Mandatory = $false)]
    [string] $ModuleManifestPath = ".\release\*\*.*.*",
    # Specifies a unique identifier for the module.
    [Parameter(Mandatory = $false)]
    [string] $Guid,
    # Module Version
    [Parameter(Mandatory = $false)]
    [string] $ModuleVersion,
    # Indicates the module is prerelease.
    [Parameter(Mandatory = $false)]
    [string] $Prerelease,
    # Skip Update of RequiredAssemblies
    [Parameter(Mandatory = $false)]
    [switch] $SkipRequiredAssemblies
)

## Initialize
Import-Module "$PSScriptRoot\CommonFunctions.psm1" -Force -WarningAction SilentlyContinue -ErrorAction Stop
[hashtable] $paramUpdateModuleManifest = @{ }
if ($Guid) { $paramUpdateModuleManifest['Guid'] = $Guid }
if ($ModuleVersion) { $paramUpdateModuleManifest['ModuleVersion'] = $ModuleVersion }
if ($Prerelease) { $paramUpdateModuleManifest['Prerelease'] = $Prerelease }

[System.IO.FileInfo] $ModuleManifestFileInfo = Get-PathInfo $ModuleManifestPath -DefaultFilename "*.psd1" -ErrorAction Stop

## Read Module Manifest
$ModuleManifest = Import-PowerShellDataFile $ModuleManifestFileInfo.FullName
$paramUpdateModuleManifest['NestedModules'] = $ModuleManifest.NestedModules
$paramUpdateModuleManifest['CmdletsToExport'] = $ModuleManifest.CmdletsToExport
$paramUpdateModuleManifest['AliasesToExport'] = $ModuleManifest.AliasesToExport
[System.IO.DirectoryInfo] $ModuleOutputDirectoryInfo = $ModuleManifestFileInfo.Directory

## Get Module Output FileList
$ModuleFileListFileInfo = Get-ChildItem $ModuleOutputDirectoryInfo.FullName -Recurse -File
$ModuleRequiredAssembliesFileInfo = $ModuleFileListFileInfo | Where-Object Extension -eq '.dll'

## Get Paths Relative to Module Base Directory
$ModuleFileList = Get-RelativePath $ModuleFileListFileInfo.FullName -WorkingDirectory $ModuleOutputDirectoryInfo.FullName -ErrorAction Stop
# PowerShell 6.0 through 7.0.x fails to load assembly if net45 dll comes before netcoreapp2.1 dll in the FileList. Fixed in PowerShell 7.1.
$ModuleFileList = $ModuleFileList -replace '\\net45\\Microsoft.Identity.Client.dll', '\!!!\Microsoft.Identity.Client.dll' -replace '\\netcoreapp2.1\\Microsoft.Identity.Client.dll', '\net45\Microsoft.Identity.Client.dll' -replace '\\!!!\\Microsoft.Identity.Client.dll', '\netcoreapp2.1\Microsoft.Identity.Client.dll'
$ModuleFileList = $ModuleFileList -replace '\\net461\\Microsoft.Identity.Client.Desktop.dll', '\!!!\Microsoft.Identity.Client.Desktop.dll' -replace '\\netcoreapp3.1\\Microsoft.Identity.Client.Desktop.dll', '\net461\Microsoft.Identity.Client.Desktop.dll' -replace '\\!!!\\Microsoft.Identity.Client.Desktop.dll', '\netcoreapp3.1\Microsoft.Identity.Client.Desktop.dll'
$ModuleFileList = $ModuleFileList -replace '\\net45\\Microsoft.Web.WebView2.', '\!!!\Microsoft.Web.WebView2.' -replace '\\netcoreapp3.0\\Microsoft.Web.WebView2.', '\net45\Microsoft.Web.WebView2.' -replace '\\!!!\\Microsoft.Web.WebView2.', '\netcoreapp3.0\Microsoft.Web.WebView2.'
#$ModuleFileList = $ModuleFileList -replace '\\net45\\', '\!!!\' -replace '\\netcoreapp2.1\\', '\net45\' -replace '\\!!!\\', '\netcoreapp2.1\'
$paramUpdateModuleManifest['FileList'] = $ModuleFileList

if (!$SkipRequiredAssemblies -and $ModuleRequiredAssembliesFileInfo) {
    $ModuleRequiredAssemblies = Get-RelativePath $ModuleRequiredAssembliesFileInfo.FullName -WorkingDirectory $ModuleOutputDirectoryInfo.FullName -ErrorAction Stop
    $paramUpdateModuleManifest['RequiredAssemblies'] = $ModuleRequiredAssemblies
}

## Clear RequiredAssemblies
(Get-Content $ModuleManifestFileInfo.FullName -Raw) -replace "(?s)RequiredAssemblies\ =\ @\([^)]*\)", "# RequiredAssemblies = @()" | Set-Content $ModuleManifestFileInfo.FullName
(Get-Content $ModuleManifestFileInfo.FullName -Raw) -replace "(?s)FileList\ =\ @\([^)]*\)", "# FileList = @()" | Set-Content $ModuleManifestFileInfo.FullName

## Install Module Dependencies
foreach ($Module in $ModuleManifest.RequiredModules) {
    if ($Module -is [hashtable]) { $ModuleName = $Module.ModuleName }
    else { $ModuleName = $Module }
    if ($ModuleName -notin $ModuleManifest.PrivateData.PSData['ExternalModuleDependencies'] -and !(Get-Module $ModuleName -ListAvailable)) {
        Install-Module $ModuleName -Force -SkipPublisherCheck -Repository PSGallery -AcceptLicense
    }
}

## Update Module Manifest in Module Output Directory
Update-ModuleManifest -Path $ModuleManifestFileInfo.FullName -ErrorAction Stop @paramUpdateModuleManifest
