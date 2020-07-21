Set-StrictMode -Version 2.0

<#
.SYNOPSIS
    Get path relative to working directory.
.EXAMPLE
    PS C:\>Get-RelativePath 'C:\DirectoryA\File1.txt'
    Get path relative to current directory.
.EXAMPLE
    PS C:\>Get-RelativePath 'C:\DirectoryA\File1.txt' -WorkingDirectory 'C:\DirectoryB' -CompareCase
    Get path relative to specified working directory with case-sensitive directory comparison.
.INPUTS
    System.String
#>
function Get-RelativePath {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # Input paths
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string[]] $InputObjects,
        # Working directory for relative paths. Default is current directory.
        [Parameter(Mandatory = $false, Position = 2)]
        [string] $WorkingDirectory = (Get-Location).ProviderPath,
        # Compare directory names as case-sensitive.
        [Parameter(Mandatory = $false)]
        [switch] $CompareCase,
        # Directory separator used in paths.
        [Parameter(Mandatory = $false)]
        [char] $DirectorySeparator = [System.IO.Path]::DirectorySeparatorChar
    )

    begin {
        ## Adapted From:
        ##  https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/libraries/System.Private.Uri/src/System/Uri.cs#L5037
        function PathDifference([string] $path1, [string] $path2, [bool] $compareCase, [char] $directorySeparator = [System.IO.Path]::DirectorySeparatorChar) {
            [int] $i = 0
            [int] $si = -1

            for ($i = 0; ($i -lt $path1.Length) -and ($i -lt $path2.Length); $i++) {
                if (($path1[$i] -cne $path2[$i]) -and ($compareCase -or ([char]::ToLowerInvariant($path1[$i]) -cne [char]::ToLowerInvariant($path2[$i])))) {
                    break
                }
                elseif ($path1[$i] -ceq $directorySeparator) {
                    $si = $i
                }
            }

            if ($i -ceq 0) {
                return $path2
            }
            if (($i -ceq $path1.Length) -and ($i -ceq $path2.Length)) {
                return [string]::Empty
            }

            [System.Text.StringBuilder] $relPath = New-Object System.Text.StringBuilder
            ## Walk down several dirs
            for (; $i -lt $path1.Length; $i++) {
                if ($path1[$i] -ceq $directorySeparator) {
                    [void] $relPath.Append("..$directorySeparator")
                }
            }
            ## Same path except that path1 ended with a file name and path2 didn't
            if ($relPath.Length -ceq 0 -and $path2.Length - 1 -ceq $si) {
                return ".$directorySeparator" ## Truncate the file name
            }
            return $relPath.Append($path2.Substring($si + 1)).ToString()
        }
    }

    process {
        foreach ($InputObject in $InputObjects) {
            if (!$WorkingDirectory.EndsWith($DirectorySeparator)) { $WorkingDirectory += $DirectorySeparator }
            [string] $RelativePath = '.{0}{1}' -f $DirectorySeparator, (PathDifference $WorkingDirectory $InputObject $CompareCase $DirectorySeparator)
            Write-Output $RelativePath
        }
    }
}

function Get-FullPath {
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        # Input Paths
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [string[]] $Paths,
        # Directory to base relative paths. Default is current directory.
        [Parameter(Mandatory = $false, Position = 2)]
        [string] $BaseDirectory = (Get-Location).ProviderPath
    )

    process {
        foreach ($Path in $Paths) {
            [string] $AbsolutePath = $Path
            if (![System.IO.Path]::IsPathRooted($AbsolutePath)) {
                $AbsolutePath = (Join-Path $BaseDirectory $AbsolutePath)
            }
            [string] $AbsolutePath = [System.IO.Path]::GetFullPath($AbsolutePath)
            Write-Output $AbsolutePath
        }
    }
}

function Resolve-FullPath {
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        # Input Paths
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [string[]] $Paths,
        # Directory to base relative paths. Default is current directory.
        [Parameter(Mandatory = $false, Position = 2)]
        [string] $BaseDirectory = (Get-Location).ProviderPath,
        # Resolves items in all child directories of the specified locations.
        [Parameter(Mandatory = $false)]
        [switch] $Recurse,
        # Resolves items in all parent directories of the specified locations.
        [Parameter(Mandatory = $false)]
        [switch] $RecurseUp
    )

    process {
        foreach ($Path in $Paths) {
            [string] $AbsolutePath = $Path
            if (![System.IO.Path]::IsPathRooted($AbsolutePath)) {
                $AbsolutePath = (Join-Path $BaseDirectory $AbsolutePath)
            }
            [string[]] $AbsoluteOutputPaths = Resolve-Path $AbsolutePath
            if ($Recurse) {
                $RecurseBaseDirectory = Join-Path (Split-Path $AbsolutePath -Parent) "**"
                $RecurseFilename = Split-Path $AbsolutePath -Leaf
                $RecursePath = Join-Path $RecurseBaseDirectory $RecurseFilename
                $AbsoluteOutputPaths += Resolve-Path $RecursePath
            }
            if ($RecurseUp) {
                $RecurseBaseDirectory = Split-Path $AbsolutePath -Parent
                $RecurseFilename = Split-Path $AbsolutePath -Leaf
                while ($RecurseBaseDirectory -match "[\\/]") {
                    $RecurseBaseDirectory = Split-Path $RecurseBaseDirectory -Parent
                    if ($RecurseBaseDirectory) {
                        $RecursePath = Join-Path $RecurseBaseDirectory $RecurseFilename
                        $AbsoluteOutputPaths += Resolve-Path $RecursePath
                    }
                }
            }
            Write-Output $AbsoluteOutputPaths
        }
    }
}

function Get-PathInfo {
    [CmdletBinding()]
    param (
        # Input Paths
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [AllowEmptyString()]
        [string[]] $Paths,
        # Specifies the type of output path when the path does not exist. By default, it will guess path type. If path exists, this parameter is ignored.
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet("Directory", "File")]
        [string] $InputPathType,
        # Root directory to base relative paths. Default is current directory.
        [Parameter(Mandatory = $false, Position = 3)]
        [string] $DefaultDirectory = (Get-Location).ProviderPath,
        # Filename to append to path if no filename is present.
        [Parameter(Mandatory = $false, Position = 4)]
        [string] $DefaultFilename,
        #
        [Parameter(Mandatory = $false)]
        [switch] $SkipEmptyPaths
    )

    process {
        foreach ($Path in $Paths) {

            if (!$SkipEmptyPaths -and !$Path) { $Path = $DefaultDirectory }
            $OutputPath = $null

            if ($Path) {
                ## Look for existing path
                try {
                    $ResolvePath = Resolve-FullPath $Path -BaseDirectory $DefaultDirectory -ErrorAction SilentlyContinue
                    $OutputPath = Get-Item $ResolvePath -ErrorAction SilentlyContinue
                }
                catch { }
                if ($OutputPath -is [array]) {
                    $paramGetPathInfo = Select-PsBoundParameters $PSBoundParameters -CommandName Get-PathInfo -ExcludeParameters Paths
                    Get-PathInfo $OutputPath @paramGetPathInfo
                    return
                }

                ## If path could not be found and there are no wildcards, then create a FileSystemInfo object for the path.
                if (!$OutputPath -and $Path -notmatch '[*?]') {
                    ## Get Absolute Path
                    [string] $AbsolutePath = Get-FullPath $Path -BaseDirectory $DefaultDirectory
                    ## Guess if path is File or Directory
                    if ($InputPathType -eq "File" -or (!$InputPathType -and $AbsolutePath -match '[\\/](?!.*[\\/]).+\.(?!\.*$).*[^\\/]$')) {
                        $OutputPath = New-Object System.IO.FileInfo -ArgumentList $AbsolutePath
                    }
                    else {
                        $OutputPath = New-Object System.IO.DirectoryInfo -ArgumentList $AbsolutePath
                    }
                }
                ## If a DefaultFilename was provided and no filename was present in path, then add the default.
                if ($DefaultFilename -and $OutputPath -is [System.IO.DirectoryInfo]) {
                    [string] $AbsolutePath = (Join-Path $OutputPath.FullName $DefaultFileName)
                    $OutputPath = $null
                    try {
                        $ResolvePath = Resolve-FullPath $AbsolutePath -BaseDirectory $DefaultDirectory -ErrorAction SilentlyContinue
                        $OutputPath = Get-Item $ResolvePath -ErrorAction SilentlyContinue
                    }
                    catch { }
                    if (!$OutputPath -and $AbsolutePath -notmatch '[*?]') {
                        $OutputPath = New-Object System.IO.FileInfo -ArgumentList $AbsolutePath
                    }
                }

                if (!$OutputPath -or !$OutputPath.Exists) {
                    if ($OutputPath) { Write-Error -Exception (New-Object System.Management.Automation.ItemNotFoundException -ArgumentList ('Cannot find path ''{0}'' because it does not exist.' -f $OutputPath.FullName)) -TargetObject $OutputPath.FullName -ErrorId 'PathNotFound' -Category ObjectNotFound }
                    else { Write-Error -Exception (New-Object System.Management.Automation.ItemNotFoundException -ArgumentList ('Cannot find path ''{0}'' because it does not exist.' -f $AbsolutePath)) -TargetObject $AbsolutePath -ErrorId 'PathNotFound' -Category ObjectNotFound }
                }
            }

            ## Return Path Info
            Write-Output $OutputPath
        }
    }
}


function Assert-DirectoryExists {
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        # Directories
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [object[]] $InputObjects,
        # Directory to base relative paths. Default is current directory.
        [Parameter(Mandatory = $false, Position = 2)]
        [string] $BaseDirectory = (Get-Location).ProviderPath
    )
    process {
        foreach ($InputObject in $InputObjects) {
            ## InputObject Casting
            if ($InputObject -is [System.IO.DirectoryInfo]) {
                [System.IO.DirectoryInfo] $DirectoryInfo = $InputObject
            }
            elseif ($InputObject -is [System.IO.FileInfo]) {
                [System.IO.DirectoryInfo] $DirectoryInfo = $InputObject.Directory
            }
            elseif ($InputObject -is [string]) {
                [System.IO.DirectoryInfo] $DirectoryInfo = $InputObject
            }

            if (!$DirectoryInfo.Exists) {
                Write-Output (New-Item $DirectoryInfo.FullName -ItemType Container)
            }
        }
    }
}

function New-LogFilename ([string] $Path) { return ('{0}.{1}.log' -f $Path, (Get-Date -Format "yyyyMMddThhmmss")) }
function Get-ExtractionFolder ([System.IO.FileInfo] $Path) { return Join-Path $Path.DirectoryName $Path.BaseName }

function Use-StartBitsTransfer {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        # Specifies the source location and the names of the files that you want to transfer.
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Source,
        # Specifies the destination location and the names of the files that you want to transfer.
        [Parameter(Mandatory = $false, Position = 1)]
        [string] $Destination,
        # Specifies the proxy usage settings
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateSet('SystemDefault', 'NoProxy', 'AutoDetect', 'Override')]
        [string] $ProxyUsage,
        # Specifies a list of proxies to use
        [Parameter(Mandatory = $false, Position = 4)]
        [uri[]] $ProxyList,
        # Specifies the authentication mechanism to use at the Web proxy
        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet('Basic', 'Digest', 'NTLM', 'Negotiate', 'Passport')]
        [string] $ProxyAuthentication,
        # Specifies the credentials to use to authenticate the user at the proxy
        [Parameter(Mandatory = $false, Position = 6)]
        [pscredential] $ProxyCredential,
        # Returns an object representing transfered item.
        [Parameter(Mandatory = $false)]
        [switch] $PassThru
    )
    [hashtable] $paramStartBitsTransfer = $PSBoundParameters
    foreach ($Parameter in $PSBoundParameters.Keys) {
        if ($Parameter -notin 'ProxyUsage', 'ProxyList', 'ProxyAuthentication', 'ProxyCredential') {
            $paramStartBitsTransfer.Remove($Parameter)
        }
    }

    if (!$Destination) { $Destination = (Get-Location).ProviderPath }
    if (![System.IO.Path]::HasExtension($Destination)) { $Destination = Join-Path $Destination (Split-Path $Source -Leaf) }
    if (Test-Path $Destination) { Write-Verbose ('The Source [{0}] was not transfered to Destination [{0}] because it already exists.' -f $Source, $Destination) }
    else {
        Write-Verbose ('Downloading Source [{0}] to Destination [{1}]' -f $Source, $Destination);
        Start-BitsTransfer $Source $Destination @paramStartBitsTransfer
    }
    if ($PassThru) { return Get-Item $Destination }
}

function Use-StartProcess {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        # Specifies the path (optional) and file name of the program that runs in the process.
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $FilePath,
        # Specifies parameters or parameter values to use when starting the process.
        [Parameter(Mandatory = $false)]
        [string[]] $ArgumentList,
        # Specifies the working directory for the process.
        [Parameter(Mandatory = $false)]
        [string] $WorkingDirectory,
        # Specifies a user account that has permission to perform this action.
        [Parameter(Mandatory = $false)]
        [pscredential] $Credential,
        # Regex pattern in cmdline to replace with '**********'
        [Parameter(Mandatory = $false)]
        [string[]] $SensitiveDataFilters
    )
    [hashtable] $paramStartProcess = $PSBoundParameters
    foreach ($Parameter in $PSBoundParameters.Keys) {
        if ($Parameter -in 'SensitiveDataFilters') {
            $paramStartProcess.Remove($Parameter)
        }
    }
    [string] $cmd = '"{0}" {1}' -f $FilePath, ($ArgumentList -join ' ')
    foreach ($Filter in $SensitiveDataFilters) {
        $cmd = $cmd -replace $Filter, '**********'
    }
    if ($PSCmdlet.ShouldProcess([System.Environment]::MachineName, $cmd)) {
        [System.Diagnostics.Process] $process = Start-Process -PassThru -Wait -NoNewWindow @paramStartProcess
        if ($process.ExitCode -ne 0) { Write-Error -Category FromStdErr -CategoryTargetName (Split-Path $FilePath -Leaf) -CategoryTargetType "Process" -TargetObject $cmd -CategoryReason "Exit Code not equal to 0" -Message ('Process [{0}] with Id [{1}] terminated with Exit Code [{2}]' -f $FilePath, $process.Id, $process.ExitCode) }
    }
}

<#
.SYNOPSIS
    Convert Byte Array or Plain Text String to Base64 String.
.DESCRIPTION

.EXAMPLE
    PS C:\>ConvertTo-Base64String "A string with base64 encoding"
    Convert String with Default Encoding to Base64 String.
.EXAMPLE
    PS C:\>"ASCII string with base64url encoding" | ConvertTo-Base64String -Base64Url -Encoding Ascii
    Convert String with Ascii Encoding to Base64Url String.
.EXAMPLE
    PS C:\>ConvertTo-Base64String ([guid]::NewGuid())
    Convert GUID to Base64 String.
.INPUTS
    System.Object
#>
function ConvertTo-Base64String {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # Value to convert
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [object] $InputObject,
        # Use base64url variant
        [Parameter (Mandatory = $false)]
        [switch] $Base64Url,
        # Output encoding to use for text strings
        [Parameter (Mandatory = $false)]
        [ValidateSet("Ascii", "UTF32", "UTF7", "UTF8", "BigEndianUnicode", "Unicode")]
        [string] $Encoding = "Default"
    )

    process {
        [byte[]] $inputBytes = $null
        if ($InputObject -is [byte[]] -or $InputObject -is [byte]) {
            $inputBytes = $InputObject
        }
        elseif ($InputObject -is [string]) {
            $inputBytes = [Text.Encoding]::$Encoding.GetBytes($InputObject)
        }
        elseif ($InputObject -is [bool] -or $InputObject -is [char] -or $InputObject -is [single] -or $InputObject -is [double] -or $InputObject -is [int16] -or $InputObject -is [int32] -or $InputObject -is [int64] -or $InputObject -is [uint16] -or $InputObject -is [uint32] -or $InputObject -is [uint64]) {
            $inputBytes = [System.BitConverter]::GetBytes($InputObject)
        }
        elseif ($InputObject -is [guid]) {
            $inputBytes = $InputObject.ToByteArray()
        }
        elseif ($InputObject -is [System.IO.FileSystemInfo]) {
            $inputBytes = Get-Content $InputObject.FullName -Raw -Encoding Byte
        }
        else {
            # Otherwise, write a non-terminating error message indicating that input object type is not supported.
            $errorMessage = "Cannot convert input of type {0} to Base64 string." -f $InputObject.GetType()
            Write-Error -Message $errorMessage -Category ([System.Management.Automation.ErrorCategory]::ParserError) -ErrorId "ConvertBase64StringFailureTypeNotSupported"
        }

        if ($inputBytes) {
            [string] $outBase64String = [System.Convert]::ToBase64String($inputBytes)
            if ($Base64Url) { $outBase64String = $outBase64String.Replace('+', '-').Replace('/', '_').Replace('=', '') }
            return $outBase64String
        }
    }
}

<#
.SYNOPSIS
    Convert Base64 String to Byte Array or Plain Text String.
.DESCRIPTION

.EXAMPLE
    PS C:\>ConvertFrom-Base64String "QSBzdHJpbmcgd2l0aCBiYXNlNjQgZW5jb2Rpbmc="
    Convert Base64 String to String with Default Encoding.
.EXAMPLE
    PS C:\>"QVNDSUkgc3RyaW5nIHdpdGggYmFzZTY0dXJsIGVuY29kaW5n" | ConvertFrom-Base64String -Base64Url -Encoding Ascii
    Convert Base64Url String to String with Ascii Encoding.
.EXAMPLE
    PS C:\>[guid](ConvertFrom-Base64String "5oIhNbCaFUGAe8NsiAKfpA==" -RawBytes)
    Convert Base64 String to GUID.
.INPUTS
    System.String
#>
function ConvertFrom-Base64String {
    [CmdletBinding()]
    [OutputType([byte[]], [string])]
    param (
        # Value to convert
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string[]] $InputObject,
        # Use base64url variant
        [Parameter (Mandatory = $false)]
        [switch] $Base64Url,
        # Output raw byte array
        [Parameter (Mandatory = $false)]
        [switch] $RawBytes,
        # Encoding to use for text strings
        [Parameter (Mandatory = $false)]
        [ValidateSet("Ascii", "UTF32", "UTF7", "UTF8", "BigEndianUnicode", "Unicode")]
        [string] $Encoding = "Default"
    )

    process {
        $listBytes = New-Object object[] $InputObject.Count
        for ($iString = 0; $iString -lt $InputObject.Count; $iString++) {
            [string] $strBase64 = $InputObject[$iString]
            if ($Base64Url) { $strBase64 = $strBase64.Replace('-', '+').Replace('_', '/').PadRight($strBase64.Length + (4 - $strBase64.Length % 4) % 4, '=') }
            [byte[]] $outBytes = [System.Convert]::FromBase64String($strBase64)
            if ($RawBytes) { $listBytes[$iString] = $outBytes }
            else {
                $outString = ([Text.Encoding]::$Encoding.GetString($outBytes))
                Write-Output $outString
            }
        }
        if ($RawBytes) {
            return $listBytes
        }
    }
}

<#
.SYNOPSIS
    Convert PowerShell data types to PowerShell string syntax.
.DESCRIPTION

.EXAMPLE
    PS C:\>ConvertTo-PsString @{ key1='value1'; key2='value2' }
    Convert hashtable to PowerShell string.
.INPUTS
    System.String
#>
function ConvertTo-PsString {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        #
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [AllowNull()]
        [object] $InputObjects,
        #
        [Parameter(Mandatory = $false)]
        [switch] $Compact,
        #
        [Parameter(Mandatory = $false, Position = 1)]
        [type[]] $RemoveTypes = ([string], [bool], [int], [long]),
        #
        [Parameter(Mandatory = $false)]
        [switch] $NoEnumerate
    )

    begin {
        if ($Compact) {
            [System.Collections.Generic.Dictionary[string, type]] $TypeAccelerators = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')::get
            [System.Collections.Generic.Dictionary[type, string]] $TypeAcceleratorsLookup = New-Object 'System.Collections.Generic.Dictionary[type,string]'
            foreach ($TypeAcceleratorKey in $TypeAccelerators.Keys) {
                if (!$TypeAcceleratorsLookup.ContainsKey($TypeAccelerators[$TypeAcceleratorKey])) {
                    $TypeAcceleratorsLookup.Add($TypeAccelerators[$TypeAcceleratorKey], $TypeAcceleratorKey)
                }
            }
        }

        function Resolve-Type {
            param (
                #
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
                [type] $ObjectType,
                #
                [Parameter(Mandatory = $false, Position = 1)]
                [switch] $Compact,
                #
                [Parameter(Mandatory = $false, Position = 1)]
                [type[]] $RemoveTypes
            )

            [string] $OutputString = ''
            if ($ObjectType.IsGenericType) {
                if ($ObjectType.FullName.StartsWith('System.Collections.Generic.Dictionary')) {
                    #$OutputString += '[hashtable]'
                    if ($Compact) {
                        $OutputString += '(Invoke-Command { $D = New-Object ''Collections.Generic.Dictionary['
                    }
                    else {
                        $OutputString += '(Invoke-Command { $D = New-Object ''System.Collections.Generic.Dictionary['
                    }
                    $iInput = 0
                    foreach ($GenericTypeArgument in $ObjectType.GenericTypeArguments) {
                        if ($iInput -gt 0) { $OutputString += ',' }
                        $OutputString += Resolve-Type $GenericTypeArgument -Compact:$Compact -RemoveTypes @()
                        $iInput++
                    }
                    $OutputString += ']'''
                }
                elseif ($InputObject.GetType().FullName -match '^(System.(Collections.Generic.[a-zA-Z]+))`[0-9]\[(?:\[(.+?), .+?, Version=.+?, Culture=.+?, PublicKeyToken=.+?\],?)+?\]$') {
                    if ($Compact) {
                        $OutputString += '[{0}[' -f $Matches[2]
                    }
                    else {
                        $OutputString += '[{0}[' -f $Matches[1]
                    }
                    $iInput = 0
                    foreach ($GenericTypeArgument in $ObjectType.GenericTypeArguments) {
                        if ($iInput -gt 0) { $OutputString += ',' }
                        $OutputString += Resolve-Type $GenericTypeArgument -Compact:$Compact -RemoveTypes @()
                        $iInput++
                    }
                    $OutputString += ']]'
                }
            }
            elseif ($ObjectType -eq [System.Collections.Specialized.OrderedDictionary]) {
                $OutputString += '[ordered]'  # Explicit cast does not work with full name. Only [ordered] works.
            }
            elseif ($Compact) {
                if ($ObjectType -notin $RemoveTypes) {
                    if ($TypeAcceleratorsLookup.ContainsKey($ObjectType)) {
                        $OutputString += '[{0}]' -f $TypeAcceleratorsLookup[$ObjectType]
                    }
                    elseif ($ObjectType.FullName.StartsWith('System.')) {
                        $OutputString += '[{0}]' -f $ObjectType.FullName.Substring(7)
                    }
                    else {
                        $OutputString += '[{0}]' -f $ObjectType.FullName
                    }
                }
            }
            else {
                $OutputString += '[{0}]' -f $ObjectType.FullName
            }
            return $OutputString
        }

        function GetPSString ($InputObject) {
            $OutputString = New-Object System.Text.StringBuilder

            if ($null -eq $InputObject) { [void]$OutputString.Append('$null') }
            else {
                ## Add Casting
                [void]$OutputString.Append((Resolve-Type $InputObject.GetType() -Compact:$Compact -RemoveTypes $RemoveTypes))

                ## Add Value
                switch ($InputObject.GetType()) {
                    { $_.Equals([String]) } {
                        [void]$OutputString.AppendFormat("'{0}'", $InputObject.Replace("'", "''")) #.Replace('"','`"')
                        break
                    }
                    { $_.Equals([Char]) } {
                        [void]$OutputString.AppendFormat("'{0}'", ([string]$InputObject).Replace("'", "''"))
                        break
                    }
                    { $_.Equals([Boolean]) -or $_.Equals([switch]) } {
                        [void]$OutputString.AppendFormat('${0}', $InputObject)
                        break
                    }
                    { $_.Equals([DateTime]) } {
                        [void]$OutputString.AppendFormat("'{0}'", $InputObject.ToString('O'))
                        break
                    }
                    { $_.BaseType.Equals([Enum]) } {
                        [void]$OutputString.AppendFormat('::{0}', $InputObject)
                        break
                    }
                    { $_.BaseType.Equals([ValueType]) } {
                        [void]$OutputString.AppendFormat('{0}', $InputObject)
                        break
                    }
                    { $_.Equals([System.Xml.XmlDocument]) } {
                        [void]$OutputString.AppendFormat("'{0}'", $InputObject.OuterXml.Replace("'", "''")) #.Replace('"','""')
                        break
                    }
                    { $_.Equals([Hashtable]) -or $_.Equals([System.Collections.Specialized.OrderedDictionary]) } {
                        [void]$OutputString.Append('@{')
                        $iInput = 0
                        foreach ($enumHashtable in $InputObject.GetEnumerator()) {
                            if ($iInput -gt 0) { [void]$OutputString.Append(';') }
                            [void]$OutputString.AppendFormat('{0}={1}', (ConvertTo-PsString $enumHashtable.Key -Compact:$Compact -NoEnumerate), (ConvertTo-PsString $enumHashtable.Value -Compact:$Compact -NoEnumerate))
                            $iInput++
                        }
                        [void]$OutputString.Append('}')
                        break
                    }
                    { $_.FullName.StartsWith('System.Collections.Generic.Dictionary') } {
                        $iInput = 0
                        foreach ($enumHashtable in $InputObject.GetEnumerator()) {
                            [void]$OutputString.AppendFormat('; $D.Add({0},{1})', (ConvertTo-PsString $enumHashtable.Key -Compact:$Compact -NoEnumerate), (ConvertTo-PsString $enumHashtable.Value -Compact:$Compact -NoEnumerate))
                            $iInput++
                        }
                        [void]$OutputString.Append('; $D })')
                        break
                    }
                    { $_.BaseType.Equals([Array]) } {
                        [void]$OutputString.Append('(Write-Output @(')
                        $iInput = 0
                        for ($iInput = 0; $iInput -lt $InputObject.Count; $iInput++) {
                            if ($iInput -gt 0) { [void]$OutputString.Append(',') }
                            [void]$OutputString.Append((ConvertTo-PsString $InputObject[$iInput] -Compact:$Compact -RemoveTypes $InputObject.GetType().DeclaredMembers.Where( { $_.Name -eq 'Set' })[0].GetParameters()[1].ParameterType -NoEnumerate))
                        }
                        [void]$OutputString.Append(') -NoEnumerate)')
                        break
                    }
                    { $_.Equals([System.Collections.ArrayList]) } {
                        [void]$OutputString.Append('@(')
                        $iInput = 0
                        for ($iInput = 0; $iInput -lt $InputObject.Count; $iInput++) {
                            if ($iInput -gt 0) { [void]$OutputString.Append(',') }
                            [void]$OutputString.Append((ConvertTo-PsString $InputObject[$iInput] -Compact:$Compact -NoEnumerate))
                        }
                        [void]$OutputString.Append(')')
                        break
                    }
                    { $_.FullName.StartsWith('System.Collections.Generic.List') } {
                        [void]$OutputString.Append('@(')
                        $iInput = 0
                        for ($iInput = 0; $iInput -lt $InputObject.Count; $iInput++) {
                            if ($iInput -gt 0) { [void]$OutputString.Append(',') }
                            [void]$OutputString.Append((ConvertTo-PsString $InputObject[$iInput] -Compact:$Compact -RemoveTypes $_.GenericTypeArguments -NoEnumerate))
                        }
                        [void]$OutputString.Append(')')
                        break
                    }
                    ## Convert objects with object initializers
                    { $_ -is [object] -and ($_.GetConstructors() | foreach { if ($_.IsPublic -and !$_.GetParameters()) { $true } }) } {
                        [void]$OutputString.Append('@{')
                        $iInput = 0
                        foreach ($Item in ($InputObject | Get-Member -MemberType Property, NoteProperty)) {
                            if ($iInput -gt 0) { [void]$OutputString.Append(';') }
                            $PropertyName = $Item.Name
                            [void]$OutputString.AppendFormat('{0}={1}', (ConvertTo-PsString $PropertyName -Compact:$Compact -NoEnumerate), (ConvertTo-PsString $InputObject.$PropertyName -Compact:$Compact -NoEnumerate))
                            $iInput++
                        }
                        [void]$OutputString.Append('}')
                        break
                    }
                    Default {
                        $Exception = New-Object ArgumentException -ArgumentList ('Cannot convert input of type {0} to PowerShell string.' -f $InputObject.GetType())
                        Write-Error -Exception $Exception -Category ([System.Management.Automation.ErrorCategory]::ParserError) -CategoryActivity $MyInvocation.MyCommand -ErrorId 'ConvertPowerShellStringFailureTypeNotSupported' -TargetObject $InputObject
                    }
                }
            }

            if ($NoEnumerate) {
                $listOutputString.Add($OutputString.ToString())
            }
            else {
                Write-Output $OutputString.ToString()
            }
        }

        if ($NoEnumerate) {
            $listOutputString = New-Object System.Collections.Generic.List[string]
        }
    }

    process {
        if ($PSCmdlet.MyInvocation.ExpectingInput -or $NoEnumerate -or $null -eq $InputObjects) {
            GetPSString $InputObjects
        }
        else {
            foreach ($InputObject in $InputObjects) {
                GetPSString $InputObject
            }
        }
    }

    end {
        if ($NoEnumerate) {
            if (($null -eq $InputObjects -and $listOutputString.Count -eq 0) -or $listOutputString.Count -gt 1) {
                Write-Warning ('To avoid losing strong type on outermost enumerable type when piping, use "Write-Output $Array -NoEnumerate | {0}".' -f $MyInvocation.MyCommand)
                $OutputArray = New-Object System.Text.StringBuilder
                [void]$OutputArray.Append('(Write-Output @(')
                if ($PSVersionTable.PSVersion -ge [version]'6.0') {
                    [void]$OutputArray.AppendJoin(',', $listOutputString)
                }
                else {
                    [void]$OutputArray.Append(($listOutputString -join ','))
                }
                [void]$OutputArray.Append(') -NoEnumerate)')
                Write-Output $OutputArray.ToString()
            }
            else {
                Write-Output $listOutputString[0]
            }

        }
    }
}

<#
.SYNOPSIS
    Filters a hashtable or PSBoundParameters containing PowerShell command parameters to only those valid for specified command.
.EXAMPLE
    PS C:\>Select-PsBoundParameters @{Name='Valid'; Verbose=$true; NotAParameter='Remove'} -CommandName Get-Process -ExcludeParameters 'Verbose'
    Filters the parameter hashtable to only include valid parameters for the Get-Process command and exclude the Verbose parameter.
.EXAMPLE
    PS C:\>Select-PsBoundParameters @{Name='Valid'; Verbose=$true; NotAParameter='Remove'} -CommandName Get-Process -CommandParameterSets NameWithUserName
    Filters the parameter hashtable to only include valid parameters for the Get-Process command in the "NameWithUserName" ParameterSet.
.INPUTS
    System.String
#>
function Select-PsBoundParameters {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        # Specifies the parameter key pairs to be filtered.
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [hashtable] $NamedParameters,

        # Specifies the parameter names to remove from the output.
        [Parameter(Mandatory = $false)]
        [ArgumentCompleter( {
                param ( $commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters )
                if ($fakeBoundParameters.ContainsKey('NamedParameters')) {
                    [string[]]$fakeBoundParameters.NamedParameters.Keys | Where-Object { $_ -Like "$wordToComplete*" }
                }
            })]
        [string[]] $ExcludeParameters,

        # Specifies the name of a PowerShell command to further filter valid parameters.
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [ArgumentCompleter( {
                param ( $commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters )
                [array] $CommandInfo = Get-Command "$wordToComplete*"
                if ($CommandInfo) {
                    $CommandInfo.Name #| ForEach-Object {$_}
                }
            })]
        [Alias('Name')]
        [string] $CommandName,

        # Specifies parameter sets of the PowerShell command to further filter valid parameters.
        [Parameter(Mandatory = $false)]
        [ArgumentCompleter( {
                param ( $commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters )
                if ($fakeBoundParameters.ContainsKey('CommandName')) {
                    [array] $CommandInfo = Get-Command $fakeBoundParameters.CommandName
                    if ($CommandInfo) {
                        $CommandInfo[0].ParameterSets.Name | Where-Object { $_ -Like "$wordToComplete*" }
                    }
                }
            })]
        [string[]] $CommandParameterSets
    )

    process {
        [hashtable] $SelectedParameters = $NamedParameters.Clone()

        [string[]] $CommandParameters = $null
        if ($CommandName) {
            $CommandInfo = Get-Command $CommandName
            if ($CommandParameterSets) {
                [System.Collections.Generic.List[string]] $listCommandParameters = New-Object System.Collections.Generic.List[string]
                foreach ($CommandParameterSet in $CommandParameterSets) {
                    $listCommandParameters.AddRange([string[]]($CommandInfo.ParameterSets | Where-Object Name -eq $CommandParameterSet | Select-Object -ExpandProperty Parameters | Select-Object -ExpandProperty Name))
                }
                $CommandParameters = $listCommandParameters | Select-Object -Unique
            }
            else {
                $CommandParameters = $CommandInfo.Parameters.Keys
            }
        }

        [string[]] $ParameterKeys = $SelectedParameters.Keys
        foreach ($ParameterKey in $ParameterKeys) {
            if ($ExcludeParameters -contains $ParameterKey -or ($CommandParameters -and $CommandParameters -notcontains $ParameterKey)) {
                $SelectedParameters.Remove($ParameterKey)
            }
        }

        return $SelectedParameters
    }
}
