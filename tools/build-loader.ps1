param(
    [ValidateSet('Build', 'Check', 'Test', 'Clippy')]
    [string]$Action = 'Build',
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$CoreOnly,
    [switch]$Publish,
    [string]$PayloadDirectory
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $root 'loader\Cargo.toml'
$cargo = (Get-Command cargo.exe -ErrorAction Stop).Source
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Install Visual Studio C++ build tools and a Windows SDK.' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $installation) { throw 'Visual Studio x64 C++ tools were not found.' }
$vsdev = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path -LiteralPath $vsdev)) { throw 'Visual Studio Developer Command Prompt was not found.' }
$temp = Join-Path $root 'build\loader-temp'
New-Item -ItemType Directory -Force -Path $temp | Out-Null
$env:TEMP = $temp
$env:TMP = $temp
$arguments = @($Action.ToLowerInvariant(), '--manifest-path', ('"' + $manifest + '"'), '--locked')
if ($Action -in @('Build', 'Test') -and $Configuration -eq 'Release') { $arguments += '--release' }
if ($CoreOnly) { $arguments += '--no-default-features' }
if ($Action -eq 'Clippy') { $arguments += @('--all-targets', '--', '-D', 'warnings') }
$command = '"' + $vsdev + '" -arch=x64 -host_arch=x64 && "' + $cargo + '" ' + ($arguments -join ' ')
& $env:ComSpec /d /s /c $command
if ($LASTEXITCODE -ne 0) { throw "Rust loader $Action failed with exit code $LASTEXITCODE" }
if (-not $Publish) { return }
if ($Action -ne 'Build') { throw '-Publish requires -Action Build.' }

if (-not $PayloadDirectory) { $PayloadDirectory = Join-Path $root 'build\Release' }
$PayloadDirectory = (Resolve-Path -LiteralPath $PayloadDirectory).Path
$sources = [ordered]@{
    'hyperrev-setup.exe' = Join-Path $root ('loader\target\' + $Configuration.ToLowerInvariant() + '\hyperrev-setup.exe')
}
if (-not $CoreOnly) { $sources['hyperrev-loader.exe'] = Join-Path $root ('loader\target\' + $Configuration.ToLowerInvariant() + '\hyperrev-loader.exe') }
foreach ($name in @('uefi-boot-standalone.efi', 'hyperv-attachment.dll')) {
    $image = Join-Path $PayloadDirectory $name
    $data = [IO.File]::ReadAllBytes($image)
    if ($data.Length -lt 64 -or $data.Length -gt 64MB -or [BitConverter]::ToUInt16($data, 0) -ne 0x5A4D) { throw "Invalid PE image: $name" }
    $offset = [BitConverter]::ToUInt32($data, 60)
    if ($offset -gt ($data.Length - 136) -or [BitConverter]::ToUInt32($data, $offset) -ne 0x4550) { throw "Invalid PE signature: $name" }
    $optionalLength = [BitConverter]::ToUInt16($data, $offset + 20)
    if ($optionalLength -lt 112 -or ([long]$offset + 24 + $optionalLength) -gt $data.Length) { throw "Truncated PE32+ header: $name" }
    if ([BitConverter]::ToUInt16($data, $offset + 4) -ne 0x8664 -or [BitConverter]::ToUInt16($data, $offset + 24) -ne 0x20B) { throw "Expected x64 PE32+ image: $name" }
    if ($name.EndsWith('.efi') -and [BitConverter]::ToUInt16($data, $offset + 92) -ne 10) { throw 'Bundle requires standalone EFI_APPLICATION rather than Windows BOOTAPP.' }
    if ($name.EndsWith('.dll') -and ([BitConverter]::ToUInt16($data, $offset + 22) -band 0x2000) -eq 0) { throw 'Attachment image requires the DLL flag.' }
    $sources[$name] = $image
}
foreach ($sourcePath in $sources.Values) { if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw "Bundle source is missing: $sourcePath" } }

$destinationDirectory = Join-Path $env:LOCALAPPDATA 'hyper-reV\bin'
New-Item -ItemType Directory -Force -Path $destinationDirectory | Out-Null
$destinationDirectory = (Resolve-Path -LiteralPath $destinationDirectory).Path
if ((Get-Item -LiteralPath $destinationDirectory).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'Publish directory is a reparse point.'
}
foreach ($name in $sources.Keys) {
    $source = $sources[$name]
    $destination = [IO.Path]::GetFullPath((Join-Path $destinationDirectory $name))
    if (Test-Path -LiteralPath $destination) {
        $existing = Get-Item -LiteralPath $destination
        if ($existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Publish target is a directory or reparse point.'
        }
    }
    $temporary = [IO.Path]::GetFullPath((Join-Path $destinationDirectory ('.publish-' + [guid]::NewGuid().ToString('N') + '.exe')))
    if ([IO.Path]::GetDirectoryName($temporary) -ne $destinationDirectory -or [IO.Path]::GetDirectoryName($destination) -ne $destinationDirectory) {
        throw 'Publish paths differ from the intended application directory.'
    }
    $bytes = [IO.File]::ReadAllBytes($source)
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    if ($hash -ne (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash) { throw 'Staged publish identity mismatch.' }
    Write-Output "Verified rename source: $temporary"
    Write-Output "Verified rename destination: $destination"
    Move-Item -LiteralPath $temporary -Destination $destination -Force
    if ($hash -ne (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash) { throw 'Published content identity mismatch.' }
    Write-Output "Published $destination"
    Write-Output "SHA256 $hash"
}
