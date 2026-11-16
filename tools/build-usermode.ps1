param(
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$TargetName = 'usermode',
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$LogName = 'usermode-build',
    [string]$MSBuildPath,
    [string]$VcpkgRoot = $env:VCPKG_ROOT,
    [string]$PlatformToolset = 'v143',
    [string]$WindowsSdkVersion = '10.0',
    [switch]$Publish
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $MSBuildPath) {
    $command = Get-Command MSBuild.exe -ErrorAction SilentlyContinue
    if ($command) {
        $MSBuildPath = $command.Source
    } else {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (Test-Path -LiteralPath $vswhere) {
            $installation = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -property installationPath
            if ($LASTEXITCODE -ne 0) { throw 'Visual Studio lookup failed' }
            if ($installation) { $MSBuildPath = Join-Path $installation 'MSBuild\Current\Bin\MSBuild.exe' }
        }
    }
}
if (-not $MSBuildPath -or -not (Test-Path -LiteralPath $MSBuildPath)) {
    throw 'Install Visual Studio C++ build tools or pass -MSBuildPath.'
}
if (-not $VcpkgRoot) { $VcpkgRoot = Join-Path $root 'build\vcpkg\tool' }
if (-not (Test-Path -LiteralPath (Join-Path $VcpkgRoot 'vcpkg.exe'))) {
    throw 'Bootstrap vcpkg first, then pass -VcpkgRoot or set VCPKG_ROOT.'
}
$VcpkgRoot = (Resolve-Path -LiteralPath $VcpkgRoot).Path
foreach ($directory in @('build\logs', 'build\vcpkg\tmp', 'build\vcpkg\downloads', 'build\vcpkg\binarycache', 'build\vcpkg\registries')) {
    New-Item -ItemType Directory -Path (Join-Path $root $directory) -Force | Out-Null
}
$env:TEMP = "$root\build\vcpkg\tmp"
$env:TMP = $env:TEMP
$env:VCPKG_DISABLE_METRICS = '1'
$env:VCPKG_ROOT = $VcpkgRoot
$env:VCPKG_DOWNLOADS = "$root\build\vcpkg\downloads"
$env:VCPKG_DEFAULT_BINARY_CACHE = "$root\build\vcpkg\binarycache"
$env:VCPKG_BINARY_SOURCES = "clear;files,$root\build\vcpkg\binarycache,readwrite"
$env:VCPKG_REGISTRIES_CACHE = "$root\build\vcpkg\registries"
$buildArgs = @(
    '/nologo', '/t:Build', '/m:2', '/v:minimal',
    '/p:Configuration=Release', '/p:Platform=x64', "/p:PlatformToolset=$PlatformToolset",
    "/p:WindowsTargetPlatformVersion=$WindowsSdkVersion",
    "/p:TargetName=$TargetName", "/p:SolutionDir=$root\",
    "/p:ForceImportBeforeCppTargets=$VcpkgRoot\scripts\buildsystems\msbuild\vcpkg.targets",
    "/p:VcpkgRoot=$VcpkgRoot\",
    "/p:VcpkgInstalledDir=$root\usermode\vcpkg_installed\", '/p:VcpkgAutoBootstrap=false',
    "/p:VcpkgAdditionalInstallOptions=--x-buildtrees-root=$root\build\vcpkg\buildtrees --x-packages-root=$root\build\vcpkg\packages --disable-metrics",
    "/bl:$root\build\logs\$LogName.binlog", '/fl',
    "/flp:logfile=$root\build\logs\$LogName.log;verbosity=normal"
)
& $MSBuildPath "$root\usermode\usermode.vcxproj" @buildArgs
if ($LASTEXITCODE -ne 0) { throw "Usermode build failed with exit code $LASTEXITCODE" }
Write-Output "Built $root\build\Release\$TargetName.exe"

if ($Publish) {
    # Fresh files inherit this standard application directory's security rather
    # than the workspace's Low mandatory label. Preserve all workspace permissions.
    $bin = Join-Path $env:LOCALAPPDATA 'hyper-reV\bin'
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
    $source = Join-Path $root "build\Release\$TargetName.exe"
    $destination = Join-Path $bin "$TargetName.exe"
    if (Test-Path -LiteralPath $destination) {
        $existing = Get-Item -LiteralPath $destination
        if ($existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Deployment target is a directory or reparse point'
        }
        Write-Output ('Previous deployment SHA256: ' + (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash)
    }
    $bytes = [IO.File]::ReadAllBytes($source)
    $bin = (Resolve-Path -LiteralPath $bin).Path
    if ((Get-Item -LiteralPath $bin).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Deployment directory is a reparse point'
    }
    $destination = [IO.Path]::GetFullPath((Join-Path $bin "$TargetName.exe"))
    $temporary = [IO.Path]::GetFullPath((Join-Path $bin ('.publish-' + [guid]::NewGuid().ToString('N') + '.exe')))
    if ([IO.Path]::GetDirectoryName($temporary) -ne $bin -or [IO.Path]::GetDirectoryName($destination) -ne $bin) {
        throw 'Publish paths differ from the intended deployment directory'
    }
    # Always create a new file: truncating an existing Low-labeled file would
    # preserve its label. A same-directory rename retains the fresh file's security.
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    if ($sourceHash -ne (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash) {
        throw "Staged deployment hash mismatch; retained $temporary for inspection"
    }
    Write-Output "Verified rename source: $temporary"
    Write-Output "Verified rename destination: $destination"
    Move-Item -LiteralPath $temporary -Destination $destination -Force
    $publishedHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
    if ($sourceHash -ne $publishedHash) { throw 'Published content identity mismatch' }
    Write-Output "Published $destination"
    Write-Output "SHA256 $publishedHash"
}
