[CmdletBinding()]
param(
    [ValidateSet('Release')]
    [string]$Configuration = 'Release',
    [switch]$SkipDefenderScan
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-LatestVersionDirectory([string]$Root, [scriptblock]$Predicate) {
    $result = Get-ChildItem -LiteralPath $Root -Directory -ErrorAction Stop |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+' -and (& $Predicate $_) } |
        Sort-Object { [version](($_.Name -split '-', 2)[0]) } -Descending |
        Select-Object -First 1
    if ($null -eq $result) {
        throw "Не найдена подходящая версия в $Root"
    }
    return $result
}

$driverRoot = $PSScriptRoot
$releaseRoot = Join-Path $driverRoot "build\$Configuration\x64"
$packageRoot = Join-Path $driverRoot 'build\package'
New-Item -ItemType Directory -Force -Path $releaseRoot, $packageRoot | Out-Null

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'vswhere.exe не найден. Установите Visual Studio 2022 с C++ Build Tools.'
}
$vsRoot = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if ([string]::IsNullOrWhiteSpace($vsRoot)) {
    throw 'Visual Studio 2022 с компилятором x64 не найдена.'
}
$vcVersion = Get-LatestVersionDirectory (Join-Path $vsRoot 'VC\Tools\MSVC') {
    param($directory)
    Test-Path -LiteralPath (Join-Path $directory.FullName 'bin\Hostx64\x64\cl.exe')
}
$cl = Join-Path $vcVersion.FullName 'bin\Hostx64\x64\cl.exe'
$link = Join-Path $vcVersion.FullName 'bin\Hostx64\x64\link.exe'

$kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$wdkVersion = Get-LatestVersionDirectory (Join-Path $kitsRoot 'Include') {
    param($directory)
    (Test-Path -LiteralPath (Join-Path $directory.FullName 'km\fltKernel.h')) -and
        (Test-Path -LiteralPath (Join-Path $kitsRoot "Lib\$($directory.Name)\km\x64\FltMgr.lib"))
}
$sdkVersion = Get-LatestVersionDirectory (Join-Path $kitsRoot 'Include') {
    param($directory)
    (Test-Path -LiteralPath (Join-Path $directory.FullName 'shared\ntdef.h')) -and
        (Test-Path -LiteralPath (Join-Path $directory.FullName 'ucrt\stdlib.h'))
}

$object = Join-Path $releaseRoot 'AntiStealerFilter.obj'
$pdb = Join-Path $releaseRoot 'AntiStealerFilter.pdb'
$sys = Join-Path $releaseRoot 'AntiStealerFilter.sys'
$compileArguments = @(
    '/nologo', '/c', '/W4', '/WX', '/wd4324', '/O2', '/Oi', '/Gy', '/GS', '/sdl',
    '/kernel', '/Zp8', '/FC', '/guard:cf', '/Qspectre',
    '/D_AMD64_', '/D_WIN64', '/DNTDDI_VERSION=0x0A000008', '/D_WIN32_WINNT=0x0A00',
    ('/I' + (Join-Path $vcVersion.FullName 'include')),
    ('/I' + (Join-Path $wdkVersion.FullName 'km')),
    ('/I' + (Join-Path $wdkVersion.FullName 'shared')),
    ('/I' + (Join-Path $sdkVersion.FullName 'km')),
    ('/I' + (Join-Path $sdkVersion.FullName 'shared')),
    ('/I' + (Join-Path $sdkVersion.FullName 'ucrt')),
    ('/Fo' + $object), ('/Fd' + $pdb),
    (Join-Path $driverRoot 'AntiStealerFilter.c')
)
& $cl @compileArguments
if ($LASTEXITCODE -ne 0) { throw "cl.exe завершился с кодом $LASTEXITCODE" }

$wdkLibraries = Join-Path $kitsRoot "Lib\$($wdkVersion.Name)\km\x64"
$sdkLibraries = Join-Path $kitsRoot "Lib\$($sdkVersion.Name)\km\x64"
$linkArguments = @(
    '/nologo', '/driver', '/subsystem:native,10.00', '/entry:GsDriverEntry', '/incremental:no',
    '/opt:ref', '/opt:icf', '/merge:_TEXT=.text', '/section:INIT,d', '/nodefaultlib',
    '/guard:cf', '/WX', ('/libpath:' + $wdkLibraries), ('/libpath:' + $sdkLibraries),
    ('/out:' + $sys), ('/pdb:' + $pdb), $object,
    'FltMgr.lib', 'ntoskrnl.lib', 'BufferOverflowFastFailK.lib'
)
& $link @linkArguments
if ($LASTEXITCODE -ne 0) { throw "link.exe завершился с кодом $LASTEXITCODE" }
if (-not (Test-Path -LiteralPath $sys)) { throw 'Драйвер не появился после линковки.' }

Copy-Item -LiteralPath (Join-Path $driverRoot 'AntiStealerFilter.inf') -Destination $packageRoot -Force
Copy-Item -LiteralPath $sys -Destination $packageRoot -Force
$inf2Cat = Join-Path $kitsRoot "bin\$($wdkVersion.Name)\x86\Inf2Cat.exe"
if (-not (Test-Path -LiteralPath $inf2Cat)) { throw "Inf2Cat.exe не найден: $inf2Cat" }
& $inf2Cat ('/driver:' + $packageRoot) '/os:10_X64,10_VB_X64,10_CO_X64,10_NI_X64,10_GE_X64'
if ($LASTEXITCODE -ne 0) { throw "Inf2Cat завершился с кодом $LASTEXITCODE" }

if (-not $SkipDefenderScan) {
    $platformRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
    $defenderPlatform = Get-LatestVersionDirectory $platformRoot {
        param($directory)
        Test-Path -LiteralPath (Join-Path $directory.FullName 'MpCmdRun.exe')
    }
    & (Join-Path $defenderPlatform.FullName 'MpCmdRun.exe') -Scan -ScanType 3 -File $packageRoot -DisableRemediation
    if ($LASTEXITCODE -ne 0) { throw "Microsoft Defender отклонил пакет (код $LASTEXITCODE)." }
}

$hash = (Get-FileHash -LiteralPath $sys -Algorithm SHA256).Hash
Write-Host "DRIVER_BUILD_OK"
Write-Host "WDK: $($wdkVersion.Name); SDK headers: $($sdkVersion.Name); MSVC: $($vcVersion.Name)"
Write-Host "SYS: $sys"
Write-Host "SHA256: $hash"
Write-Warning 'Пакет не подписан. Не устанавливайте его до получения Microsoft-assigned altitude и production-подписи каталога.'
