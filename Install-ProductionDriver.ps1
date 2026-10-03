#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PackageDirectory
)

$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
$sys = Join-Path $package 'AntiStealerFilter.sys'
$inf = Join-Path $package 'AntiStealerFilter.inf'
$cat = Join-Path $package 'AntiStealerFilter.cat'
foreach ($required in @($sys,$inf,$cat)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Отсутствует файл пакета: $required" }
}

$infText = Get-Content -LiteralPath $inf -Raw
if ($infText -match '"385201"') {
    throw 'INF всё ещё содержит временную altitude 385201. Получите назначенную Microsoft altitude перед установкой.'
}

$catalogSignature = Get-AuthenticodeSignature -LiteralPath $cat
if ($catalogSignature.Status -ne 'Valid') {
    throw "Каталог драйвера не имеет действительной production-подписи: $($catalogSignature.Status). Отключать Secure Boot или проверку подписи запрещено."
}

$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
if (-not $signtool) {
    $signtool = Get-ChildItem -LiteralPath 'C:\Program Files (x86)\Windows Kits\10\bin' -Filter signtool.exe -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $signtool) { throw 'signtool.exe не найден; установите WDK.' }
& $signtool verify /kp /c $cat $sys
if ($LASTEXITCODE -ne 0) { throw 'Каталог не подтверждает SYS в режиме kernel policy.' }

& pnputil.exe /add-driver $inf /install
if ($LASTEXITCODE -ne 0) { throw "pnputil завершился с кодом $LASTEXITCODE" }
& fltmc.exe load AntiStealerFilter
if ($LASTEXITCODE -ne 0) { throw "fltmc завершился с кодом $LASTEXITCODE" }
Write-Host 'Подписанный AntiStealerFilter установлен и загружен.'
