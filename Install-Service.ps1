#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramFiles\AntiStealer"
)

$ErrorActionPreference = 'Stop'
$appSource = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'App\AntiStealer.exe')) {
    Join-Path $PSScriptRoot 'App'
} else {
    Join-Path $PSScriptRoot 'dist'
}
$serviceSource = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Service\AntiStealer.Service.exe')) {
    Join-Path $PSScriptRoot 'Service'
} else {
    Join-Path $PSScriptRoot 'service\dist'
}

$dotnet = Get-Command dotnet.exe -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $dotnet) {
    throw 'Не найден .NET Desktop Runtime 9 x64. Установите его с https://dotnet.microsoft.com/download/dotnet/9.0 и повторите установку.'
}
$desktopRuntimes = & $dotnet.Source --list-runtimes
if (-not ($desktopRuntimes | Select-String '^Microsoft\.WindowsDesktop\.App 9\.')) {
    throw 'Нужен .NET Desktop Runtime 9 x64. Установите его с https://dotnet.microsoft.com/download/dotnet/9.0 и повторите установку.'
}
if (-not (Test-Path -LiteralPath (Join-Path $appSource 'AntiStealer.exe'))) {
    throw 'Сначала выполните publish: папка dist с AntiStealer.exe не найдена.'
}
if (-not (Test-Path -LiteralPath (Join-Path $serviceSource 'AntiStealer.Service.exe'))) {
    throw 'Сначала выполните publish службы: service\dist\AntiStealer.Service.exe не найден.'
}

$null = & sc.exe query AntiStealerService 2>$null
$serviceExists = $LASTEXITCODE -eq 0
if ($serviceExists) {
    & sc.exe stop AntiStealerService | Out-Null
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        $state = & sc.exe query AntiStealerService 2>$null | Select-String 'STOPPED'
        if ($state) { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $state) { throw 'Служба не остановилась за 10 секунд; файлы не изменены.' }
}

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
$appTarget = Join-Path $InstallRoot 'App'
$serviceTarget = Join-Path $InstallRoot 'Service'
$serviceExe = Join-Path $serviceTarget 'AntiStealer.Service.exe'
$appExe = Join-Path $appTarget 'AntiStealer.exe'

# An older installed UI keeps its managed DLL loaded. Stop only the UI whose
# executable path is exactly inside this installation, never a development copy.
if (Test-Path -LiteralPath $appExe) {
    $runningInstalledUi = @(Get-Process -Name 'AntiStealer' -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Path -and [string]::Equals([IO.Path]::GetFullPath($_.Path), [IO.Path]::GetFullPath($appExe), [StringComparison]::OrdinalIgnoreCase) }
        catch { $false }
    })
    foreach ($process in $runningInstalledUi) {
        Stop-Process -Id $process.Id -Force -ErrorAction Stop
        $process.WaitForExit(5000)
    }
}

New-Item -ItemType Directory -Path $appTarget,$serviceTarget -Force | Out-Null
Copy-Item -Path (Join-Path $appSource '*') -Destination $appTarget -Recurse -Force
Copy-Item -Path (Join-Path $serviceSource '*') -Destination $serviceTarget -Recurse -Force

function Set-TrustedInstalledBaseline([string]$FilePath) {
    $dataRoot = Join-Path $env:ProgramData 'AntiStealer'
    $baselineFile = Join-Path $dataRoot 'integrity-baseline.json'
    New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
    $items = @()
    if (Test-Path -LiteralPath $baselineFile) {
        try { $items = @((Get-Content -LiteralPath $baselineFile -Raw | ConvertFrom-Json)) } catch { $items = @() }
    }
    $fullPath = [IO.Path]::GetFullPath($FilePath)
    $items = @($items | Where-Object { $_.FilePath -and -not [string]::Equals($_.FilePath, $fullPath, [StringComparison]::OrdinalIgnoreCase) })
    $items += [pscustomobject]@{
        FilePath = $fullPath
        ProcessName = 'AntiStealer'
        Sha256 = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash
        UpdatedAt = [DateTimeOffset]::Now
    }
    ConvertTo-Json -InputObject @($items) -Depth 4 | Set-Content -LiteralPath $baselineFile -Encoding UTF8
}

Set-TrustedInstalledBaseline $appExe
Set-TrustedInstalledBaseline $serviceExe

if ($serviceExists) {
    & sc.exe config AntiStealerService binPath= ('"' + $serviceExe + '"') start= auto DisplayName= 'AntiStealer Protection Service' | Out-Null
} else {
    & sc.exe create AntiStealerService binPath= ('"' + $serviceExe + '"') start= auto DisplayName= 'AntiStealer Protection Service' | Out-Null
}
if ($LASTEXITCODE -ne 0) { throw "Не удалось создать/обновить службу: sc.exe $LASTEXITCODE" }
& sc.exe description AntiStealerService 'Blocks suspicious exfiltration and monitors credential-store access.' | Out-Null
& sc.exe failure AntiStealerService reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null

# GUIDs avoid localization problems: File System, Filtering Platform Connection, Process Creation.
foreach ($subcategory in @(
    '{0CCE921D-69AE-11D9-BED3-505054503030}',
    '{0CCE9226-69AE-11D9-BED3-505054503030}',
    '{0CCE922B-69AE-11D9-BED3-505054503030}'
)) {
    & auditpol.exe /set /subcategory:$subcategory /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Не удалось включить Security Audit ${subcategory}: auditpol.exe $LASTEXITCODE" }
}

& sc.exe start AntiStealerService | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Не удалось запустить службу: sc.exe $LASTEXITCODE" }

$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\AntiStealer.lnk'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($startMenu)
$shortcut.TargetPath = Join-Path $appTarget 'AntiStealer.exe'
$shortcut.WorkingDirectory = $appTarget
$shortcut.Description = 'AntiStealer protection console'
$shortcut.Save()

try {
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $folder = $scheduler.GetFolder('\')
    $definition = $scheduler.NewTask(0)
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $definition.RegistrationInfo.Description = 'AntiStealer notification UI at user logon'
    $definition.Principal.UserId = $user
    $definition.Principal.LogonType = 3
    $definition.Principal.RunLevel = 1
    $definition.Settings.Enabled = $true
    $definition.Settings.StartWhenAvailable = $true
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Settings.ExecutionTimeLimit = 'PT0S'
    $definition.Settings.MultipleInstances = 2
    $trigger = $definition.Triggers.Create(9)
    $trigger.UserId = $user
    $trigger.Enabled = $true
    $action = $definition.Actions.Create(0)
    $action.Path = $appExe
    $action.WorkingDirectory = $appTarget
    $folder.RegisterTaskDefinition('AntiStealer', $definition, 6, $user, $null, 3, $null) | Out-Null
} catch {
    Write-Warning ('Не удалось добавить UI в автозапуск: ' + $_.Exception.Message)
}

try {
    Start-Process -FilePath $appExe -WorkingDirectory $appTarget
} catch {
    Write-Warning ('Не удалось запустить UI уведомлений: ' + $_.Exception.Message)
}

Write-Host "AntiStealer.Service установлена и запущена. UI: $appTarget\AntiStealer.exe"
Write-Host 'Ярлык AntiStealer добавлен в меню Пуск.'
Write-Host 'Компактные уведомления будут запускаться вместе со входом пользователя.'
Write-Host 'Minifilter устанавливается отдельно и только после production-подписи Microsoft.'
