#Requires -RunAsAdministrator
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
& sc.exe stop AntiStealerService | Out-Null
Start-Sleep -Seconds 2
& sc.exe delete AntiStealerService | Out-Null

try {
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $scheduler.GetFolder('\').DeleteTask('AntiStealer',0)
} catch { }

Get-NetFirewallRule -Group 'AntiStealer' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\AntiStealer.lnk'
if (Test-Path -LiteralPath $startMenu) {
    Remove-Item -LiteralPath $startMenu -Force -ErrorAction SilentlyContinue
}
Write-Host 'Служба, задача автозапуска и правила AntiStealer удалены.'
Write-Host 'Карантин, журнал и контрольные суммы в C:\ProgramData\AntiStealer сохранены для восстановления и расследования.'
