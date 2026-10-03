# Выпуск AntiStealerFilter

Папка `driver\build\package` генерируется локально скриптом сборки и содержит проверенный, но **неподписанный** development-пакет. Она исключена из Git и нужна для локального аудита и последующей отправки в Microsoft, а не для установки на основной компьютер.

## Обязательные шаги

1. Запросить у Microsoft собственную altitude для `AntiStealerFilter.sys`. Текущая группа в INF — `FSFilter Activity Monitor`, временная altitude — `385201`. Microsoft может назначить другую группу или высоту. Официальная инструкция: <https://learn.microsoft.com/windows-hardware/drivers/ifs/minifilter-altitude-request>.
2. Заменить `385201` в `driver\AntiStealerFilter.inf` на выданное значение и снова выполнить `driver\Build-Driver.ps1`.
3. Зарегистрироваться в Hardware Dev Center с EV code-signing certificate. Для Windows Client доступна attestation-подпись; для полноценного production-релиза Microsoft рекомендует HLK/dashboard signing: <https://learn.microsoft.com/windows-hardware/drivers/dashboard/driver-signing-offerings>.
4. Отправить пакет и использовать возвращённый Microsoft подписанный каталог/драйвер. Для Windows 10 1607+ новый kernel-mode драйвер должен быть подписан Microsoft: <https://learn.microsoft.com/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later->.
5. Проверить пакет командой `signtool verify /kp /c AntiStealerFilter.cat AntiStealerFilter.sys`.
6. Только после успешной проверки запустить от администратора:

   ```powershell
   .\Install-ProductionDriver.ps1 -PackageDirectory .\driver\build\package
   ```

Скрипт установки специально отклоняет временную altitude, неподписанный каталог и пакет, который не проходит kernel-policy verification.

## Чего делать нельзя

- отключать Secure Boot или Driver Signature Enforcement;
- добавлять драйвер или папку сборки в исключения Defender;
- устанавливать тестовый сертификат в доверенные корни основной Windows;
- использовать случайную altitude вместо назначенной Microsoft.

Тест-загрузку, Driver Verifier и стресс-тесты файловой системы выполняйте только в отдельной виртуальной машине со снимком. Kernel-драйвер нельзя считать production-ready только на основании успешной компиляции.
