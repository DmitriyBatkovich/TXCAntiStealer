# AntiStealer 0.3.3

> **Development status:** the user-mode application and LocalSystem service are functional, but the minifilter is an unsigned review prototype. The altitude `385201` is a placeholder requested from Microsoft and must not be used for distribution until Microsoft assigns an altitude and signs the production driver package.

## Overview (English)

AntiStealer is a Windows defense-in-depth prototype designed to detect and contain credential-stealing malware. It combines a LocalSystem service, Security Audit events, process and Authenticode inspection, Windows Firewall containment, executable integrity baselines, and a WDK file-system minifilter.

The minifilter registers for `IRP_MJ_CREATE` and examines user-mode read opens against a policy supplied by the service through a Filter Manager communication port. For a matching path it sends the requestor PID, requested access, target category, and normalized path to the service. The service replies allow/deny after evaluating process identity, signature, expected publisher, allowlist, and legitimate ownership of the credential store. The driver never modifies file contents.

Protected targets include selected browser cookie/login stores, Telegram `tdata`, Discord LevelDB, Steam configuration/session files, DPAPI locations, and wallet directories. When the service is unavailable or a decision times out after 1.5 seconds, the minifilter fails open to avoid making Windows unbootable. Kernel code does not perform networking, certificate validation, or hard-code credential paths.

### Repository layout

- `driver/` — WDK minifilter source, INF, shared protocol, and reproducible build script.
- `service/` — LocalSystem service, Security Audit subscriber, and Filter Manager port client.
- root C# sources — WinForms UI and shared behavioral detection/containment engine.
- `ProtectedPaths.json` — user-mode path policy sent to the minifilter.
- `DRIVER-RELEASE.md` — altitude, signing, verification, and production-release checklist.
- `THREAT_MODEL.md` — security boundaries and known limitations.

### Minifilter registration request

- Binary: `AntiStealerFilter.sys`
- Filter type: `FileSystem`
- Start type: `Demand`
- Requested load-order group: `FSFilter Activity Monitor`
- Requested altitude: `385201` (Microsoft may assign another altitude or group)

No production driver binary or signing material is stored in this repository. Build output is intentionally ignored.

## Русская документация

Локальная многоуровневая защита Windows от стилеров, подмены EXE и отправки украденных сессий. Никакой телеметрии и облачной передачи данных нет.

## Архитектура

1. **Windows-служба** работает как LocalSystem и не зависит от открытого окна.
2. **Security Audit** подписывается на 4663 (доступ к файлам), 4688 (процесс), 5156 (соединение) и события изменения Windows Firewall. SACL ставится только на каталоги с секретами.
3. **Поведенческий движок** сопоставляет PID, TCP, подпись, путь запуска, родителя, метку загрузки и свежесть файла.
4. **Integrity Guard** хранит SHA-256 браузеров, Telegram, Steam, Discord и AntiStealer. Подписанные обновления принимаются, неподписанная подмена блокируется.
5. **Firewall Guard** включает обратно отключённые профили и восстанавливает удалённые блокирующие правила.
6. **Minifilter** перехватывает чтение cookie, login data, Telegram `tdata`, Discord LevelDB, Steam config/ssfn, DPAPI и кошельков до открытия файла. Защищённые пути загружает служба по двустороннему порту; в ядре нет строк с секретами. Жёсткий тайм-аут первого решения — 1,5 с; при недоступной службе драйвер fail-open, чтобы не сломать загрузку Windows.
7. **TXC UI** использует чёрно-жёлтую тему и объёмную янтарную эмблему, показывает компактные карточки тревоги и сворачивания в трей, карантин, журнал, ручное доверие по SHA-256 и управляет сканированием службы. Контекстное меню в трее следует светлой или тёмной системной теме Windows. Щелчок по карточке открывает подробности, а сам UI автоматически запускается при входе пользователя.

Список файловых правил хранится в `ProtectedPaths.json` рядом со службой и при установке попадает в защищённую ACL каталога `%ProgramFiles%\AntiStealer`. Владелец хранилища определяется не по одному имени EXE: проверяются действительная цепочка Authenticode и ожидаемый издатель (Google, Microsoft, Mozilla, Telegram, Discord, Valve и т. д.).

## Сборка и установка службы

Требуется установленный .NET Desktop Runtime 9. Java, JDK и Node.js не нужны.

```powershell
dotnet publish -c Release --no-restore -o .\dist
dotnet publish .\service\AntiStealer.Service.csproj -c Release --no-restore -o .\service\dist
powershell -ExecutionPolicy Bypass -File .\Install-Service.ps1
```

Скрипт копирует файлы в `%ProgramFiles%\AntiStealer`, включает необходимые категории Security Audit по GUID, создаёт службу с автоматическим перезапуском и запускает её. Карантин и журналы находятся в `%ProgramData%\AntiStealer`.

Без установки службы `AntiStealer.exe` продолжает работать в пользовательском режиме и может запускаться через Task Scheduler.

## Доверенные сетевые инструменты

- Proxifier автоматически исключается только при валидной Authenticode-подписи издателя Initex. Простое имя `Proxifier.exe` ничего не разрешает.
- TG WS Proxy и другие portable-инструменты добавляются кнопкой **«Доверять файлу…»**. Разрешается только текущий SHA-256; после изменения/обновления подтверждение потребуется снова.
- Не добавляйте в исключения repack/crack-сборки. Используйте официальный установщик Proxifier с `proxifier.com`.

## Minifilter

Исходники находятся в `driver`. Для воспроизводимой x64-сборки запустите `driver\Build-Driver.ps1`: скрипт использует установленные Visual Studio C++/WDK, компилирует с `/W4 /WX`, включает CFG/Spectre-защиту, создаёт каталог через Inf2Cat и сканирует пакет Microsoft Defender. Проверенная development-сборка находится в `driver\build\package`.

Development-пакет, создаваемый локально, намеренно не подписан, а INF всё ещё содержит временную altitude `385201`: такой пакет устанавливать нельзя. Production-драйвер требует назначенной Microsoft altitude и подписи через Hardware Dev Center. `Install-ProductionDriver.ps1` отказывается устанавливать неподписанный драйвер, временную altitude и не предлагает отключать Secure Boot. Порядок выпуска описан в `DRIVER-RELEASE.md`.

## Проверка

```powershell
dotnet .\dist\AntiStealer.dll --self-test
dotnet .\service\dist\AntiStealer.Service.dll --self-test
```

Обе .NET-сборки компилируются с `TreatWarningsAsErrors=true`. Перед выдачей папки `dist` сканируются Microsoft Defender.

## Границы защиты

AntiStealer дополняет, а не заменяет Microsoft Defender. Подписанный minifilter существенно сужает окно кражи файлов, но не может гарантированно остановить код, уже внедрённый внутрь доверенного браузера, компрометацию ядра/прошивки или использование уже украденной удалённой сессии. Подробности — в `THREAT_MODEL.md`.
