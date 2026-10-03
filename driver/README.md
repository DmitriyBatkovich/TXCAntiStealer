# AntiStealer minifilter

## English summary

This WDK minifilter registers a pre-create callback for `IRP_MJ_CREATE`. For user-mode read opens that match the policy supplied by the AntiStealer service, it sends the requestor PID, access mask, target category, and normalized path to the service over the Filter Manager communication port. The service returns an allow/deny verdict. The driver never modifies file contents, fails open if the service is absent, and applies a 1.5-second decision timeout.

The INF currently contains the requested placeholder altitude `385201` in the `FSFilter Activity Monitor` group. Do not install or distribute the driver until Microsoft assigns an altitude and the package receives a production Microsoft signature.

WDK minifilter, который перехватывает `IRP_MJ_CREATE` с правами чтения для защищённых хранилищ. После подключения служба загружает до 32 правил пути через `FilterSendMessage`; перед открытием совпавшего файла драйвер отправляет PID и путь службе через `\\AntiStealerPort`. Служба проверяет цепочку Authenticode, конкретного издателя и владельца хранилища, затем отвечает `allow/deny`.

## Безопасное поведение

- тайм-аут решения — не более 1,5 с, а сведения об уже проверенных процессах кэшируются службой;
- при недоступной службе драйвер работает fail-open, чтобы не заблокировать загрузку Windows;
- в ядре нет проверки сертификатов, хешей, сети и статического списка секретов — это делает служба;
- драйвер не скрывает процессы, файлы и события и не перехватывает ввод;
- отключать Secure Boot или принудительную проверку подписи для установки нельзя.

## Что требуется для сборки

- Visual Studio 2022 с Desktop development with C++;
- Windows Driver Kit 10/11, совпадающий с Windows SDK;
- запуск `Build-Driver.ps1` или сборка `AntiStealerFilter.vcxproj`, конфигурация `Release|x64`.

Проверенная сборка выполнена WDK `10.0.28000.0`, SDK headers `10.0.26100.0` и MSVC `14.44.35207`. `Inf2Cat` завершился без ошибок/предупреждений, Microsoft Defender не обнаружил угроз в итоговом пакете.

## Production-подпись

Значение altitude `385201` в INF является временным для разработки. Перед распространением нужно получить собственную altitude у Microsoft, пройти аудит/HLK или attestation signing через Hardware Dev Center и выпустить подписанный каталог. Неподписанный `.sys` установочный скрипт принимать не должен.
