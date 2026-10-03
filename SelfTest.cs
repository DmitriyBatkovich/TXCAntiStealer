namespace AntiStealer;

internal static class SelfTest
{
    public static int Run()
    {
        var failures = new List<string>();

        var stealer = RiskScorer.Assess(Facts(
            trusted: false, highRisk: true, userWritable: true, recent: true,
            random: true, internetMark: true), true);
        if (!stealer.ShouldBlock || stealer.Score < RiskScorer.BlockThreshold)
            failures.Add("опасный процесс не был помечен для блокировки");

        var signedUpdate = RiskScorer.Assess(Facts(
            trusted: true, highRisk: true, userWritable: true, recent: true), true);
        if (signedUpdate.ShouldBlock)
            failures.Add("подписанное обновление ошибочно заблокировано");

        var developerBuild = RiskScorer.Assess(Facts(
            trusted: false, highRisk: false, userWritable: true, recent: true), true);
        if (developerBuild.ShouldBlock)
            failures.Add("обычная локальная dev-сборка ошибочно заблокирована");

        try { _ = NativeNetwork.GetOutboundConnections(); }
        catch (Exception ex) { failures.Add("перечисление TCP-соединений: " + ex.Message); }

        var signedChrome = Facts(trusted: true, highRisk: false, userWritable: false, recent: false).WithName("chrome", "CN=Google LLC");
        if (!SensitiveTargetPolicy.IsLegitimateOwner(@"C:\Users\Test\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies", signedChrome))
            failures.Add("подписанный Chrome не распознан владельцем своего хранилища");
        if (SensitiveTargetPolicy.IsLegitimateOwner(@"C:\Users\Test\AppData\Roaming\Telegram Desktop\tdata\key_data", signedChrome))
            failures.Add("Chrome ошибочно получил доступ к Telegram tdata");
        var wrongPublisherChrome = Facts(trusted: true, highRisk: false, userWritable: false, recent: false).WithName("chrome", "CN=Unrelated Publisher LLC");
        if (SensitiveTargetPolicy.IsLegitimateOwner(@"C:\Users\Test\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies", wrongPublisherChrome))
            failures.Add("подписанный посторонним издателем chrome.exe ошибочно признан владельцем хранилища");

        var signedProxifier = Facts(trusted: true, highRisk: false, userWritable: false, recent: false).WithName("Proxifier", "CN=Initex Software OÜ");
        if (!TrustedToolsPolicy.IsBuiltInTrustedTool(signedProxifier))
            failures.Add("официальный подписанный Proxifier не попал в безопасное исключение");
        var fakeProxifier = Facts(trusted: false, highRisk: true, userWritable: true, recent: true).WithName("Proxifier", null);
        if (TrustedToolsPolicy.IsBuiltInTrustedTool(fakeProxifier))
            failures.Add("неподписанный Proxifier ошибочно попал в исключение");

        const string auditXml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><EventData><Data Name='ProcessId'>0x4D2</Data><Data Name='ObjectName'>C:\\Users\\Test\\Cookies</Data></EventData></Event>";
        try
        {
            var fields = AuditEventParser.ReadFields(auditXml);
            if (!AuditEventParser.TryParsePid(fields["ProcessId"], out var parsedPid) || parsedPid != 1234)
                failures.Add("PID из Security Audit разобран неверно");
        }
        catch (Exception ex) { failures.Add("разбор Security Audit XML: " + ex.Message); }

        try
        {
            if (Environment.ProcessPath is { } host && File.Exists(host) && !SignatureVerifier.IsTrusted(host))
                failures.Add("подпись установленного .NET host не прошла WinVerifyTrust");
        }
        catch (Exception ex) { failures.Add("проверка подписи: " + ex.Message); }

        var integrityTestRoot = Path.Combine(Path.GetTempPath(), "AntiStealer-SelfTest-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(integrityTestRoot);
            var developmentExe = Path.Combine(integrityTestRoot, "AntiStealer.exe");
            File.WriteAllText(developmentExe, "build-one");
            var integrity = new IntegrityGuard(integrityTestRoot);
            integrity.RegisterSelf(developmentExe);
            File.WriteAllText(developmentExe, "build-two");
            integrity.RegisterSelf(developmentExe);
            if (integrity.CheckKnownFiles().Count != 0)
                failures.Add("пересобранная локальная dev-копия AntiStealer ошибочно признана подменой");
        }
        catch (Exception ex) { failures.Add("контроль обновления локальной сборки: " + ex.Message); }
        finally
        {
            try { Directory.Delete(integrityTestRoot, recursive: true); } catch { }
        }

        if (failures.Count == 0)
        {
            Console.WriteLine("SELF_TEST_OK");
            return 0;
        }

        Console.WriteLine("SELF_TEST_FAILED");
        foreach (var failure in failures)
            Console.WriteLine("- " + failure);
        return 1;
    }

    private static ProcessFacts Facts(
        bool trusted,
        bool highRisk,
        bool userWritable,
        bool recent,
        bool random = false,
        bool internetMark = false) => new()
    {
        ProcessId = 123,
        ProcessName = random ? "a92be30c810fde" : "sample",
        FilePath = @"C:\Users\Test\sample.exe",
        IsTrustedSignature = trusted,
        SignerSubject = trusted ? "CN=Test Publisher" : null,
        IsHighRiskPath = highRisk,
        IsUserWritablePath = userWritable,
        IsRecentlyWritten = recent,
        LooksRandomNamed = random,
        HasInternetZoneMarker = internetMark,
        MasqueradesAsWindows = false,
        HasSuspiciousParent = false
    };

    private static ProcessFacts WithName(this ProcessFacts source, string name, string? signer) => new()
    {
        ProcessId = source.ProcessId,
        ProcessName = name,
        FilePath = source.FilePath,
        ParentName = source.ParentName,
        IsTrustedSignature = source.IsTrustedSignature,
        SignerSubject = signer,
        IsHighRiskPath = source.IsHighRiskPath,
        IsUserWritablePath = source.IsUserWritablePath,
        HasInternetZoneMarker = source.HasInternetZoneMarker,
        IsRecentlyWritten = source.IsRecentlyWritten,
        LooksRandomNamed = source.LooksRandomNamed,
        MasqueradesAsWindows = source.MasqueradesAsWindows,
        HasSuspiciousParent = source.HasSuspiciousParent
    };
}
