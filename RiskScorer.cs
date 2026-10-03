namespace AntiStealer;

internal static class RiskScorer
{
    internal const int BlockThreshold = 100;

    public static RiskAssessment Assess(ProcessFacts facts, bool hasOutboundConnection)
    {
        var score = 0;
        var reasons = new List<string>();

        if (!facts.IsTrustedSignature)
        {
            score += 40;
            reasons.Add("нет доверенной цифровой подписи");
        }

        if (facts.IsHighRiskPath)
        {
            score += 35;
            reasons.Add("запуск из Temp, Downloads или AppData\\Roaming");
        }
        else if (facts.IsUserWritablePath)
        {
            score += 10;
            reasons.Add("запуск из пользовательской папки");
        }

        if (hasOutboundConnection)
        {
            score += 25;
            reasons.Add("установлено внешнее TCP-соединение");
        }

        if (facts.IsRecentlyWritten)
        {
            score += 15;
            reasons.Add("исполняемый файл появился недавно");
        }

        if (facts.HasInternetZoneMarker)
        {
            score += 20;
            reasons.Add("Windows пометила файл как загруженный из интернета");
        }

        if (facts.LooksRandomNamed)
        {
            score += 15;
            reasons.Add("имя файла похоже на случайно сгенерированное");
        }

        if (facts.MasqueradesAsWindows)
        {
            score += 50;
            reasons.Add("маскируется под системный процесс вне папки Windows");
        }

        if (facts.HasSuspiciousParent)
        {
            score += 30;
            reasons.Add($"запущен через {facts.ParentName}");
        }

        var strongSignal = facts.IsHighRiskPath || facts.HasInternetZoneMarker ||
                           facts.MasqueradesAsWindows || facts.HasSuspiciousParent;

        return new RiskAssessment
        {
            Score = score,
            Reasons = reasons,
            ShouldBlock = hasOutboundConnection && strongSignal && score >= BlockThreshold
        };
    }
}
