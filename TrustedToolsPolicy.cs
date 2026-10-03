namespace AntiStealer;

internal static class TrustedToolsPolicy
{
    private static readonly HashSet<string> ProxifierNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Proxifier", "Proxifier64", "ProxyChecker"
    };

    public static bool IsBuiltInTrustedTool(ProcessFacts facts)
    {
        if (!facts.IsTrustedSignature || string.IsNullOrWhiteSpace(facts.SignerSubject))
            return false;

        // Имя само по себе не является исключением. Нужна валидная Authenticode-подпись Initex.
        return ProxifierNames.Contains(facts.ProcessName) &&
               facts.SignerSubject.Contains("Initex", StringComparison.OrdinalIgnoreCase);
    }
}
