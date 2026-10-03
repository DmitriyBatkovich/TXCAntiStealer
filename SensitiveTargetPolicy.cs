namespace AntiStealer;

internal static class SensitiveTargetPolicy
{
    private static readonly HashSet<string> WindowsCredentialProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "lsass", "services", "svchost", "winlogon", "credentialuibroker", "logonui"
    };

    public static bool IsSensitivePath(string path)
    {
        var normalized = path.Replace('/', '\\');
        return Contains(normalized, @"\Google\Chrome\User Data\") ||
               Contains(normalized, @"\Microsoft\Edge\User Data\") ||
               Contains(normalized, @"\Mozilla\Firefox\Profiles\") ||
               Contains(normalized, @"\Telegram Desktop\tdata\") ||
               Contains(normalized, @"\discord\Local Storage\leveldb\") ||
               Contains(normalized, @"\Steam\config\") ||
               (Contains(normalized, @"\Steam\") && Contains(normalized, @"\ssfn")) ||
               Contains(normalized, @"\Microsoft\Credentials\") ||
               Contains(normalized, @"\Microsoft\Protect\") ||
               Contains(normalized, @"\Exodus\exodus.wallet\") ||
               Contains(normalized, @"\Electrum\wallets\") ||
               Contains(normalized, @"\nkbihfbeogaeaoehlefnkodbefgpgknn\");
    }

    public static bool IsLegitimateOwner(string targetPath, ProcessFacts process)
    {
        if (!process.IsTrustedSignature)
            return false;

        var path = targetPath.Replace('/', '\\');
        var name = process.ProcessName;

        if (Contains(path, @"\Google\Chrome\User Data\"))
            return name.Equals("chrome", StringComparison.OrdinalIgnoreCase) && SignerContains(process, "Google LLC");
        if (Contains(path, @"\Microsoft\Edge\User Data\"))
            return name.Equals("msedge", StringComparison.OrdinalIgnoreCase) && SignerContains(process, "Microsoft Corporation");
        if (Contains(path, @"\Mozilla\Firefox\Profiles\"))
            return name.Equals("firefox", StringComparison.OrdinalIgnoreCase) && SignerContains(process, "Mozilla Corporation");
        if (Contains(path, @"\Telegram Desktop\tdata\"))
            return name.Equals("telegram", StringComparison.OrdinalIgnoreCase) &&
                   (SignerContains(process, "Telegram FZ-LLC") || SignerContains(process, "Telegram Messenger"));
        if (Contains(path, @"\discord\Local Storage\leveldb\"))
            return name.StartsWith("discord", StringComparison.OrdinalIgnoreCase) && SignerContains(process, "Discord Inc");
        if (Contains(path, @"\Steam\config\") ||
            (Contains(path, @"\Steam\") && Contains(path, @"\ssfn")))
            return (name.Equals("steam", StringComparison.OrdinalIgnoreCase) || name.Equals("steamwebhelper", StringComparison.OrdinalIgnoreCase)) &&
                   (SignerContains(process, "Valve Corp") || SignerContains(process, "Valve Corporation"));
        if (Contains(path, @"\Exodus\exodus.wallet\"))
            return name.StartsWith("exodus", StringComparison.OrdinalIgnoreCase) && SignerContains(process, "Exodus Movement");
        if (Contains(path, @"\Electrum\wallets\"))
            return false; // Publisher identity is not stable; the user must trust an exact SHA-256.

        if (Contains(path, @"\Microsoft\Credentials\") || Contains(path, @"\Microsoft\Protect\"))
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
            return WindowsCredentialProcesses.Contains(name) &&
                   process.FilePath.StartsWith(windows, StringComparison.OrdinalIgnoreCase) &&
                   SignerContains(process, "Microsoft Windows");
        }

        // MetaMask and similar browser-extension stores may only be read by the signed owning browser.
        if (Contains(path, @"\nkbihfbeogaeaoehlefnkodbefgpgknn\"))
            return (name.Equals("chrome", StringComparison.OrdinalIgnoreCase) && SignerContains(process, "Google LLC")) ||
                   (name.Equals("msedge", StringComparison.OrdinalIgnoreCase) && SignerContains(process, "Microsoft Corporation")) ||
                   (name.Equals("brave", StringComparison.OrdinalIgnoreCase) && SignerContains(process, "Brave Software")) ||
                   (name.Equals("opera", StringComparison.OrdinalIgnoreCase) && SignerContains(process, "Opera Norway"));

        return false;
    }

    private static bool Contains(string path, string fragment) =>
        path.Contains(fragment, StringComparison.OrdinalIgnoreCase);

    private static bool SignerContains(ProcessFacts process, string publisher) =>
        process.SignerSubject?.Contains(publisher, StringComparison.OrdinalIgnoreCase) == true;
}
