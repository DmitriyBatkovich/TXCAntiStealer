using System.Security.Cryptography;
using System.Text;

namespace AntiStealer;

internal static class FirewallBlocker
{
    public static string Block(string filePath)
    {
        var ruleName = RuleName(filePath);
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
                         ?? throw new InvalidOperationException("Windows Firewall API недоступен");
        var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule")
                       ?? throw new InvalidOperationException("Windows Firewall rule API недоступен");
        dynamic policy = Activator.CreateInstance(policyType)!;

        try { policy.Rules.Remove(ruleName); } catch { }

        dynamic rule = Activator.CreateInstance(ruleType)!;
        rule.Name = ruleName;
        rule.Description = "Автоматическая блокировка AntiStealer: подозрительная программа";
        rule.ApplicationName = Path.GetFullPath(filePath);
        rule.Protocol = 256; // NET_FW_IP_PROTOCOL_ANY
        rule.Direction = 2;  // NET_FW_RULE_DIR_OUT
        rule.Action = 0;     // NET_FW_ACTION_BLOCK
        rule.Enabled = true;
        rule.Profiles = int.MaxValue;
        rule.Grouping = "AntiStealer";
        policy.Rules.Add(rule);
        return ruleName;
    }

    public static void Remove(string ruleName)
    {
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
        if (policyType is null)
            return;
        dynamic policy = Activator.CreateInstance(policyType)!;
        try { policy.Rules.Remove(ruleName); } catch { }
    }

    public static void RemoveForPath(string filePath)
    {
        if (!string.IsNullOrWhiteSpace(filePath))
            Remove(RuleName(filePath));
    }

    public static bool Exists(string ruleName)
    {
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
        if (policyType is null)
            return false;
        dynamic policy = Activator.CreateInstance(policyType)!;
        try
        {
            dynamic rule = policy.Rules.Item(ruleName);
            return rule is not null && rule.Enabled;
        }
        catch
        {
            return false;
        }
    }

    private static string RuleName(string filePath)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(filePath).ToUpperInvariant()));
        return $"AntiStealer_Block_{Convert.ToHexString(bytes)[..12]}";
    }
}
