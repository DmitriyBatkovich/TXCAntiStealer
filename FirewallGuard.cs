namespace AntiStealer;

internal static class FirewallGuard
{
    private static readonly (int Id, string Name)[] Profiles =
    [
        (1, "доменный"),
        (2, "частный"),
        (4, "публичный")
    ];

    public static IReadOnlyList<string> CheckAndRepair()
    {
        var repaired = new List<string>();
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
                         ?? throw new InvalidOperationException("Windows Firewall API недоступен");
        dynamic policy = Activator.CreateInstance(policyType)!;

        foreach (var profile in Profiles)
        {
            bool enabled = policy.FirewallEnabled[profile.Id];
            if (enabled)
                continue;

            policy.FirewallEnabled[profile.Id] = true;
            repaired.Add($"Брандмауэр был отключён ({profile.Name} профиль). AntiStealer включил его обратно.");
        }

        return repaired;
    }
}
