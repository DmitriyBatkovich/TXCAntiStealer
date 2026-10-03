namespace AntiStealer;

internal sealed class ProcessFacts
{
    public required int ProcessId { get; init; }
    public required string ProcessName { get; init; }
    public required string FilePath { get; init; }
    public long StartTimeUtcTicks { get; init; }
    public string? ParentName { get; init; }
    public bool IsTrustedSignature { get; init; }
    public string? SignerSubject { get; init; }
    public bool IsHighRiskPath { get; init; }
    public bool IsUserWritablePath { get; init; }
    public bool HasInternetZoneMarker { get; init; }
    public bool IsRecentlyWritten { get; init; }
    public bool LooksRandomNamed { get; init; }
    public bool MasqueradesAsWindows { get; init; }
    public bool HasSuspiciousParent { get; init; }
}

internal sealed class RiskAssessment
{
    public int Score { get; init; }
    public bool ShouldBlock { get; init; }
    public required IReadOnlyList<string> Reasons { get; init; }
}

internal sealed class DetectionEvent
{
    public DateTimeOffset Time { get; init; } = DateTimeOffset.Now;
    public required int ProcessId { get; init; }
    public required string ProcessName { get; init; }
    public required string FilePath { get; init; }
    public required string RemoteEndpoints { get; init; }
    public required string Reasons { get; init; }
    public required int Risk { get; init; }
    public required string FirewallRuleName { get; init; }
    public string Status { get; set; } = "Интернет заблокирован";
}

internal sealed class UserNotification
{
    public DateTimeOffset Time { get; init; } = DateTimeOffset.Now;
    public required string Kind { get; init; }
    public required string Title { get; init; }
    public required string Message { get; init; }
    public DetectionEvent? Detection { get; init; }
}

internal sealed class Candidate
{
    public required ProcessFacts Facts { get; init; }
    public DateTimeOffset FirstSeen { get; init; } = DateTimeOffset.Now;
    public bool Detected { get; set; }
}

internal enum AlertChoice
{
    KeepBlocked,
    Terminate,
    Quarantine,
    Allow
}

internal sealed record SignatureInfo(bool IsTrusted, string? SignerSubject);
