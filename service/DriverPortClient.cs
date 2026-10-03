using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace AntiStealer;

internal sealed class DriverPortClient : IDisposable
{
    private const string PortName = "\\AntiStealerPort";
    private const int MaxPolicyRules = 32;
    private const int MaxParentChars = 128;
    private const int MaxLeafChars = 64;
    private readonly Func<int, string, bool> _decision;
    private readonly CancellationTokenSource _stop = new();
    private Task? _worker;
    private SafeFileHandle? _port;

    public DriverPortClient(Func<int, string, bool> decision) => _decision = decision;

    internal static bool ValidateProtocolLayout(out string error)
    {
        var checks = new (string Name, int Actual, int Expected)[]
        {
            (nameof(FilterMessageHeader), Marshal.SizeOf<FilterMessageHeader>(), 16),
            (nameof(AccessMessage), Marshal.SizeOf<AccessMessage>(), 1072),
            (nameof(FilterReplyHeader), Marshal.SizeOf<FilterReplyHeader>(), 16),
            (nameof(AccessReply), Marshal.SizeOf<AccessReply>(), 24),
            (nameof(PathRule), Marshal.SizeOf<PathRule>(), 388),
            (nameof(PolicyUpdate), Marshal.SizeOf<PolicyUpdate>(), 12432)
        };
        foreach (var check in checks)
        {
            if (check.Actual == check.Expected)
                continue;
            error = $"{check.Name}: размер {check.Actual}, ожидался {check.Expected}";
            return false;
        }

        error = string.Empty;
        return true;
    }

    public void Start() => _worker ??= Task.Run(() => Run(_stop.Token));

    private void Run(CancellationToken cancellationToken)
    {
        var reportedUnavailable = false;
        while (!cancellationToken.IsCancellationRequested)
        {
            var hr = FilterConnectCommunicationPort(PortName, 0, IntPtr.Zero, 0, IntPtr.Zero, out var port);
            if (hr < 0 || port.IsInvalid)
            {
                if (!reportedUnavailable)
                {
                    ServiceLog.Write($"Minifilter is not connected (0x{hr:X8}); audit fallback remains active");
                    reportedUnavailable = true;
                }
                if (cancellationToken.WaitHandle.WaitOne(TimeSpan.FromSeconds(10)))
                    break;
                continue;
            }

            reportedUnavailable = false;
            _port = port;
            ServiceLog.Write("Minifilter communication port connected");
            if (!TrySendPolicy(port))
            {
                ServiceLog.Write("Minifilter rejected the protected-path policy; reconnecting");
                port.Dispose();
                _port = null;
                if (cancellationToken.WaitHandle.WaitOne(TimeSpan.FromSeconds(2)))
                    break;
                continue;
            }
            ReceiveLoop(port, cancellationToken);
            port.Dispose();
            _port = null;
        }
    }

    private static bool TrySendPolicy(SafeFileHandle port)
    {
        try { return SendPolicy(port); }
        catch (Exception ex)
        {
            ServiceLog.Write("Protected-path policy could not be loaded: " + ex.Message);
            return false;
        }
    }

    private static bool SendPolicy(SafeFileHandle port)
    {
        var policyPath = Path.Combine(AppContext.BaseDirectory, "ProtectedPaths.json");
        var definitions = JsonSerializer.Deserialize<List<PolicyDefinition>>(File.ReadAllText(policyPath)) ??
            throw new InvalidDataException("ProtectedPaths.json is empty");
        if (definitions.Count is < 1 or > MaxPolicyRules)
            throw new InvalidDataException($"ProtectedPaths.json must contain 1..{MaxPolicyRules} rules");

        var rules = new PathRule[MaxPolicyRules];
        for (var i = 0; i < rules.Length; i++)
            rules[i] = new PathRule { ParentFragment = string.Empty, LeafFragment = string.Empty };
        for (var i = 0; i < definitions.Count; i++)
        {
            var definition = definitions[i];
            if (definition.Category is < 1 or > 8 || string.IsNullOrWhiteSpace(definition.Parent) ||
                definition.Parent.Length >= MaxParentChars || definition.Leaf.Length >= MaxLeafChars ||
                definition.Parent.IndexOfAny(['\r', '\n', '\0']) >= 0 || definition.Leaf.IndexOfAny(['\r', '\n', '\0']) >= 0)
                throw new InvalidDataException($"ProtectedPaths.json rule {i + 1} is invalid");
            rules[i] = new PathRule
            {
                Category = definition.Category,
                ParentFragment = definition.Parent,
                LeafFragment = definition.Leaf
            };
        }

        var policy = new PolicyUpdate
        {
            Version = 1,
            Command = 1,
            RuleCount = (uint)definitions.Count,
            Rules = rules
        };
        var hr = FilterSendMessage(port, ref policy, (uint)Marshal.SizeOf<PolicyUpdate>(),
            IntPtr.Zero, 0, out _);
        if (hr < 0)
            ServiceLog.Write($"Protected-path policy update failed (0x{hr:X8})");
        else
            ServiceLog.Write($"Protected-path policy loaded ({definitions.Count} rules)");
        return hr >= 0;
    }

    private sealed class PolicyDefinition
    {
        public uint Category { get; init; }
        public string Parent { get; init; } = string.Empty;
        public string Leaf { get; init; } = string.Empty;
    }

    private void ReceiveLoop(SafeFileHandle port, CancellationToken cancellationToken)
    {
        var size = Marshal.SizeOf<AccessMessage>();
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var hr = FilterGetMessage(port, buffer, (uint)size, IntPtr.Zero);
                if (hr < 0)
                    break;

                var message = Marshal.PtrToStructure<AccessMessage>(buffer);
                var allow = true;
                try { allow = _decision(unchecked((int)message.ProcessId), message.Path ?? string.Empty); }
                catch (Exception ex) { ServiceLog.Write("Driver decision failed: " + ex.Message); }

                var reply = new AccessReply
                {
                    Header = new FilterReplyHeader { Status = 0, MessageId = message.Header.MessageId },
                    Version = 1,
                    Verdict = allow ? 1u : 0u
                };
                FilterReplyMessage(port, ref reply, (uint)Marshal.SizeOf<AccessReply>());
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FilterMessageHeader { public uint ReplyLength; public ulong MessageId; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct AccessMessage
    {
        public FilterMessageHeader Header;
        public uint Version;
        public uint ProcessId;
        public uint DesiredAccess;
        public uint Category;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)] public string? Path;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FilterReplyHeader { public int Status; public ulong MessageId; }

    [StructLayout(LayoutKind.Sequential)]
    private struct AccessReply { public FilterReplyHeader Header; public uint Version; public uint Verdict; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PathRule
    {
        public uint Category;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MaxParentChars)] public string ParentFragment;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MaxLeafChars)] public string LeafFragment;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PolicyUpdate
    {
        public uint Version;
        public uint Command;
        public uint RuleCount;
        public uint Reserved;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxPolicyRules)] public PathRule[] Rules;
    }

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(
        string portName, uint options, IntPtr context, ushort contextSize, IntPtr securityAttributes, out SafeFileHandle port);

    [DllImport("fltlib.dll")]
    private static extern int FilterGetMessage(SafeFileHandle port, IntPtr messageBuffer, uint messageBufferSize, IntPtr overlapped);

    [DllImport("fltlib.dll")]
    private static extern int FilterReplyMessage(SafeFileHandle port, ref AccessReply replyBuffer, uint replyBufferSize);

    [DllImport("fltlib.dll")]
    private static extern int FilterSendMessage(SafeFileHandle port, ref PolicyUpdate inputBuffer,
        uint inputBufferSize, IntPtr outputBuffer, uint outputBufferSize, out uint bytesReturned);

    public void Dispose()
    {
        _stop.Cancel();
        _port?.Dispose();
        try { _worker?.Wait(3000); } catch { }
        _stop.Dispose();
    }
}
