using System.Runtime.InteropServices;

namespace AntiStealer;

internal static class InteractiveNotifier
{
    private const string UiPresenceName = @"Global\AntiStealerInteractiveUi";
    private const uint MbOk = 0;
    private const uint MbIconWarning = 0x30;

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSSendMessageW(
        IntPtr server,
        uint sessionId,
        string title,
        uint titleLength,
        string message,
        uint messageLength,
        uint style,
        uint timeout,
        out uint response,
        bool wait);

    public static void Warn(string title, string message)
    {
        try
        {
            var session = WTSGetActiveConsoleSessionId();
            if (session == uint.MaxValue)
                return;
            WTSSendMessageW(IntPtr.Zero, session, title, (uint)(title.Length * 2),
                message, (uint)(message.Length * 2), MbOk | MbIconWarning, 0, out _, false);
        }
        catch { }
    }

    public static bool IsUiPresent()
    {
        try
        {
            using var presence = EventWaitHandle.OpenExisting(UiPresenceName);
            return presence.WaitOne(0);
        }
        catch { return false; }
    }
}
