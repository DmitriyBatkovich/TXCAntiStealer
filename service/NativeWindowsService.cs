using System.Runtime.InteropServices;

namespace AntiStealer;

internal static class NativeWindowsService
{
    private const string ServiceName = "AntiStealerService";
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceStartPending = 0x00000002;
    private const uint ServiceStopPending = 0x00000003;
    private const uint ServiceRunning = 0x00000004;
    private const uint ServiceStopped = 0x00000001;
    private const uint ServiceAcceptStop = 0x00000001;
    private const uint ServiceAcceptShutdown = 0x00000004;
    private const uint ServiceControlStop = 0x00000001;
    private const uint ServiceControlShutdown = 0x00000005;
    private const uint RescanControl = 128;

    private static readonly ManualResetEventSlim StopEvent = new(false);
    private static readonly ServiceMainDelegate ServiceMainCallback = ServiceMain;
    private static readonly ServiceControlHandlerEx ControlCallback = Handler;
    private static IntPtr _statusHandle;
    private static ProtectionServiceHost? _host;
    private static uint _checkpoint;

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMainDelegate(uint argumentCount, IntPtr arguments);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint ServiceControlHandlerEx(uint control, uint eventType, IntPtr eventData, IntPtr context);

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceTableEntry
    {
        public IntPtr ServiceName;
        public IntPtr ServiceProcedure;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool StartServiceCtrlDispatcherW([In] ServiceTableEntry[] serviceTable);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandlerExW(string serviceName, ServiceControlHandlerEx handler, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetServiceStatus(IntPtr statusHandle, ref ServiceStatus serviceStatus);

    public static int Run()
    {
        var namePtr = Marshal.StringToHGlobalUni(ServiceName);
        try
        {
            var table = new[]
            {
                new ServiceTableEntry
                {
                    ServiceName = namePtr,
                    ServiceProcedure = Marshal.GetFunctionPointerForDelegate(ServiceMainCallback)
                },
                new ServiceTableEntry()
            };
            if (StartServiceCtrlDispatcherW(table))
                return 0;
            var error = Marshal.GetLastWin32Error();
            ServiceLog.Write("StartServiceCtrlDispatcher failed: " + error);
            return error;
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
        }
    }

    private static void ServiceMain(uint argumentCount, IntPtr arguments)
    {
        _statusHandle = RegisterServiceCtrlHandlerExW(ServiceName, ControlCallback, IntPtr.Zero);
        if (_statusHandle == IntPtr.Zero)
            return;

        SetStatus(ServiceStartPending, 0, 15_000);
        try
        {
            _host = new ProtectionServiceHost();
            _host.Start();
            SetStatus(ServiceRunning, ServiceAcceptStop | ServiceAcceptShutdown, 0);
            StopEvent.Wait();
            SetStatus(ServiceStopPending, 0, 10_000);
            _host.Dispose();
            _host = null;
            SetStatus(ServiceStopped, 0, 0);
        }
        catch (Exception ex)
        {
            ServiceLog.Write("Fatal service error: " + ex);
            SetStatus(ServiceStopped, 0, 0, 1);
        }
    }

    private static uint Handler(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        if (control is ServiceControlStop or ServiceControlShutdown)
        {
            SetStatus(ServiceStopPending, 0, 10_000);
            StopEvent.Set();
        }
        else if (control == RescanControl)
        {
            _host?.SignalScan();
        }
        return 0;
    }

    private static void SetStatus(uint state, uint accepted, uint waitHint, uint exitCode = 0)
    {
        if (_statusHandle == IntPtr.Zero)
            return;
        var status = new ServiceStatus
        {
            ServiceType = ServiceWin32OwnProcess,
            CurrentState = state,
            ControlsAccepted = accepted,
            Win32ExitCode = exitCode,
            CheckPoint = state is ServiceStartPending or ServiceStopPending ? ++_checkpoint : 0,
            WaitHint = waitHint
        };
        SetServiceStatus(_statusHandle, ref status);
    }
}
