using System.Net;
using System.Runtime.InteropServices;

namespace AntiStealer;

internal static class NativeNetwork
{
    private const int AfInet = 2;
    private const int ErrorInsufficientBuffer = 122;

    private enum TcpTableClass
    {
        TcpTableOwnerPidAll = 5
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int size,
        bool order,
        int ipVersion,
        TcpTableClass tableClass,
        uint reserved);

    public static Dictionary<int, List<string>> GetOutboundConnections()
    {
        var result = new Dictionary<int, List<string>>();
        var size = 0;
        var first = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet, TcpTableClass.TcpTableOwnerPidAll, 0);
        if (first != ErrorInsufficientBuffer || size <= 0)
            return result;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableClass.TcpTableOwnerPidAll, 0) != 0)
                return result;

            var rows = Marshal.ReadInt32(buffer);
            var rowPtr = IntPtr.Add(buffer, sizeof(int));
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

            for (var i = 0; i < rows; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(IntPtr.Add(rowPtr, i * rowSize));
                // 3 = SYN_SENT, 5 = ESTABLISHED. LISTEN and loopback-only traffic are ignored.
                if (row.State is not (3 or 5) || row.RemoteAddr == 0 || row.RemotePort == 0)
                    continue;

                var remoteIp = new IPAddress(row.RemoteAddr);
                if (IPAddress.IsLoopback(remoteIp))
                    continue;

                var port = (ushort)IPAddress.NetworkToHostOrder((short)(row.RemotePort & 0xFFFF));
                var pid = unchecked((int)row.OwningPid);
                if (!result.TryGetValue(pid, out var endpoints))
                {
                    endpoints = new List<string>();
                    result[pid] = endpoints;
                }

                var endpoint = $"{remoteIp}:{port}";
                if (!endpoints.Contains(endpoint, StringComparer.OrdinalIgnoreCase))
                    endpoints.Add(endpoint);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }
}
