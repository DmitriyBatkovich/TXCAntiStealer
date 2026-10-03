namespace AntiStealer;

internal static class ServiceProgram
{
    private static int Main(string[] args)
    {
        if (args.Contains("--self-test", StringComparer.OrdinalIgnoreCase))
        {
            var result = SelfTest.Run();
            if (DriverPortClient.ValidateProtocolLayout(out var error))
                return result;
            Console.WriteLine("SELF_TEST_FAILED");
            Console.WriteLine("- двоичный протокол minifilter: " + error);
            return 1;
        }

        if (args.Contains("--console", StringComparer.OrdinalIgnoreCase))
            return RunConsole();

        return NativeWindowsService.Run();
    }

    private static int RunConsole()
    {
        using var host = new ProtectionServiceHost();
        using var stop = new ManualResetEventSlim(false);
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            stop.Set();
        };
        host.Start();
        Console.WriteLine("AntiStealer.Service запущена в консольном режиме. Ctrl+C для остановки.");
        stop.Wait();
        return 0;
    }
}
