using System.Security.Principal;

namespace AntiStealer;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        if (args.Contains("--self-test", StringComparer.OrdinalIgnoreCase))
        {
            Environment.ExitCode = SelfTest.Run();
            return;
        }

        ApplicationConfiguration.Initialize();

        var previewIndex = Array.FindIndex(args,
            argument => argument.Equals("--render-ui-preview", StringComparison.OrdinalIgnoreCase));
        if (previewIndex >= 0 && previewIndex + 1 < args.Length)
        {
            using var preview = new MainForm(previewMode: true);
            preview.RenderPreview(Path.GetFullPath(args[previewIndex + 1]));
            return;
        }

        var trayPreviewIndex = Array.FindIndex(args,
            argument => argument.Equals("--render-tray-preview", StringComparison.OrdinalIgnoreCase));
        if (trayPreviewIndex >= 0 && trayPreviewIndex + 1 < args.Length)
        {
            using var preview = new TrayStatusToastForm(() => { });
            preview.RenderPreview(Path.GetFullPath(args[trayPreviewIndex + 1]));
            return;
        }

        if (!IsAdministrator())
        {
            MessageBox.Show(
                "AntiStealer нужны права администратора, чтобы блокировать программы в брандмауэре и помещать угрозы в карантин.",
                "AntiStealer",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        Application.Run(new MainForm());
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
