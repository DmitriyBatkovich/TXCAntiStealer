using System.Security.Principal;

namespace AntiStealer;

internal static class StartupManager
{
    private const string TaskName = "AntiStealer";

    public static bool IsEnabled()
    {
        try
        {
            dynamic service = Connect();
            dynamic folder = service.GetFolder("\\");
            dynamic task = folder.GetTask(TaskName);
            return task is not null && task.Enabled;
        }
        catch { return false; }
    }

    public static void Enable(string executablePath)
    {
        if (!File.Exists(executablePath))
            throw new FileNotFoundException("Файл AntiStealer не найден", executablePath);

        dynamic service = Connect();
        dynamic folder = service.GetFolder("\\");
        dynamic definition = service.NewTask(0);
        var user = WindowsIdentity.GetCurrent().Name;

        definition.RegistrationInfo.Description = "AntiStealer: контроль подмены EXE и исходящих соединений";
        definition.Principal.UserId = user;
        definition.Principal.LogonType = 3; // TASK_LOGON_INTERACTIVE_TOKEN
        definition.Principal.RunLevel = 1; // TASK_RUNLEVEL_HIGHEST
        definition.Settings.Enabled = true;
        definition.Settings.StartWhenAvailable = true;
        definition.Settings.DisallowStartIfOnBatteries = false;
        definition.Settings.StopIfGoingOnBatteries = false;
        definition.Settings.ExecutionTimeLimit = "PT0S";
        definition.Settings.MultipleInstances = 2; // ignore new instance

        dynamic trigger = definition.Triggers.Create(9); // TASK_TRIGGER_LOGON
        trigger.UserId = user;
        trigger.Enabled = true;

        dynamic action = definition.Actions.Create(0); // TASK_ACTION_EXEC
        action.Path = Path.GetFullPath(executablePath);
        action.WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(executablePath));

        folder.RegisterTaskDefinition(TaskName, definition, 6, user, null, 3, null); // CREATE_OR_UPDATE
    }

    public static void Disable()
    {
        dynamic service = Connect();
        dynamic folder = service.GetFolder("\\");
        try { folder.DeleteTask(TaskName, 0); } catch { }
    }

    private static dynamic Connect()
    {
        var serviceType = Type.GetTypeFromProgID("Schedule.Service")
                          ?? throw new InvalidOperationException("Task Scheduler API недоступен");
        dynamic service = Activator.CreateInstance(serviceType)!;
        service.Connect();
        return service;
    }
}
