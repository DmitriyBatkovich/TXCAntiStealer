using System.Text.Json;

namespace AntiStealer;

internal static class NotificationFeedWriter
{
    private static readonly object Gate = new();
    private static readonly string FeedPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "AntiStealer", "notifications.jsonl");

    public static void Publish(UserNotification notification)
    {
        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FeedPath)!);
                File.AppendAllText(FeedPath, JsonSerializer.Serialize(notification) + Environment.NewLine);
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Write("Notification feed write failed: " + ex.Message);
        }
    }
}
