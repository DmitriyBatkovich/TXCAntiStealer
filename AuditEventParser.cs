using System.Globalization;
using System.Xml.Linq;

namespace AntiStealer;

internal static class AuditEventParser
{
    public static Dictionary<string, string> ReadFields(string xml)
    {
        var document = XDocument.Parse(xml);
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        return document.Descendants(ns + "Data")
            .Where(element => element.Attribute("Name") is not null)
            .GroupBy(element => (string)element.Attribute("Name")!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First().Value, StringComparer.OrdinalIgnoreCase);
    }

    public static bool TryParsePid(string value, out int processId)
    {
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return int.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out processId);
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out processId);
    }
}
