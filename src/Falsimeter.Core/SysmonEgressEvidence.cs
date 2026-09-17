using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Falsimeter.Core;

public sealed record NetworkAuditEvent(DateTimeOffset TimeCreated, string EventType, string ProcessName, string Destination, string Detail);

public static class SysmonEgressEvidence
{
    public static async Task<EgressObservation> CollectAsync(DateTimeOffset startedAt, DateTimeOffset endedAt, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Sysmon egress evidence requires Windows.");
        var start = startedAt.AddSeconds(-2).UtcDateTime.ToString("O");
        var info = new ProcessStartInfo("wevtutil.exe") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        info.ArgumentList.Add("qe");
        info.ArgumentList.Add("Microsoft-Windows-Sysmon/Operational");
        info.ArgumentList.Add($"/q:*[System[((EventID=3 or EventID=22) and TimeCreated[@SystemTime >= '{start}'])]]");
        info.ArgumentList.Add("/f:xml");
        info.ArgumentList.Add("/rd:true");
        info.ArgumentList.Add("/c:2000");

        using var process = Process.Start(info) ?? throw new InvalidOperationException("Unable to query the Sysmon event log.");
        var output = await process.StandardOutput.ReadToEndAsync(ct);
        var error = await process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        if (process.ExitCode != 0) throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? "Sysmon event-log query failed." : error.Trim());

        var events = Regex.Matches(output, @"<Event(?:\s[^>]*)?>.*?</Event>", RegexOptions.Singleline)
            .Select(match => XDocument.Parse(match.Value).Root!)
            .Select(Parse)
            .Where(e => e is not null && e.TimeCreated <= endedAt.AddSeconds(2) && IsLocalRunner(e.ProcessName))
            .Cast<NetworkAuditEvent>()
            .OrderBy(e => e.TimeCreated)
            .ToArray();
        var destinations = events.Select(e => e.Destination).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        return new(startedAt, endedAt, 0, destinations, "Sysmon Event IDs 3 and 22", "Observation identifies connections and DNS activity during the test window; an independent allowlist or gateway enforces containment.", events, true);
    }

    private static NetworkAuditEvent? Parse(XElement element)
    {
        var system = element.Elements().FirstOrDefault(e => e.Name.LocalName == "System");
        var idText = system?.Elements().FirstOrDefault(e => e.Name.LocalName == "EventID")?.Value;
        var timeText = system?.Elements().FirstOrDefault(e => e.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
        if (!DateTimeOffset.TryParse(timeText, out var time)) return null;
        var values = element.Descendants().Where(e => e.Name.LocalName == "Data")
            .ToDictionary(e => e.Attribute("Name")?.Value ?? string.Empty, e => e.Value, StringComparer.OrdinalIgnoreCase);
        var image = values.GetValueOrDefault("Image", string.Empty);
        if (idText == "3")
        {
            var ip = values.GetValueOrDefault("DestinationIp", string.Empty);
            var port = values.GetValueOrDefault("DestinationPort", string.Empty);
            return new(time, "Network connection", image, string.IsNullOrWhiteSpace(port) ? ip : ip + ":" + port, values.GetValueOrDefault("Protocol", string.Empty));
        }
        if (idText == "22") return new(time, "DNS query", image, values.GetValueOrDefault("QueryName", string.Empty), values.GetValueOrDefault("QueryStatus", string.Empty));
        return null;
    }

    private static bool IsLocalRunner(string processName) =>
        processName.EndsWith("\\ollama.exe", StringComparison.OrdinalIgnoreCase) ||
        processName.EndsWith("\\lms.exe", StringComparison.OrdinalIgnoreCase) ||
        processName.EndsWith("\\python.exe", StringComparison.OrdinalIgnoreCase);
}
