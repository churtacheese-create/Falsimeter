using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Falsimeter.Core;

public sealed record HostAuditEvent(DateTimeOffset TimeCreated, string ObjectName, string ProcessName, string AccessMask, string AccessList);

public static class WindowsAuditEvidence
{
    public static async Task<IReadOnlyList<HostAuditEvent>> CollectAsync(DateTimeOffset startedAt, DateTimeOffset endedAt, HostAccessPolicy policy, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows Security auditing is required for host-access evidence.");

        var start = startedAt.AddSeconds(-2).UtcDateTime.ToString("O");
        var info = new ProcessStartInfo("wevtutil.exe") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        info.ArgumentList.Add("qe");
        info.ArgumentList.Add("Security");
        info.ArgumentList.Add($"/q:*[System[(EventID=4663 and TimeCreated[@SystemTime >= '{start}'])]]");
        info.ArgumentList.Add("/f:xml");
        info.ArgumentList.Add("/rd:true");
        info.ArgumentList.Add("/c:2000");

        using var process = Process.Start(info) ?? throw new InvalidOperationException("Unable to query the Windows Security event log.");
        var output = await process.StandardOutput.ReadToEndAsync(ct);
        var error = await process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        if (process.ExitCode != 0) throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? "Windows Security event-log query failed." : error.Trim());
        if (string.IsNullOrWhiteSpace(output)) return [];

        // wevtutil emits consecutive Event documents on some Windows builds rather
        // than one document with an Events root. Parse each event independently.
        var events = Regex.Matches(output, @"<Event(?:\s[^>]*)?>.*?</Event>", RegexOptions.Singleline)
            .Select(match => XDocument.Parse(match.Value).Root!)
            .Select(Parse);
        return events
            .Where(e => e is not null && e.TimeCreated <= endedAt.AddSeconds(2) && MatchesPolicy(e, policy) && !IsFalsimeterProcess(e.ProcessName))
            .Cast<HostAuditEvent>()
            .OrderBy(e => e.TimeCreated)
            .ToArray();
    }

    private static HostAuditEvent? Parse(XElement element)
    {
        var system = element.Elements().FirstOrDefault(e => e.Name.LocalName == "System");
        var timeText = system?.Elements().FirstOrDefault(e => e.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
        if (!DateTimeOffset.TryParse(timeText, out var time)) return null;
        var values = element.Descendants().Where(e => e.Name.LocalName == "Data")
            .ToDictionary(e => e.Attribute("Name")?.Value ?? string.Empty, e => e.Value, StringComparer.OrdinalIgnoreCase);
        if (!values.TryGetValue("ObjectName", out var objectName) || string.IsNullOrWhiteSpace(objectName)) return null;
        return new(time, objectName, values.GetValueOrDefault("ProcessName", string.Empty), values.GetValueOrDefault("AccessMask", string.Empty), values.GetValueOrDefault("AccessList", string.Empty));
    }

    private static bool MatchesPolicy(HostAuditEvent evidence, HostAccessPolicy policy)
    {
        var target = evidence.ObjectName.Replace('/', '\\');
        foreach (var path in policy.ProtectedPaths)
        {
            try
            {
                var full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
                if (target.Equals(full, StringComparison.OrdinalIgnoreCase) || target.StartsWith(full + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return true;
            }
            catch (ArgumentException) { }
        }
        return policy.RegistryPaths.Any(path =>
        {
            var slash = path.Replace('/', '\\').IndexOf('\\');
            var subKey = slash < 0 ? string.Empty : path[(slash + 1)..].Replace('/', '\\').Trim('\\');
            return !string.IsNullOrWhiteSpace(subKey) && target.Contains("\\" + subKey, StringComparison.OrdinalIgnoreCase);
        });
    }

    private static bool IsFalsimeterProcess(string processName) =>
        processName.EndsWith("\\dotnet.exe", StringComparison.OrdinalIgnoreCase) ||
        processName.EndsWith("\\Falsimeter.App.exe", StringComparison.OrdinalIgnoreCase) ||
        processName.EndsWith("\\Falsimeter.Cli.exe", StringComparison.OrdinalIgnoreCase);
}
