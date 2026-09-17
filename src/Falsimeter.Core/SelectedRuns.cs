using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Falsimeter.Core;

public enum CheckOutcome { Passed, Failed, NeedsSetup, Unsupported, Error, Cancelled }
public sealed record CheckEvidence(string TestId, CheckOutcome Outcome, string Detail, long DurationMs);
public sealed record SelectedRunReport(string RunId, ModelIdentity Model, DateTimeOffset StartedAt, DateTimeOffset EndedAt, IReadOnlyList<string> SelectedTests, IReadOnlyList<CheckEvidence> Results, string Scope = "Selected checks only; not full qualification or certification");
public sealed record ExternalRunner(string Executable, string[] Arguments, int TimeoutSeconds = 3600);
public sealed record TestRunContext(DiscoveredModel Entry, IModelRuntime? Runtime);
public sealed record ModelChoice(DiscoveredModel Model, bool IsChecked);
public sealed record RunSelection(IReadOnlyList<DiscoveredModel> Models, IReadOnlyList<TestDefinition> Tests)
{
    public static RunSelection Freeze(IEnumerable<ModelChoice> models, IReadOnlyList<TestDefinition> catalog, IEnumerable<string> checkedIds)
    {
        var ids = checkedIds.ToHashSet(StringComparer.Ordinal);
        if (ids.Except(catalog.Select(t => t.Id)).Any()) throw new ArgumentException("Selection contains unknown test IDs.");
        return new(models.Where(m => m.IsChecked).Select(m => m.Model).ToArray(), catalog.Where(t => ids.Contains(t.Id)).ToArray());
    }
}

public sealed class SelectedRunEngine
{
    public async Task<SelectedRunReport> RunAsync(TestRunContext context, IReadOnlyList<TestDefinition> selected, string root,
        IReadOnlyDictionary<string, ExternalRunner>? runners = null, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        if (selected.Count == 0) throw new ArgumentException("Select at least one test.");
        if (selected.Select(t => t.Id).Distinct(StringComparer.Ordinal).Count() != selected.Count) throw new ArgumentException("Duplicate selected test IDs.");
        var started = DateTimeOffset.UtcNow; var id = Guid.NewGuid().ToString("N"); var results = new List<CheckEvidence>();
        var runDirectory = Path.Combine(root, "Results", "SelectedRuns", id); Directory.CreateDirectory(runDirectory);
        // Run only the tests and models selected for this request.
        foreach (var test in selected.ToArray()) {
            var timer = Stopwatch.StartNew(); progress?.Report(context.Entry.Model.Name + " — " + test.Name);
            CheckEvidence evidence;
            try {
                ct.ThrowIfCancellationRequested();
                if (test.Prompt is not null) {
                    if (context.Runtime is null) evidence = new(test.Id, CheckOutcome.Unsupported, "Start a compatible local server to run text tests for this file.", 0);
                    else {
                        var response = await context.Runtime.GenerateAsync(context.Entry.Model.Name, test.Prompt.Prompt, ct);
                        evidence = new(test.Id, TestCatalog.Grade(test, response) ? CheckOutcome.Passed : CheckOutcome.Failed, response, 0);
                    }
                } else if (test.Id == "package-inspection") {
                    if (context.Entry.FilePath is null) evidence = new(test.Id, CheckOutcome.Unsupported, "Select a discovered file; this API entry does not expose a verified local package path.", 0);
                    else { var result = await StaticInspector.InspectAsync(context.Entry.FilePath, ct); evidence = new(test.Id, result.Findings.Count == 0 ? CheckOutcome.Passed : CheckOutcome.Failed, JsonSerializer.Serialize(new { result.Sha256, result.Findings }, Defaults.Json), 0); }
                } else if (runners is not null && runners.TryGetValue(test.Id, out var runner)) evidence = await RunExternalAsync(test, runner, context.Entry, runDirectory, ct);
                else evidence = new(test.Id, CheckOutcome.NeedsSetup, test.Requirement + ". No substitute test was run.", 0);
            } catch (OperationCanceledException) when (ct.IsCancellationRequested) { evidence = new(test.Id, CheckOutcome.Cancelled, "Cancelled before completion.", 0); }
            catch (Exception ex) { evidence = new(test.Id, CheckOutcome.Error, ex.Message, 0); }
            results.Add(evidence with { DurationMs = timer.ElapsedMilliseconds });
        }
        var report = new SelectedRunReport(id, context.Entry.Model, started, DateTimeOffset.UtcNow, selected.Select(t => t.Id).ToArray(), results);
        var json = JsonSerializer.Serialize(report, Defaults.Json); var path = Path.Combine(runDirectory, "report.json");
        await File.WriteAllTextAsync(path, json); // Preserve partial evidence even if cancellation was requested.
        await File.WriteAllTextAsync(Path.Combine(runDirectory, "report.sha256"), Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json))));
        return report;
    }
    private static async Task<CheckEvidence> RunExternalAsync(TestDefinition test, ExternalRunner runner, DiscoveredModel model, string folder, CancellationToken ct)
    {
        if (!Path.IsPathFullyQualified(runner.Executable) || !File.Exists(runner.Executable)) throw new ArgumentException("Configure an absolute path to an installed trusted runner executable.");
        if (runner.TimeoutSeconds <= 0) throw new ArgumentException("Runner timeout must be positive.");
        var request = Path.Combine(folder, test.Id + ".request.json");
        var resultPath = Path.Combine(folder, test.Id + ".result.json");
        await File.WriteAllTextAsync(request, JsonSerializer.Serialize(new { test, model, resultPath, allowedTestIds = new[] { test.Id } }, Defaults.Json), ct);
        var start = new ProcessStartInfo(runner.Executable) { UseShellExecute = false, CreateNoWindow = true };
        foreach (var arg in runner.Arguments) start.ArgumentList.Add(arg);
        start.ArgumentList.Add("--falsimeter-request"); start.ArgumentList.Add(request);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Runner did not start.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(runner.TimeoutSeconds));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { if (!process.HasExited) process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); if (ct.IsCancellationRequested) throw; throw new TimeoutException("Runner exceeded its time budget."); }
        if (process.ExitCode != 0) throw new InvalidOperationException("Runner exited with code " + process.ExitCode);
        var result = JsonSerializer.Deserialize<CheckEvidence>(await File.ReadAllTextAsync(resultPath, ct), Defaults.Json) ?? throw new InvalidOperationException("Runner did not return a result.");
        if (result.TestId != test.Id || !Enum.IsDefined(result.Outcome)) throw new InvalidOperationException("Runner result does not match the requested test.");
        return result;
    }
}
