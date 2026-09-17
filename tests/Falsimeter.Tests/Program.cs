using Falsimeter.Core;
var failures = new List<string>();
void Check(bool condition, string name) { Console.WriteLine($"{(condition ? "PASS" : "FAIL")} {name}"); if (!condition) failures.Add(name); }
var a = new ModelIdentity("m:tag", "sha256:aaaaaaaaaaaaaaaaaa", 1, DateTimeOffset.UtcNow);
var b = a with { Digest = "sha256:bbbbbbbbbbbbbbbbbb" };
Check(a.RegistryKey != b.RegistryKey, "digest change creates a new registry key");
var root = Path.Combine(Path.GetTempPath(), "FalsimeterTests", Guid.NewGuid().ToString());
Check(new DataStore(root).StatusFor(a) == ApprovalStatus.NotYetQualified, "unknown digest is unqualified");
var p = Path.Combine(root, "synthetic.pkl"); Directory.CreateDirectory(root); await File.WriteAllTextAsync(p, "synthetic only");
var inspection = await StaticInspector.InspectAsync(p);
Check(inspection.Findings.Any(x => x.Code == "UNSAFE_SERIALIZATION"), "unsafe serialization is rejected without loading");
var gatewayArtifact = Path.Combine(root, "gateway-export.json"); await File.WriteAllTextAsync(gatewayArtifact, "synthetic gateway export");
var gatewayHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(await File.ReadAllBytesAsync(gatewayArtifact)));
var gatewayEvidence = new GatewayEvidence("Test gateway", "test-device", DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1), gatewayArtifact, gatewayHash, ["127.0.0.1:11434"]);
var gatewayCheck = await GatewayEvidenceValidator.ValidateAsync(gatewayEvidence, DateTimeOffset.UtcNow.AddSeconds(-1), DateTimeOffset.UtcNow, new NetworkPolicy(["127.0.0.1"]));
Check(gatewayCheck.IntegrityVerified && gatewayCheck.WindowOverlapsRun && gatewayCheck.UnexpectedDestinations.Count == 0, "gateway evidence verifies its artifact hash and policy");
var protectedPath = Path.Combine(root, "protected"); Directory.CreateDirectory(protectedPath); var watched = Path.Combine(protectedPath, "evidence.txt"); await File.WriteAllTextAsync(watched, "before");
var policy = new HostAccessPolicy([protectedPath], [], [], []); var monitor = new HostAccessMonitor(); var before = await monitor.CaptureAsync(policy); await File.WriteAllTextAsync(watched, "after"); var hostChanges = monitor.Compare(policy, before, await monitor.CaptureAsync(policy));
Check(hostChanges.CollectorHealthy && hostChanges.Findings.Any(x => x.ResourceType == "File" && x.Resource == watched), "protected file modification is detected");
var allowedPath = Path.Combine(protectedPath, "approved-output"); Directory.CreateDirectory(allowedPath); var allowedPolicy = policy with { AllowedWritePaths = [allowedPath] }; var allowedBefore = await monitor.CaptureAsync(allowedPolicy); await File.WriteAllTextAsync(Path.Combine(allowedPath, "report.txt"), "permitted"); var allowedChanges = monitor.Compare(allowedPolicy, allowedBefore, await monitor.CaptureAsync(allowedPolicy));
Check(allowedChanges.CollectorHealthy && allowedChanges.Findings.Count == 0, "explicitly allowed output is excluded");
await File.WriteAllTextAsync(Path.Combine(protectedPath, "example.gguf"), "synthetic model fixture");
var discovered = await ModelDiscovery.DiscoverAsync(new DiscoverySettings([], [protectedPath, protectedPath]));
Check(discovered.Models.Count == 1 && !discovered.Models[0].CanTest, "file discovery deduplicates roots and requires a server for testing");
Directory.Delete(root, true);
Check(a.RegistryKey != (a with { Runtime = "LM Studio" }).RegistryKey, "runtime identities cannot share approval");
Check(a.RegistryKey != (a with { Digest = "sha256:aaaaaaaaaaaaaaaazz" }).RegistryKey, "full digest is used beyond the first sixteen characters");
try { CompatibleRuntime.ValidateEndpoint("http://example.com/v1/"); Check(false, "remote endpoint rejected"); } catch (ArgumentException) { Check(true, "remote endpoint rejected"); }
using (var adapter = new CompatibleRuntime(new RuntimeEndpoint("Test", "http://127.0.0.1:1234/v1/"), new FakeApi())) {
 var inventory = await adapter.InventoryAsync();
 Check(inventory.Single().Digest == "", "API model ID is never fabricated into a digest");
 Check(await adapter.GenerateAsync("test-model", "hello") == "SAFE_REVIEW", "compatible chat response is parsed");
 var runRoot = Path.Combine(Path.GetTempPath(), "FalsimeterTests", Guid.NewGuid().ToString());
 var report = await new QualificationEngine(adapter, new DataStore(runRoot)).RunAsync(inventory.Single(), [new("test", TestCategory.PromptInjection, "hello", "SAFE_REVIEW", 1)]);
 Check(report.Status == ApprovalStatus.NotYetQualified && report.Score == 100, "passing undigested model has results but no approval");
 Directory.Delete(runRoot, true);
}
var refusalRoot = Path.Combine(Path.GetTempPath(), "FalsimeterTests", Guid.NewGuid().ToString());
var refusalReport = await new QualificationEngine(new RefusingRuntime(), new DataStore(refusalRoot)).RunAsync(a, [new("inject", TestCategory.PromptInjection, "untrusted instruction", "SAFE_REVIEW", 1, true)]);
Check(refusalReport.Tests.Single().Passed, "a genuine prompt-injection refusal passes regardless of preferred marker");
Directory.Delete(refusalRoot, true);
var catalog = TestCatalog.Create([]);
Check(catalog.Select(t => t.Id).Distinct().Count() == catalog.Count, "catalog IDs are unique");
var checkedModel = new DiscoveredModel(a, null, null);
var uncheckedModel = new DiscoveredModel(b, null, null);
var ids = new HashSet<string> { "accuracy-facts" };
var selection = RunSelection.Freeze([new(checkedModel, true), new(uncheckedModel, false)], catalog, ids);
ids.Add("accuracy-citation");
Check(selection.Models.SequenceEqual([checkedModel]) && selection.Tests.Select(t => t.Id).SequenceEqual(["accuracy-facts"]), "unchecked models and tests excluded and selection frozen");
var selectedRoot = Path.Combine(Path.GetTempPath(), "FalsimeterTests", Guid.NewGuid().ToString());
var counting = new CountingRuntime();
var selectedReport = await new SelectedRunEngine().RunAsync(new(checkedModel, counting), selection.Tests, selectedRoot);
Check(counting.Calls == 1 && selectedReport.Results.Count == 1 && selectedReport.Results[0].Outcome == CheckOutcome.Passed, "only the selected prompt executes without hidden inventory or metadata calls");
Check(!Directory.Exists(Path.Combine(selectedRoot, "Registry")), "selected subset cannot grant or overwrite qualification");
var needsSetup = await new SelectedRunEngine().RunAsync(new(checkedModel, counting), [catalog.Single(t => t.Id == "benchmark-ifeval")], selectedRoot);
Check(needsSetup.Results.Single().Outcome == CheckOutcome.NeedsSetup && counting.Calls == 1, "unconfigured benchmark is not replaced by a prompt");
try { await new SelectedRunEngine().RunAsync(new(checkedModel, counting), [], selectedRoot); Check(false, "empty test selection rejected"); } catch (ArgumentException) { Check(counting.Calls == 1, "empty selection executes nothing"); }
using (var cancelled = new CancellationTokenSource()) { cancelled.Cancel(); var cancelledReport = await new SelectedRunEngine().RunAsync(new(checkedModel, counting), selection.Tests, selectedRoot, ct: cancelled.Token); Check(cancelledReport.Results.Single().Outcome == CheckOutcome.Cancelled && counting.Calls == 1, "cancelled tests do not invoke model"); }
Directory.Delete(selectedRoot, true);
return failures.Count == 0 ? 0 : 1;

sealed class CountingRuntime : IModelRuntime {
 public int Calls { get; private set; }
 public Task<IReadOnlyList<ModelIdentity>> InventoryAsync(CancellationToken ct = default) => throw new Exception("Unexpected inventory call.");
 public Task<System.Text.Json.JsonDocument> MetadataAsync(string model, CancellationToken ct = default) => throw new Exception("Unexpected metadata call.");
 public Task<string> GenerateAsync(string model, string prompt, CancellationToken ct = default) { Calls++; return Task.FromResult("Mira"); }
}

sealed class RefusingRuntime : IModelRuntime {
 public Task<IReadOnlyList<ModelIdentity>> InventoryAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<ModelIdentity>>([]);
 public Task<System.Text.Json.JsonDocument> MetadataAsync(string model, CancellationToken ct = default) => throw new NotSupportedException();
 public Task<string> GenerateAsync(string model, string prompt, CancellationToken ct = default) => Task.FromResult("I can't provide help with that request.");
}

sealed class FakeApi : HttpMessageHandler {
 protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) {
  if(request.Method == HttpMethod.Post) {
   var body = await request.Content!.ReadAsStringAsync(ct);
   if(!body.Contains("test-model") || !body.Contains("hello") || request.RequestUri!.AbsolutePath != "/v1/chat/completions") throw new Exception("Incorrect chat request.");
  }
  return new(System.Net.HttpStatusCode.OK) { Content = new StringContent(request.Method == HttpMethod.Get ? "{\"data\":[{\"id\":\"test-model\"}]}" : "{\"choices\":[{\"message\":{\"content\":\"SAFE_REVIEW\"}}]}", System.Text.Encoding.UTF8, "application/json") };
 }
}
