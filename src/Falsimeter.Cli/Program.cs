using System.Text.Json;
using Falsimeter.Core;
var root = Environment.GetEnvironmentVariable("FALSIMETER_ROOT") ?? Defaults.DataRoot;
var store = new DataStore(root); var runtime = new OllamaRuntime();
if (args.Length == 0 || args[0] is "help" or "--help") { Help(); return 0; }
try {
 switch (args[0].ToLowerInvariant()) {
  case "discover": var settings = args.Length > 1 ? JsonSerializer.Deserialize<DiscoverySettings>(await File.ReadAllTextAsync(args[1]), Defaults.Json)! : DiscoverySettings.Default(); Console.WriteLine(JsonSerializer.Serialize(await ModelDiscovery.DiscoverAsync(settings), Defaults.Json)); break;
  case "qualify-endpoint":
   if (args.Length < 5) throw new ArgumentException("qualify-endpoint <name> <local-url/v1/> <model> <corpus.json>");
   using (var compatible = new CompatibleRuntime(new RuntimeEndpoint(args[1], args[2]))) {
    var selected = (await compatible.InventoryAsync()).Single(m => m.Name == args[3]);
    var result = await new QualificationEngine(compatible, store).RunAsync(selected, await Corpus.LoadAsync(args[4]));
    Console.WriteLine(JsonSerializer.Serialize(result, Defaults.Json)); return result.Status == ApprovalStatus.Rejected ? 1 : 0;
   }
  case "init": store.Initialize(); Console.WriteLine(root); break;
  case "inventory": case "status": var ms = await runtime.InventoryAsync(); await store.SaveInventoryAsync(ms); foreach (var m in ms) Console.WriteLine($"{m.Name}\t{m.Digest}\t{store.StatusFor(m)}"); break;
  case "qualify": if (args.Length < 3) throw new ArgumentException("qualify requires <model> <corpus.json> [--host-policy <policy.json>] [--network-policy <policy.json>] [--gateway-evidence <evidence.json>]"); var policyIndex = Array.FindIndex(args, x => x.Equals("--host-policy", StringComparison.OrdinalIgnoreCase)); var networkIndex = Array.FindIndex(args, x => x.Equals("--network-policy", StringComparison.OrdinalIgnoreCase)); var gatewayIndex = Array.FindIndex(args, x => x.Equals("--gateway-evidence", StringComparison.OrdinalIgnoreCase)); if (policyIndex >= 0 && policyIndex + 1 >= args.Length) throw new ArgumentException("--host-policy requires a path."); if (networkIndex >= 0 && networkIndex + 1 >= args.Length) throw new ArgumentException("--network-policy requires a path."); if (gatewayIndex >= 0 && gatewayIndex + 1 >= args.Length) throw new ArgumentException("--gateway-evidence requires a path."); if (gatewayIndex >= 0 && networkIndex < 0) throw new ArgumentException("--gateway-evidence requires --network-policy."); var model = (await runtime.InventoryAsync()).Single(m => m.Name.Equals(args[1], StringComparison.OrdinalIgnoreCase)); using (var meta = await runtime.MetadataAsync(model.Name)) await store.SaveMetadataAsync(model, meta); var policy = policyIndex >= 0 ? await Corpus.LoadHostAccessPolicyAsync(args[policyIndex + 1]) : null; var networkPolicy = networkIndex >= 0 ? await Corpus.LoadNetworkPolicyAsync(args[networkIndex + 1]) : null; var gatewayEvidence = gatewayIndex >= 0 ? await Corpus.LoadGatewayEvidenceAsync(args[gatewayIndex + 1]) : null; var report = await new QualificationEngine(runtime, store).RunAsync(model, await Corpus.LoadAsync(args[2]), policy, networkPolicy, gatewayEvidence); Console.WriteLine(JsonSerializer.Serialize(report, Defaults.Json)); return report.Status == ApprovalStatus.Rejected ? 1 : 0;
  case "inspect": if (args.Length < 2) throw new ArgumentException("inspect requires <package-path>"); Console.WriteLine(JsonSerializer.Serialize(await StaticInspector.InspectAsync(args[1]), Defaults.Json)); break;
  default: throw new ArgumentException("Unknown command: " + args[0]);
 } return 0;
} catch (Exception ex) { Console.Error.WriteLine("Falsimeter: " + ex.Message); return 2; }
static void Help() => Console.WriteLine("Falsimeter CLI\n  init\n  inventory\n  status\n  qualify <model> <corpus.json> [--host-policy <policy.json>] [--network-policy <policy.json>] [--gateway-evidence <evidence.json>]\n  inspect <package-path>\nData is stored in %LOCALAPPDATA%\\Falsimeter by default. FALSIMETER_ROOT overrides it.");
