using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Falsimeter.Core;

public sealed record RuntimeEndpoint(string Name, string Url, string Protocol = "OpenAI");
public sealed record DiscoverySettings(List<RuntimeEndpoint> Endpoints, List<string> ModelFolders)
{
    public static DiscoverySettings Default()
    {
        var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return new([
            new("Ollama", "http://127.0.0.1:11434", "Ollama"),
            new("LM Studio", "http://127.0.0.1:1234/v1/"),
            new("Local API :8080", "http://127.0.0.1:8080/v1/"),
            new("Local API :8000", "http://127.0.0.1:8000/v1/"),
            new("Local API :5001", "http://127.0.0.1:5001/v1/")
        ], [Environment.GetEnvironmentVariable("HF_HUB_CACHE") ?? Path.Combine(Environment.GetEnvironmentVariable("HF_HOME") ?? Path.Combine(user, ".cache", "huggingface"), "hub"),
            Path.Combine(user, ".lmstudio", "models"), Path.Combine(user, ".cache", "lm-studio", "models"),
            Path.Combine(local, "nomic.ai", "GPT4All"), Path.Combine(user, "jan", "models")]);
    }
}
public sealed record DiscoveredModel(ModelIdentity Model, RuntimeEndpoint? Endpoint, string? FilePath)
{
    public bool CanTest => Endpoint is not null;
    public string Availability => CanTest ? "Ready to test" : "File found · start a compatible server";
}
public sealed record DiscoveryResult(IReadOnlyList<DiscoveredModel> Models, IReadOnlyList<string> Diagnostics);

public sealed class CompatibleRuntime : IModelRuntime, IDisposable
{
    private readonly HttpClient _http;
    private readonly RuntimeEndpoint _endpoint;
    public CompatibleRuntime(RuntimeEndpoint endpoint, HttpMessageHandler? handler = null)
    {
        var uri = ValidateEndpoint(endpoint.Url);
        _endpoint = endpoint;
        _http = new HttpClient(handler ?? new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false })
        { BaseAddress = uri, Timeout = TimeSpan.FromMinutes(10) };
    }
    public static Uri ValidateEndpoint(string url)
    {
        var uri = new Uri(url.TrimEnd('/') + "/");
        if (uri.Scheme != "http" || !IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) || !IPAddress.IsLoopback(ip) || uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0)
            throw new ArgumentException("Use a numeric loopback HTTP address, for example http://127.0.0.1:1234/v1/.");
        return uri;
    }
    public async Task<IReadOnlyList<ModelIdentity>> InventoryAsync(CancellationToken ct = default)
    {
        using var r = await _http.GetAsync(_endpoint.Protocol == "Ollama" ? "api/tags" : "models", ct);
        r.EnsureSuccessStatusCode(); using var d = await JsonDocument.ParseAsync(await r.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        return d.RootElement.GetProperty(_endpoint.Protocol == "Ollama" ? "models" : "data").EnumerateArray().Select(m =>
            new ModelIdentity(m.GetProperty(_endpoint.Protocol == "Ollama" ? "name" : "id").GetString()!,
                m.TryGetProperty("digest", out var digest) ? digest.GetString() ?? "" : "",
                m.TryGetProperty("size", out var size) && size.TryGetInt64(out var bytes) ? bytes : 0,
                DateTimeOffset.UtcNow, _endpoint.Name + " · " + _http.BaseAddress)).ToList();
    }
    public async Task<JsonDocument> MetadataAsync(string model, CancellationToken ct = default)
    {
        using var r = _endpoint.Protocol == "Ollama" ? await _http.PostAsJsonAsync("api/show", new { model }, ct) : await _http.GetAsync("models", ct);
        r.EnsureSuccessStatusCode(); return await JsonDocument.ParseAsync(await r.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
    }
    public async Task<string> GenerateAsync(string model, string prompt, CancellationToken ct = default)
    {
        object body = _endpoint.Protocol == "Ollama" ? new { model, prompt, stream = false, options = new { temperature = 0 } } : new { model, messages = new[] { new { role = "user", content = prompt } }, stream = false, temperature = 0 };
        using var r = await _http.PostAsJsonAsync(_endpoint.Protocol == "Ollama" ? "api/generate" : "chat/completions", body, ct);
        r.EnsureSuccessStatusCode(); using var d = await JsonDocument.ParseAsync(await r.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        return _endpoint.Protocol == "Ollama" ? d.RootElement.GetProperty("response").GetString() ?? "" : d.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString() ?? throw new InvalidOperationException("The endpoint did not return text; it may not support chat.");
    }
    public void Dispose() => _http.Dispose();
}

public static class ModelDiscovery
{
    public static async Task<DiscoveryResult> DiscoverAsync(DiscoverySettings settings, CancellationToken ct = default)
    {
        var rows = new List<DiscoveredModel>(); var diagnostics = new List<string>();
        var results = await Task.WhenAll(settings.Endpoints.Select(async endpoint =>
        {
            try {
                if (endpoint.Protocol is not "Ollama" and not "OpenAI") throw new ArgumentException("Unsupported protocol.");
                using var runtime = new CompatibleRuntime(endpoint); using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(3));
                return (Models: (await runtime.InventoryAsync(timeout.Token)).Select(m => new DiscoveredModel(m, endpoint, null)).ToList(), Error: (string?)null);
            } catch (Exception e) when (!ct.IsCancellationRequested) { return (Models: new List<DiscoveredModel>(), Error: endpoint.Name + ": " + e.Message); }
        }));
        foreach (var result in results) { rows.AddRange(result.Models); if (result.Error is not null) diagnostics.Add(result.Error); }
        await Task.Run(() => {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var root in settings.ModelFolders.Distinct(StringComparer.OrdinalIgnoreCase)) {
                if (!Directory.Exists(root)) continue;
                try {
                    foreach (var path in EnumerateModelFiles(root)) {
                        ct.ThrowIfCancellationRequested();
                        if (!new[] { ".gguf", ".safetensors", ".bin", ".onnx", ".pt", ".pth" }.Contains(Path.GetExtension(path).ToLowerInvariant()) || !seen.Add(Path.GetFullPath(path))) continue;
                        var file = new FileInfo(path);
                        rows.Add(new(new(file.Name, "", file.Length, file.LastWriteTimeUtc, "Local model file"), null, path));
                    }
                } catch (Exception e) when (!ct.IsCancellationRequested) { diagnostics.Add(root + ": " + e.Message); }
            }
        }, ct);
        return new(rows, diagnostics);
    }
    // Skip directory junctions. Cache links may be listed without reading their contents.
    private static IEnumerable<string> EnumerateModelFiles(string root) {
        var pending = new Stack<string>(); pending.Push(root);
        while (pending.Count > 0) {
            var directory = pending.Pop();
            foreach (var file in Directory.EnumerateFiles(directory)) yield return file;
            foreach (var child in Directory.EnumerateDirectories(directory))
                if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) == 0) pending.Push(child);
        }
    }
}
