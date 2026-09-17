using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Falsimeter.Core;
namespace Falsimeter.App;
public partial class MainWindow : Window
{
 private readonly DataStore _store;
 private DiscoverySettings _settings = DiscoverySettings.Default();
 private readonly Dictionary<string, QualificationReport> _reports = new();
 private readonly Dictionary<Row, SelectedRunReport> _selectedReports = new();
 private IReadOnlyList<TestDefinition> _catalog = [];
 private readonly HashSet<string> _selectedTests = new(StringComparer.Ordinal);
 private CancellationTokenSource? _runCancellation;
 private string? _hostPolicy;
 private bool _busy;
 public MainWindow() {
  InitializeComponent();
  var root = Environment.GetEnvironmentVariable("FALSIMETER_ROOT") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Falsimeter", "Data");
  _store = new(root); RootLabel.Text = "Data root: " + root; RootLabel.ToolTip = root;
  _catalog = TestCatalog.Create(JsonSerializer.Deserialize<List<TestCase>>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "corpus", "synthetic-v1.json")), Defaults.Json) ?? []);
  try { if (File.Exists(SettingsPath)) _settings = JsonSerializer.Deserialize<DiscoverySettings>(File.ReadAllText(SettingsPath), Defaults.Json) ?? _settings; } catch (Exception e) { StatusText.Text = "Settings could not be loaded: " + e.Message; }
 }
 private string SettingsPath => Path.Combine(_store.Root, "discovery.json");
 private void Busy(bool value) { _busy = value; DiscoverButton.IsEnabled = QualifyButton.IsEnabled = TestsButton.IsEnabled = ModelsGrid.IsEnabled = !value; CancelButton.IsEnabled = value && _runCancellation is not null; }
 private async void Discover_Click(object sender, RoutedEventArgs e) {
  if (_busy) return; Busy(true);
  try { StatusText.Text = "Discovering local model servers and files…"; var result = await ModelDiscovery.DiscoverAsync(_settings); ModelsGrid.ItemsSource = result.Models.Select(m => new Row(m, _store.StatusFor(m.Model))).ToList(); CountText.Text = result.Models.Count + " models"; StatusText.Text = $"Found {result.Models.Count} entries. {result.Diagnostics.Count} server or folder notices."; StatusText.ToolTip = string.Join(Environment.NewLine, result.Diagnostics); }
  catch (Exception ex) { StatusText.Text = ex.Message; } finally { Busy(false); }
 }
 private async void Qualify_Click(object sender, RoutedEventArgs e) {
  if (_busy) return;
  var plan = RunSelection.Freeze(ModelsGrid.Items.OfType<Row>().Select(r => new ModelChoice(r.Entry, r.IsChecked)), _catalog, _selectedTests);
  var rows = ModelsGrid.Items.OfType<Row>().Where(r => plan.Models.Contains(r.Entry)).ToArray();
  var tests = plan.Tests.ToArray();
  if (rows.Length == 0 || tests.Length == 0) { StatusText.Text = "Check at least one model and choose at least one test. Nothing was run."; return; }
  _runCancellation = new CancellationTokenSource();
  Busy(true);
  try {
   var runnersPath = Path.Combine(_store.Root, "test-runners.json");
   var runners = File.Exists(runnersPath) ? JsonSerializer.Deserialize<Dictionary<string, ExternalRunner>>(await File.ReadAllTextAsync(runnersPath), Defaults.Json) : null;
   foreach (var row in rows) {
    if (_runCancellation.IsCancellationRequested) break;
    using var runtime = row.Entry.Endpoint is null ? null : new CompatibleRuntime(row.Entry.Endpoint);
    var report = await new SelectedRunEngine().RunAsync(new(row.Entry, runtime), tests, _store.Root, runners, new Progress<string>(text => StatusText.Text = text), _runCancellation.Token);
    _selectedReports[row] = report; row.LastRun = $"{report.Results.Count(r => r.Outcome == CheckOutcome.Passed)}/{report.Results.Count} passed · selected checks";
    ModelsGrid.Items.Refresh();
   }
   StatusText.Text = _runCancellation.IsCancellationRequested ? "Stopped. Partial results are saved; remaining models were not started." : $"Selected run finished: {rows.Length} models × {tests.Length} tests. Open ⋯ for outcomes and setup requirements.";
  } catch (Exception ex) { StatusText.Text = "Run stopped: " + ex.Message; } finally { _runCancellation.Dispose(); _runCancellation = null; Busy(false); }
 }
 private void Cancel_Click(object sender, RoutedEventArgs e) => _runCancellation?.Cancel();
 private void Tests_Click(object sender, RoutedEventArgs e) {
  if (_busy) return;
  var page = new TestSelectionWindow(_catalog, _selectedTests) { Owner = this };
  if (page.ShowDialog() == true) { _selectedTests.Clear(); _selectedTests.UnionWith(page.SelectedIds); TestsButton.Content = $"☑  Tests ({_selectedTests.Count})"; }
 }
 private void Details_Click(object sender, RoutedEventArgs e) { if ((sender as FrameworkElement)?.DataContext is Row row) ShowReport(row); }
 private void ShowReport(Row row) {
  if (_selectedReports.TryGetValue(row, out var selected)) {
   var text = $"{selected.Model.Name}\n{selected.Scope}\nRun: {selected.RunId}\n\n" + string.Join("\n\n", selected.Results.Select(r => $"{_catalog.First(t => t.Id == r.TestId).Name} — {r.Outcome}\n{r.Detail}"));
   new Window { Owner = this, Title = "Selected test results", Width = 860, Height = 640, Content = new TextBox { Text = text, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(20), Background = Background, Foreground = Foreground } }.ShowDialog(); return;
  }
  _reports.TryGetValue(row.Entry.Model.RegistryKey, out var report);
  if (report is null) { var path = Path.Combine(_store.Root, "Registry", row.Entry.Model.RegistryKey + ".qualification.json"); try { if (File.Exists(path)) report = JsonSerializer.Deserialize<QualificationReport>(File.ReadAllText(path), Defaults.Json); } catch { } }
  var content = report is null ? $"{row.Name}\n{row.Location}\n\n{row.Availability}\nNo saved test report.\n\nModels are discovered without loading their files." : JsonSerializer.Serialize(report, Defaults.Json);
  new Window { Owner = this, Title = row.Name + " — Results", Width = 860, Height = 640, Background = Background, Content = new TextBox { Text = content, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Background = Background, Foreground = Foreground, FontFamily = new FontFamily("Consolas"), Padding = new Thickness(20) } }.ShowDialog();
 }
 private void Settings_Click(object sender, RoutedEventArgs e) {
  if (_busy) return;
  var dialog = new Window { Owner = this, Title = "Falsimeter — Discovery settings", Width = 760, Height = 580, Background = Background };
  var panel = new DockPanel { Margin = new Thickness(20) };
  var save = new Button { Content = "Save settings", Margin = new Thickness(0,12,0,0) }; DockPanel.SetDock(save, Dock.Bottom); panel.Children.Add(save);
  var policy = new TextBox { Text = _hostPolicy ?? "", ToolTip = "Optional host policy JSON path", Margin = new Thickness(0,10,0,0) }; DockPanel.SetDock(policy, Dock.Bottom); panel.Children.Add(policy);
  var label = new TextBlock { Text = "Add local API addresses and model folders below. Bottom field: optional host policy path.", TextWrapping = TextWrapping.Wrap, Foreground = Foreground, Margin = new Thickness(0,0,0,12) }; DockPanel.SetDock(label, Dock.Top); panel.Children.Add(label);
  var editor = new TextBox { Text = JsonSerializer.Serialize(_settings, Defaults.Json), AcceptsReturn = true, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Background = Background, Foreground = Foreground, FontFamily = new FontFamily("Consolas") }; panel.Children.Add(editor);
  save.Click += (_, _) => { try { var value = JsonSerializer.Deserialize<DiscoverySettings>(editor.Text, Defaults.Json) ?? throw new Exception("Settings are empty."); if(value.Endpoints is null || value.ModelFolders is null) throw new Exception("Endpoints and modelFolders are required."); foreach (var endpoint in value.Endpoints) CompatibleRuntime.ValidateEndpoint(endpoint.Url); _store.Initialize(); File.WriteAllText(SettingsPath, JsonSerializer.Serialize(value, Defaults.Json)); _settings = value; _hostPolicy = string.IsNullOrWhiteSpace(policy.Text) ? null : policy.Text; dialog.Close(); } catch (Exception ex) { MessageBox.Show(dialog, ex.Message, "Check settings"); } };
  dialog.Content = panel; dialog.ShowDialog();
 }
 private sealed class Row(DiscoveredModel entry, ApprovalStatus status) {
  public bool IsChecked { get; set; }
  public string? LastRun { get; set; }
  public DiscoveredModel Entry { get; } = entry;
  public ApprovalStatus Status { get; set; } = status;
  public string Name => Entry.Model.Name;
  public string Source => Entry.Endpoint?.Name ?? "Local model file";
  public string Location => Entry.FilePath ?? Entry.Endpoint?.Url ?? "";
  public string Digest => string.IsNullOrEmpty(Entry.Model.Digest) ? "Not supplied · identity unverified" : Entry.Model.Digest;
  public string Size => Entry.Model.Size > 0 ? $"{Entry.Model.Size / 1_073_741_824d:0.0} GB" : "Unknown";
  public string Availability => LastRun ?? Entry.Availability;
  public string StatusLabel => Status switch { ApprovalStatus.Approved => "✓  Approved", ApprovalStatus.Rejected => "×  Rejected", ApprovalStatus.ApprovedWithRestrictions => "!  Restricted", _ => "◷  NotYetQualified" };
  public Brush StatusColor => Status switch { ApprovalStatus.Approved => Brushes.SpringGreen, ApprovalStatus.Rejected => Brushes.Salmon, _ => Brushes.Gold };
 }
}
