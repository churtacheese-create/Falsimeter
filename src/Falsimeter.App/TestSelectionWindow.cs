using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Falsimeter.Core;

namespace Falsimeter.App;
public sealed class TestSelectionWindow : Window
{
    private readonly HashSet<string> _selected;
    public IReadOnlyCollection<string> SelectedIds => _selected;
    public TestSelectionWindow(IReadOnlyList<TestDefinition> catalog, IEnumerable<string> selected)
    {
        _selected = new(selected, StringComparer.Ordinal);
        Title = "Falsimeter — Test catalog"; Width = 1020; Height = 760; MinWidth = 740; MinHeight = 480;
        Background = new SolidColorBrush(Color.FromRgb(12,22,35)); Foreground = Brushes.White;
        var root = new DockPanel { Margin = new Thickness(24), Background = Background }; Content = root;
        var top = new StackPanel(); DockPanel.SetDock(top, Dock.Top); root.Children.Add(top);
        top.Children.Add(new TextBlock { Text = "Choose tests", FontSize = 30, FontWeight = FontWeights.SemiBold });
        top.Children.Add(new TextBlock { Text = "Only checked tests run against checked models. Each probe is a limited measurement, not a certification.\nTests that need local collectors or a lab harness show their requirements below. If setup is incomplete, the result is Needs setup.", Margin = new Thickness(0,8,0,12), TextWrapping = TextWrapping.Wrap, Foreground = Brushes.LightSteelBlue });
        var search = new TextBox { Margin = new Thickness(0,0,0,12), Padding = new Thickness(9), ToolTip = "Search test name, group or description" }; top.Children.Add(search);
        var bottom = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0,12,0,0) }; DockPanel.SetDock(bottom, Dock.Bottom); root.Children.Add(bottom);
        var apply = new Button { Content = "Use checked tests", Padding = new Thickness(18,10,18,10) }; apply.Click += (_,_) => { DialogResult = true; }; bottom.Children.Add(apply);
        var clear = new Button { Content = "Clear all", Padding = new Thickness(18,10,18,10), Margin = new Thickness(12,0,12,0) }; bottom.Children.Add(clear);
        var count = new TextBlock { VerticalAlignment = VerticalAlignment.Center }; bottom.Children.Add(count);
        var items = new StackPanel(); root.Children.Add(new ScrollViewer { Content = items, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        void Count() => count.Text = $"{_selected.Count} checked / {catalog.Count} catalog entries";
        void Render() {
            items.Children.Clear();
            foreach (var group in catalog.Where(t => string.IsNullOrWhiteSpace(search.Text) || (t.Name + " " + t.Description + " " + t.Group).Contains(search.Text, StringComparison.OrdinalIgnoreCase)).GroupBy(t => t.Group)) {
                items.Children.Add(new TextBlock { Text = group.Key, FontSize = 19, Foreground = Brushes.DeepSkyBlue, Margin = new Thickness(0,18,0,10) });
                foreach (var test in group) {
                    var text = new StackPanel();
                    text.Children.Add(new TextBlock { Text = test.Name, FontSize = 16, FontWeight = FontWeights.SemiBold });
                    text.Children.Add(new TextBlock { Text = test.Description, TextWrapping = TextWrapping.Wrap, Foreground = Brushes.LightSteelBlue, Margin = new Thickness(0,5,0,4), MaxWidth = 820, MaxHeight = 160 });
                    text.Children.Add(new TextBlock { Text = test.IsBuiltIn ? "Built in · " + test.Requirement : "Local setup required · " + test.Requirement, Foreground = test.IsBuiltIn ? Brushes.LightGreen : Brushes.Gold, TextWrapping = TextWrapping.Wrap, MaxWidth = 820 });
                    var check = new CheckBox { Content = text, IsChecked = _selected.Contains(test.Id), Foreground = Brushes.White, Margin = new Thickness(0,0,0,14), Padding = new Thickness(8,0,0,0) };
                    check.Checked += (_,_) => { _selected.Add(test.Id); Count(); }; check.Unchecked += (_,_) => { _selected.Remove(test.Id); Count(); }; items.Children.Add(check);
                }
            }
            Count();
        }
        search.TextChanged += (_,_) => Render(); clear.Click += (_,_) => { _selected.Clear(); Render(); }; Render();
    }
}
