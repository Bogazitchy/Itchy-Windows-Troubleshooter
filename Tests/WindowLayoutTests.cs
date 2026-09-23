using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Xunit;

namespace ItchyWindowsTroubleshooter.Tests;

public sealed class WindowLayoutTests
{
    [Fact]
    public async Task MainAndRepairViewsRenderAtNotebookSizes()
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                var window = new MainWindow(initializeBackgroundServices: false);
                var root = (Grid)window.Content;
                root.Background = window.Background;
                foreach (var (width, height) in new[] { (1320, 820), (1093, 560), (910, 470) })
                {
                    window.Height = height;
                    root.Measure(new Size(width, height));
                    root.Arrange(new Rect(0, 0, width, height));
                    root.UpdateLayout();
                    var tabs = Descendants(root).OfType<TabControl>().First();
                    foreach (var tab in tabs.Items.OfType<TabItem>().Where(x => x.Header?.ToString() is "Ana Panel" or "Onarım Araçları" or "Mavi Ekran"))
                    {
                        tabs.SelectedItem = tab;
                        root.Measure(new Size(width, height));
                        root.Arrange(new Rect(0, 0, width, height));
                        root.UpdateLayout();
                        Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.Render);
                        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
                        bitmap.Render(root);
                        var pixels = new byte[width * height * 4];
                        bitmap.CopyPixels(pixels, width * 4, 0);
                        Assert.Contains(pixels.Where((_, i) => i % 4 == 3), x => x != 0);
                        var directory = Path.Combine(AppContext.BaseDirectory, "layout-artifacts");
                        Directory.CreateDirectory(directory);
                        var name = tab.Header?.ToString()?.Replace(" ", "-") ?? "view";
                        var encoder = new PngBitmapEncoder();
                        encoder.Frames.Add(BitmapFrame.Create(bitmap));
                        using var output = File.Create(Path.Combine(directory, $"{width}x{height}-{name}.png"));
                        encoder.Save(output);
                        foreach (var button in Descendants(root).OfType<Button>().Where(x => x.IsVisible && x.ActualHeight > 0))
                            Assert.True(button.ActualHeight >= 20, $"Clipped button: {button.Content}");
                    }
                }
                window.Close();
                completion.SetResult();
            }
            catch (Exception ex) { completion.SetException(ex); }
            finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(30));
    }

    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            yield return child;
            foreach (var nested in Descendants(child)) yield return nested;
        }
    }
}
