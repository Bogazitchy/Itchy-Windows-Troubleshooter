using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using ItchyWindowsTroubleshooter.Models;
using ItchyWindowsTroubleshooter.Services;
using Microsoft.Win32;

namespace ItchyWindowsTroubleshooter;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    public static RoutedUICommand CopyTextCommand { get; } = new("Metni Kopyala", nameof(CopyTextCommand), typeof(MainWindow));
    public static RoutedUICommand CopyTextSelectionCommand { get; } = new("Secileni Kopyala", nameof(CopyTextSelectionCommand), typeof(MainWindow));
    public static RoutedUICommand CopyAllTextCommand { get; } = new("Tumunu Kopyala", nameof(CopyAllTextCommand), typeof(MainWindow));
    public static RoutedUICommand CopySelectedRowsCommand { get; } = new("Secili Satirlari Kopyala", nameof(CopySelectedRowsCommand), typeof(MainWindow));
    public static RoutedUICommand CopyAllRowsCommand { get; } = new("Tum Tabloyu Kopyala", nameof(CopyAllRowsCommand), typeof(MainWindow));

    private readonly LogService _logService = new();
    private readonly CommandRunner _commandRunner;
    private readonly SystemAnalysisService _analysisService;
    private readonly RepairService _repairService;
    private readonly ShortcutService _shortcutService = new();
    private readonly RestorePointService _restorePointService;
    private readonly ReportService _reportService = new();
    private readonly DispatcherTimer _temperatureTimer = new() { Interval = TimeSpan.FromMinutes(1) };
    private CancellationTokenSource? _cts;
    private bool _temperatureRefreshRunning;
    private string _systemStatus = "Taranmadi";
    private string _headerSummary = "Genel tarama baslatildiginda Windows kayitlari ve temel sistem durumu okunur.";
    private string _analysisSummary = "Tarama sonrasinda burada sade analiz sonucu gorunecek.";
    private string _blueScreenSummary = "Derin dump analizi henuz calistirilmadi.";
    private string _adminStatus = "";
    private string _systemInfoText = "";
    private string _lastScanText = "Henuz yok";
    private string _liveLog = "";
    private string _protectionStatus = "Durum henuz okunmadi.";
    private string _reportPath = "";
    private string _temperatureRefreshText = "Sistem bilgileri yukleniyor...";
    private string _scanStage = "Hazir";
    private bool _isBusy;
    private int _criticalCount;
    private int _warningCount;
    private int _infoCount;

    public MainWindow()
    {
        InitializeComponent();
        _commandRunner = new CommandRunner(AppendLogAsync);
        _analysisService = new SystemAnalysisService(_commandRunner, AppendLogAsync);
        _repairService = new RepairService(_commandRunner);
        _restorePointService = new RestorePointService(_commandRunner);

        Shortcuts = new ObservableCollection<ShortcutItem>(_shortcutService.GetShortcuts());
        AdminStatus = IsAdministrator() ? "Yonetici izni: Var" : "Yonetici izni: Yok. Bazi onarimlar icin yonetici olarak calistirin.";
        DataContext = this;
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
        Closed += MainWindow_Closed;
        SourceInitialized += (_, _) => ApplyWindowTheme();
        AddHandler(Mouse.PreviewMouseDownEvent, new MouseButtonEventHandler(DataGrid_PreviewMouseRightButtonDown), true);
        _temperatureTimer.Tick += TemperatureTimer_Tick;
        _ = RefreshProtectionAsync();
    }

    public ObservableCollection<Finding> Findings { get; } = new();
    public ObservableCollection<BlueScreenRecord> BlueScreenItems { get; } = new();
    public ObservableCollection<DumpAnalysisItem> DumpAnalyses { get; } = new();
    public ObservableCollection<EventRecordItem> EventItems { get; } = new();
    public ObservableCollection<ReliabilityRecordItem> ReliabilityItems { get; } = new();
    public ObservableCollection<DiagnosticLogItem> DiagnosticItems { get; } = new();
    public ObservableCollection<HealthCheckItem> HealthChecks { get; } = new();
    public ObservableCollection<ScanCoverageItem> ScanCoverage { get; } = new();
    public ObservableCollection<SystemInfoItem> SystemDetails { get; } = new();
    public ObservableCollection<DriverInfoItem> DriverItems { get; } = new();
    public ObservableCollection<ResourceMetricItem> ResourceMetrics { get; } = new();
    public ObservableCollection<RestorePointItem> RestorePoints { get; } = new();
    public ObservableCollection<ShortcutItem> Shortcuts { get; }
    public List<RepairResult> RepairHistory { get; } = new();

    public string SystemStatus { get => _systemStatus; set => SetField(ref _systemStatus, value); }
    public string HeaderSummary { get => _headerSummary; set => SetField(ref _headerSummary, value); }
    public string AnalysisSummary { get => _analysisSummary; set => SetField(ref _analysisSummary, value); }
    public string BlueScreenSummary { get => _blueScreenSummary; set => SetField(ref _blueScreenSummary, value); }
    public string AdminStatus { get => _adminStatus; set => SetField(ref _adminStatus, value); }
    public string SystemInfoText { get => _systemInfoText; set => SetField(ref _systemInfoText, value); }
    public string LastScanText { get => _lastScanText; set => SetField(ref _lastScanText, value); }
    public string LiveLog { get => _liveLog; set => SetField(ref _liveLog, value); }
    public string ProtectionStatus { get => _protectionStatus; set => SetField(ref _protectionStatus, value); }
    public string ReportPath { get => _reportPath; set => SetField(ref _reportPath, value); }
    public string TemperatureRefreshText { get => _temperatureRefreshText; set => SetField(ref _temperatureRefreshText, value); }
    public string ScanStage { get => _scanStage; set => SetField(ref _scanStage, value); }
    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (_isBusy == value) return;
            _isBusy = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsBusy)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsIdle)));
        }
    }
    public bool IsIdle => !IsBusy;
    public int CriticalCount { get => _criticalCount; set => SetField(ref _criticalCount, value); }
    public int WarningCount { get => _warningCount; set => SetField(ref _warningCount, value); }
    public int InfoCount { get => _infoCount; set => SetField(ref _infoCount, value); }

    public event PropertyChangedEventHandler? PropertyChanged;

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        Loaded -= MainWindow_Loaded;
        await LoadStartupSystemInfoAsync();
        _temperatureTimer.Start();
    }

    private void MainWindow_Closed(object? sender, EventArgs e)
    {
        _temperatureTimer.Stop();
        _cts?.Cancel();
    }

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (!IsBusy)
        {
            return;
        }

        e.Cancel = true;
        AppendLog("Tarama devam ederken pencere kapatma istegi engellendi. Once taramayi iptal edin.");
    }

    private async void TemperatureTimer_Tick(object? sender, EventArgs e)
    {
        await RefreshTemperaturesAsync();
    }

    private async Task LoadStartupSystemInfoAsync()
    {
        try
        {
            AppendLog("Acilis sistem envanteri okunuyor.");
            var detailsTask = _analysisService.GetSystemDetailsAsync(CancellationToken.None);
            var driversTask = _analysisService.GetDriverDetailsAsync(CancellationToken.None);
            await Task.WhenAll(detailsTask, driversTask);
            ReplaceCollection(SystemDetails, await detailsTask);
            ReplaceCollection(DriverItems, await driversTask);
            SystemInfoText = SystemInventoryService.BuildTextSummary(SystemDetails.ToList());
            TemperatureRefreshText = $"Sicakliklar her dakika yenilenir. Son yenileme: {DateTime.Now:HH:mm:ss}";
            AppendLog("Acilis sistem envanteri hazir.");
        }
        catch (Exception ex)
        {
            TemperatureRefreshText = "Sistem bilgileri yuklenemedi.";
            AppendLog($"Acilis sistem bilgileri okunamadi: {ex.Message}");
        }
    }

    private async Task RefreshTemperaturesAsync()
    {
        if (IsBusy || _temperatureRefreshRunning)
        {
            return;
        }

        _temperatureRefreshRunning = true;
        try
        {
            var temperatures = await _analysisService.GetTemperaturesAsync(CancellationToken.None);
            foreach (var oldItem in SystemDetails.Where(IsTemperatureItem).ToList())
            {
                SystemDetails.Remove(oldItem);
            }

            foreach (var item in temperatures)
            {
                SystemDetails.Add(item);
            }

            SystemInfoText = SystemInventoryService.BuildTextSummary(SystemDetails.ToList());
            TemperatureRefreshText = $"Sicakliklar her dakika yenilenir. Son yenileme: {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex)
        {
            TemperatureRefreshText = $"Sicaklik yenilenemedi: {DateTime.Now:HH:mm:ss}";
            AppendLog($"Sicaklik yenileme hatasi: {ex.Message}");
        }
        finally
        {
            _temperatureRefreshRunning = false;
        }
    }

    private async void StartScan_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync(async token =>
        {
            ClearScanData();
            AppendLog("Genel sistem taramasi basladi.");
            var result = await _analysisService.RunGeneralScanAsync(token);
            ApplyResult(result);
        });
    }

    private async void BlueScreen_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync(async token =>
        {
            BlueScreenItems.Clear();
            DumpAnalyses.Clear();
            BlueScreenSummary = "Dump dosyalari ve semboller analiz ediliyor...";
            var result = await _analysisService.AnalyzeBlueScreensAsync(token);
            ApplyBlueScreenResult(result);
        });
    }

    private async void SelectDump_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Analiz edilecek dump dosyasini secin",
            Filter = "Windows dump dosyalari (*.dmp;*.mdmp;*.hdmp;*.kdmp)|*.dmp;*.mdmp;*.hdmp;*.kdmp|Tum dosyalar (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        await RunBusyAsync(async token =>
        {
            BlueScreenItems.Clear();
            DumpAnalyses.Clear();
            BlueScreenSummary = $"{Path.GetFileName(dialog.FileName)} analiz ediliyor...";
            var result = await _analysisService.AnalyzeSelectedDumpAsync(dialog.FileName, token);
            ApplyBlueScreenResult(result);
        });
    }

    private async void InstallWinDbg_Click(object sender, RoutedEventArgs e)
    {
        var answer = MessageBox.Show(
            "Microsoft WinDbg kurulacak veya guncellenecek. Bu arac dump dosyalarinda sembol, stack ve supheli surucu analizi icin gereklidir. Devam edilsin mi?",
            "WinDbg kurulumu",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Information);
        if (answer != MessageBoxResult.OK)
        {
            return;
        }

        await RunBusyAsync(async token =>
        {
            var result = await _commandRunner.RunCmdAsync(
                "winget install --id Microsoft.WinDbg -e --accept-package-agreements --accept-source-agreements",
                token);
            AppendLog(result.Success ? "WinDbg kurulum komutu tamamlandi." : "WinDbg winget ile kurulamadi; resmi kurulum sayfasi aciliyor.");
            if (!result.Success)
            {
                Process.Start(new ProcessStartInfo("https://learn.microsoft.com/windows-hardware/drivers/debugger/") { UseShellExecute = true });
            }
        });
    }

    private async void ErrorAnalysis_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync(async token =>
        {
            EventItems.Clear();
            var items = await _analysisService.GetImportantEventsAsync(30, token);
            foreach (var item in items)
            {
                EventItems.Add(item);
            }
        });
    }

    private async void Reliability_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync(async token =>
        {
            ReliabilityItems.Clear();
            var items = await _analysisService.GetReliabilityRecordsAsync(30, token);
            foreach (var item in items)
            {
                ReliabilityItems.Add(item);
            }
        });
    }

    private async void Protection_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync(_ => RefreshProtectionAsync());
    }

    private async void CreateRestorePoint_Click(object sender, RoutedEventArgs e)
    {
        var answer = MessageBox.Show(
            "Geri yukleme noktasi olusturulacak. Bu islem yonetici izni ve Sistem Koruma'nin acik olmasini gerektirebilir.",
            "Onay",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Information);

        if (answer != MessageBoxResult.OK)
        {
            return;
        }

        await RunBusyAsync(async token =>
        {
            var result = await _restorePointService.CreateRestorePointAsync("ITCHY onarim oncesi nokta", token);
            AppendLog(result.Output);
            await RefreshProtectionAsync();
        });
    }

    private void OpenProtection_Click(object sender, RoutedEventArgs e)
    {
        _shortcutService.Open("SystemPropertiesProtection.exe");
    }

    private async void Repair_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button button || button.Tag is not string id)
        {
            return;
        }

        var plan = _repairService.GetPlan(id);
        if (plan is null)
        {
            return;
        }

        var message = $"{plan.Title}\n\n{plan.Description}\n\nGuvenli mi: {plan.Safety}\nSure: {plan.Duration}\nYeniden baslatma: {plan.RestartNote}\nYonetici izni: {plan.AdminNote}\n\nDevam edilsin mi?";
        var answer = MessageBox.Show(message, "Onarim onayi", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.OK)
        {
            AppendLog($"{plan.Title} kullanici tarafindan iptal edildi.");
            return;
        }

        await RunBusyAsync(async token =>
        {
            AppendLog($"{plan.Title} baslatildi.");
            var result = await _repairService.RunAsync(id, token);
            RepairHistory.Add(result);
            AppendLog(result.Output);
            AppendLog(result.Success ? $"{plan.Title} tamamlandi." : $"{plan.Title} hata ile bitti. Cikis kodu: {result.ExitCode}");
        });
    }

    private void Shortcut_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: ShortcutItem shortcut })
        {
            _shortcutService.Open(shortcut.Command);
        }
    }

    private async void CreateReport_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync(async token =>
        {
            var snapshot = new ReportSnapshot(
                SystemStatus,
                HeaderSummary,
                AnalysisSummary,
                BlueScreenSummary,
                SystemInfoText,
                Findings.ToList(),
                BlueScreenItems.ToList(),
                DumpAnalyses.ToList(),
                EventItems.ToList(),
                ReliabilityItems.ToList(),
                DiagnosticItems.ToList(),
                HealthChecks.ToList(),
                ScanCoverage.ToList(),
                SystemDetails.ToList(),
                DriverItems.ToList(),
                ResourceMetrics.ToList(),
                RestorePoints.ToList(),
                RepairHistory.ToList(),
                ProtectionStatus,
                LiveLog);

            var report = await _reportService.CreateReportAsync(snapshot, token);
            ReportPath = $"Rapor olusturuldu:\nHTML: {report.HtmlPath}\nTXT: {report.TextPath}";
            AppendLog(ReportPath);
            Process.Start(new ProcessStartInfo(report.HtmlPath) { UseShellExecute = true });
        });
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        AppendLog("Iptal istegi gonderildi.");
    }

    private void CopyText_Executed(object sender, ExecutedRoutedEventArgs e)
    {
        if (e.OriginalSource is TextBlock { Text.Length: > 0 } textBlock)
        {
            SetClipboardText(textBlock.Text);
        }
    }

    private void CopyTextSelection_Executed(object sender, ExecutedRoutedEventArgs e)
    {
        if (e.OriginalSource is not TextBox textBox)
        {
            return;
        }

        SetClipboardText(string.IsNullOrEmpty(textBox.SelectedText) ? textBox.Text : textBox.SelectedText);
    }

    private void CopyAllText_Executed(object sender, ExecutedRoutedEventArgs e)
    {
        if (e.OriginalSource is TextBox { Text.Length: > 0 } textBox)
        {
            SetClipboardText(textBox.Text);
        }
    }

    private void DataGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Right || e.OriginalSource is not DependencyObject source)
        {
            return;
        }

        var grid = FindVisualParent<DataGrid>(source);
        var row = FindVisualParent<DataGridRow>(source);
        if (grid is null || row is null || grid.SelectedItems.Contains(row.Item))
        {
            return;
        }

        grid.SelectedItems.Clear();
        row.IsSelected = true;
        grid.CurrentItem = row.Item;
    }

    private void CopySelectedRows_Executed(object sender, ExecutedRoutedEventArgs e)
    {
        if (e.OriginalSource is not DataGrid grid)
        {
            return;
        }

        var rows = grid.SelectedItems.Cast<object>().ToList();
        if (rows.Count == 0 && grid.CurrentItem is not null)
        {
            rows.Add(grid.CurrentItem);
        }

        CopyGridRows(grid, rows);
    }

    private void CopyAllRows_Executed(object sender, ExecutedRoutedEventArgs e)
    {
        if (e.OriginalSource is not DataGrid grid)
        {
            return;
        }

        var rows = grid.Items.Cast<object>()
            .Where(x => x != CollectionView.NewItemPlaceholder)
            .ToList();
        CopyGridRows(grid, rows);
    }

    private static void CopyGridRows(DataGrid grid, IReadOnlyList<object> rows)
    {
        if (rows.Count == 0)
        {
            return;
        }

        var columns = grid.Columns
            .Where(x => x.Visibility == Visibility.Visible)
            .OrderBy(x => x.DisplayIndex)
            .ToList();
        var text = new StringBuilder();
        text.AppendLine(string.Join('\t', columns.Select(x => NormalizeClipboardCell(x.Header))));
        foreach (var row in rows)
        {
            text.AppendLine(string.Join('\t', columns.Select(x => NormalizeClipboardCell(x.OnCopyingCellClipboardContent(row)))));
        }

        SetClipboardText(text.ToString().TrimEnd());
    }

    private static string NormalizeClipboardCell(object? value)
    {
        return (value?.ToString() ?? "")
            .Replace('\t', ' ')
            .Replace("\r", " ")
            .Replace("\n", " ");
    }

    private static T? FindVisualParent<T>(DependencyObject child) where T : DependencyObject
    {
        var current = child;
        while (current is not null)
        {
            if (current is T match)
            {
                return match;
            }

            current = current is Visual
                ? VisualTreeHelper.GetParent(current)
                : LogicalTreeHelper.GetParent(current);
        }

        return null;
    }

    private static void SetClipboardText(string text)
    {
        if (!string.IsNullOrWhiteSpace(text))
        {
            Clipboard.SetDataObject(text, true);
        }
    }

    private async Task RunBusyAsync(Func<CancellationToken, Task> work)
    {
        if (IsBusy)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        IsBusy = true;
        try
        {
            await work(_cts.Token);
        }
        catch (OperationCanceledException)
        {
            ScanStage = "Tarama iptal edildi";
            AppendLog("Islem iptal edildi.");
        }
        catch (Exception ex)
        {
            ScanStage = "Tarama hatayla durdu";
            AppendLog($"Hata: {ex.Message}");
            MessageBox.Show(ex.Message, "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsBusy = false;
            _cts.Dispose();
            _cts = null;
        }
    }

    private void ApplyResult(GeneralScanResult result)
    {
        foreach (var item in result.Findings)
        {
            Findings.Add(item);
        }

        foreach (var item in result.BlueScreens)
        {
            BlueScreenItems.Add(item);
        }

        foreach (var item in result.DumpAnalyses)
        {
            DumpAnalyses.Add(item);
        }

        foreach (var item in result.Events)
        {
            EventItems.Add(item);
        }

        foreach (var item in result.ReliabilityRecords)
        {
            ReliabilityItems.Add(item);
        }

        foreach (var item in result.DiagnosticLogs)
        {
            DiagnosticItems.Add(item);
        }

        foreach (var item in result.HealthChecks)
        {
            HealthChecks.Add(item);
        }

        foreach (var item in result.ScanCoverage)
        {
            ScanCoverage.Add(item);
        }

        ReplaceCollection(SystemDetails, result.SystemDetails);
        ReplaceCollection(DriverItems, result.Drivers);

        foreach (var item in result.ResourceMetrics)
        {
            ResourceMetrics.Add(item);
        }

        CriticalCount = result.Findings.Count(x => x.Severity == Severity.Critical);
        WarningCount = result.Findings.Count(x => x.Severity == Severity.Warning);
        InfoCount = result.Findings.Count(x => x.Severity == Severity.Info);
        var strongRootCause = result.Findings.Any(x => x.IsRootCauseCandidate && x.Severity == Severity.Critical && x.ConfidenceScore >= 70);
        var reviewCandidate = result.Findings.Any(x => x.IsRootCauseCandidate && x.Severity is Severity.Critical or Severity.Warning && x.ConfidenceScore >= 55);
        var hasActionableFinding = result.Findings.Any(x => x.Severity != Severity.Success);
        SystemStatus = strongRootCause ? "Dikkat Gerekli" : reviewCandidate ? "Incelenmeli" : hasActionableFinding ? "Izlenmeli" : "Iyi";
        var coverageScore = result.ScanCoverage.Count == 0
            ? 0
            : (int)Math.Round(result.ScanCoverage.Sum(x => x.Status == "Tamamlandi" ? 1.0 : x.Status == "Kismi" ? 0.5 : 0) / result.ScanCoverage.Count * 100);
        HeaderSummary = $"{CriticalCount} kritik bulgu, {WarningCount} uyari, {InfoCount} bilgi. Tarama kapsami %{coverageScore}.";
        AnalysisSummary = result.UserSummary;
        BlueScreenSummary = result.BlueScreenSummary;
        LastScanText = DateTime.Now.ToString("dd.MM.yyyy HH:mm");
        SystemInfoText = result.SystemInfo;
        TemperatureRefreshText = $"Sicakliklar her dakika yenilenir. Son yenileme: {DateTime.Now:HH:mm:ss}";
        ScanStage = "Tarama tamamlandi";
        AppendLog("Genel sistem taramasi tamamlandi.");
    }

    private async Task RefreshProtectionAsync()
    {
        var status = await _restorePointService.GetProtectionStatusAsync(CancellationToken.None);
        ProtectionStatus = status.Summary;
        RestorePoints.Clear();
        foreach (var item in status.RestorePoints)
        {
            RestorePoints.Add(item);
        }
    }

    private void ClearScanData()
    {
        Findings.Clear();
        BlueScreenItems.Clear();
        DumpAnalyses.Clear();
        EventItems.Clear();
        ReliabilityItems.Clear();
        DiagnosticItems.Clear();
        HealthChecks.Clear();
        ScanCoverage.Clear();
        ResourceMetrics.Clear();
        CriticalCount = 0;
        WarningCount = 0;
        InfoCount = 0;
        ScanStage = "Tarama hazirlaniyor";
        AnalysisSummary = "Tarama calisiyor. Event Viewer, Guvenilirlik Gecmisi, kaynak kullanimi, aygitlar, suruculer ve donanim sensorleri okunuyor.";
        BlueScreenSummary = "Dump dosyalari, stop code, semboller, stack ve olay korelasyonu analiz ediliyor.";
    }

    private void ApplyBlueScreenResult(BlueScreenScanResult result)
    {
        BlueScreenSummary = result.Summary;
        foreach (var item in result.DumpAnalyses)
        {
            DumpAnalyses.Add(item);
        }

        foreach (var item in result.Signals)
        {
            BlueScreenItems.Add(item);
        }

        AppendLog($"Mavi ekran analizi tamamlandi: {result.DumpAnalyses.Count} dump, {result.Signals.Count} olay/dosya sinyali.");
    }

    private Task AppendLogAsync(string text)
    {
        Dispatcher.Invoke(() =>
        {
            var stage = ResolveScanStage(text);
            if (!string.IsNullOrWhiteSpace(stage))
            {
                ScanStage = stage;
            }

            AppendLog(text);
        });
        return Task.CompletedTask;
    }

    private static string? ResolveScanStage(string text)
    {
        if (text.Contains("Genel tarama", StringComparison.OrdinalIgnoreCase)) return "Tarama kaynaklari hazirlaniyor";
        if (text.Contains("Event Viewer", StringComparison.OrdinalIgnoreCase) || text.Contains("olay kayit", StringComparison.OrdinalIgnoreCase)) return "Olay kayitlari okunuyor";
        if (text.Contains("Reliability", StringComparison.OrdinalIgnoreCase) || text.Contains("Guvenilirlik", StringComparison.OrdinalIgnoreCase)) return "Guvenilirlik gecmisi okunuyor";
        if (text.Contains("Aygit Yoneticisi", StringComparison.OrdinalIgnoreCase) || text.Contains("surucu envanteri", StringComparison.OrdinalIgnoreCase)) return "Aygit ve suruculer kontrol ediliyor";
        if (text.Contains("kaynak", StringComparison.OrdinalIgnoreCase) || text.Contains("performans", StringComparison.OrdinalIgnoreCase)) return "Kaynak kullanimi ornekleniyor";
        if (text.Contains("saglik", StringComparison.OrdinalIgnoreCase) || text.Contains("DISM", StringComparison.OrdinalIgnoreCase)) return "Sistem sagligi denetleniyor";
        if (text.Contains("dump", StringComparison.OrdinalIgnoreCase) || text.Contains("Mavi ekran", StringComparison.OrdinalIgnoreCase)) return "Dump ve cokme kayitlari analiz ediliyor";
        return null;
    }

    private void AppendLog(string text)
    {
        var line = $"[{DateTime.Now:HH:mm:ss}] {text}";
        LiveLog = string.IsNullOrWhiteSpace(LiveLog) ? line : $"{LiveLog}{Environment.NewLine}{line}";
        _logService.Write(line);
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private void ApplyWindowTheme()
    {
        try
        {
            var handle = new WindowInteropHelper(this).Handle;
            var darkMode = 1;
            if (DwmSetWindowAttribute(handle, 20, ref darkMode, sizeof(int)) != 0)
            {
                DwmSetWindowAttribute(handle, 19, ref darkMode, sizeof(int));
            }

            var borderColor = 0x003D3630;
            var captionColor = 0x0017110D;
            var textColor = 0x00FCF6F0;
            DwmSetWindowAttribute(handle, 34, ref borderColor, sizeof(int));
            DwmSetWindowAttribute(handle, 35, ref captionColor, sizeof(int));
            DwmSetWindowAttribute(handle, 36, ref textColor, sizeof(int));
        }
        catch
        {
        }
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr windowHandle, int attribute, ref int value, int valueSize);

    private static bool IsTemperatureItem(SystemInfoItem item)
    {
        return item.Category.Equals("CPU Sicakligi", StringComparison.OrdinalIgnoreCase) ||
               item.Category.Equals("GPU Sicakligi", StringComparison.OrdinalIgnoreCase);
    }

    private static void ReplaceCollection<T>(ObservableCollection<T> target, IEnumerable<T> items)
    {
        target.Clear();
        foreach (var item in items)
        {
            target.Add(item);
        }
    }

    private void SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
