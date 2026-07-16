using System.Windows.Media;

namespace ItchyWindowsTroubleshooter.Models;

public enum Severity
{
    Critical,
    Warning,
    Info,
    Success
}

public sealed record Finding(Severity Severity, string Title, string Cause, string Evidence, string Recommendation)
{
    public int ConfidenceScore { get; init; } = 50;
    public string Correlation { get; init; } = "Tek veri kaynagi";
    public string Component { get; init; } = "Windows";
    public string Role { get; init; } = "Kok Neden Adayi";
    public DateTime? LatestOccurrence { get; init; }
    public int OccurrenceCount { get; init; } = 1;
    public int IndependentSourceCount { get; init; } = 1;
    public string CrashRelation { get; init; } = "Dogrudan zaman eslesmesi yok";
    public string SearchKey { get; init; } = string.Empty;

    public bool IsRootCauseCandidate => Role is "Dogrudan Ariza" or "Kok Neden Adayi";

    public string SeverityText => Severity switch
    {
        Severity.Critical => "Kritik",
        Severity.Warning => "Uyari",
        Severity.Success => "Basarili",
        _ => "Bilgi"
    };

    public string Confidence => ConfidenceScore switch
    {
        >= 90 => "Cok Yuksek",
        >= 75 => "Yuksek",
        >= 50 => "Orta",
        >= 30 => "Dusuk",
        _ => "Cok Dusuk"
    };

    public string RecencyText
    {
        get
        {
            if (!LatestOccurrence.HasValue)
            {
                return "Zaman bilgisi yok";
            }

            var age = DateTime.Now - LatestOccurrence.Value;
            if (age.TotalHours <= 24) return "Son 24 saat";
            if (age.TotalDays <= 7) return "Son 7 gun";
            if (age.TotalDays <= 30) return "Son 30 gun";
            return "Eski kayit";
        }
    }

    public Brush SeverityBrush => Severity switch
    {
        Severity.Critical => Brushes.IndianRed,
        Severity.Warning => Brushes.Orange,
        Severity.Success => Brushes.MediumSeaGreen,
        _ => Brushes.DeepSkyBlue
    };

    public Brush ConfidenceBrush => ConfidenceScore switch
    {
        >= 90 => Brushes.IndianRed,
        >= 75 => Brushes.Orange,
        >= 50 => Brushes.Gold,
        _ => Brushes.DeepSkyBlue
    };
}

public sealed record BlueScreenRecord(string Title, string Summary, string TechnicalDetail, DateTime? TimeCreated);

public sealed record DumpAnalysisItem(
    string FileName,
    string FilePath,
    DateTime? CreatedAt,
    string FileSize,
    string IntegrityStatus,
    string AnalysisStatus,
    string BugCheckCode,
    string BugCheckName,
    string BugCheckParameters,
    string SuspectedComponent,
    string ComponentDetails,
    string ProcessName,
    string FailureBucket,
    string Confidence,
    string RootCauseSummary,
    string Evidence,
    string CorrelatedEvents,
    string Recommendation,
    string DebuggerUsed,
    string RawDebuggerOutput)
{
    public Brush ConfidenceBrush => Confidence switch
    {
        "Yuksek" => Brushes.IndianRed,
        "Orta-Yuksek" => Brushes.OrangeRed,
        "Orta" => Brushes.Orange,
        _ => Brushes.DeepSkyBlue
    };
}

public sealed record BlueScreenScanResult(
    string Summary,
    IReadOnlyList<DumpAnalysisItem> DumpAnalyses,
    IReadOnlyList<BlueScreenRecord> Signals);

public sealed record EventRecordItem(DateTime? TimeCreated, string LogName, string Provider, int Id, string Level, string Message);

public sealed record ReliabilityRecordItem(DateTime? TimeGenerated, string SourceName, string ProductName, string Message);

public sealed record DiagnosticLogItem(
    DateTime? TimeCreated,
    string Category,
    string Component,
    string Source,
    string Code,
    string Summary);

public sealed record SystemInfoItem(string Category, string Name, string Value, string Status);

public sealed record DriverInfoItem(
    string Category,
    string DeviceName,
    string Manufacturer,
    string DriverVersion,
    string DriverDate,
    string HardwareId,
    string Status);

public sealed record ResourceMetricItem(string Name, string Value, string Status, string Detail);

public sealed record HealthCheckItem(
    DateTime? ObservedAt,
    string Category,
    string Component,
    string Status,
    string Value,
    string Detail);

public sealed record ScanCoverageItem(string Source, string Status, int RecordCount, string Detail);

public sealed record SystemHealthScanResult(
    IReadOnlyList<HealthCheckItem> Checks,
    IReadOnlyList<ScanCoverageItem> Coverage);

public sealed record ResourceScanResult(
    IReadOnlyList<ResourceMetricItem> Metrics,
    double CpuAverage,
    double CpuPeak,
    double MemoryAverage,
    double DiskAverage,
    double DiskPeak,
    double DiskQueuePeak,
    string TopCpuProcess,
    double TopCpuPercent,
    string TopMemoryProcess,
    double TopMemoryMb);

public sealed record RestorePointItem(DateTime? CreatedAt, string Description, string Type);

public sealed record ShortcutItem(string Name, string Command, string Description);

public sealed record CommandResult(string Command, int ExitCode, string Output, bool Success);

public sealed record RepairPlan(string Id, string Title, string Description, string Safety, string Duration, string RestartNote, string AdminNote);

public sealed record RepairResult(string Title, bool Success, int ExitCode, string Output, DateTime StartedAt, DateTime FinishedAt);

public sealed record ProtectionStatus(string Summary, IReadOnlyList<RestorePointItem> RestorePoints);

public sealed record GeneralScanResult(
    string UserSummary,
    string BlueScreenSummary,
    string SystemInfo,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<BlueScreenRecord> BlueScreens,
    IReadOnlyList<DumpAnalysisItem> DumpAnalyses,
    IReadOnlyList<EventRecordItem> Events,
    IReadOnlyList<ReliabilityRecordItem> ReliabilityRecords,
    IReadOnlyList<DiagnosticLogItem> DiagnosticLogs,
    IReadOnlyList<HealthCheckItem> HealthChecks,
    IReadOnlyList<ScanCoverageItem> ScanCoverage,
    IReadOnlyList<SystemInfoItem> SystemDetails,
    IReadOnlyList<DriverInfoItem> Drivers,
    IReadOnlyList<ResourceMetricItem> ResourceMetrics);

public sealed record ReportSnapshot(
    string SystemStatus,
    string HeaderSummary,
    string AnalysisSummary,
    string BlueScreenSummary,
    string SystemInfo,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<BlueScreenRecord> BlueScreens,
    IReadOnlyList<DumpAnalysisItem> DumpAnalyses,
    IReadOnlyList<EventRecordItem> Events,
    IReadOnlyList<ReliabilityRecordItem> ReliabilityRecords,
    IReadOnlyList<DiagnosticLogItem> DiagnosticLogs,
    IReadOnlyList<HealthCheckItem> HealthChecks,
    IReadOnlyList<ScanCoverageItem> ScanCoverage,
    IReadOnlyList<SystemInfoItem> SystemDetails,
    IReadOnlyList<DriverInfoItem> Drivers,
    IReadOnlyList<ResourceMetricItem> ResourceMetrics,
    IReadOnlyList<RestorePointItem> RestorePoints,
    IReadOnlyList<RepairResult> RepairHistory,
    string ProtectionStatus,
    string LogText);

public sealed record ReportResult(string HtmlPath, string TextPath);
