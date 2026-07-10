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
    public Brush SeverityBrush => Severity switch
    {
        Severity.Critical => Brushes.IndianRed,
        Severity.Warning => Brushes.Orange,
        Severity.Success => Brushes.MediumSeaGreen,
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
    IReadOnlyList<SystemInfoItem> SystemDetails,
    IReadOnlyList<DriverInfoItem> Drivers,
    IReadOnlyList<ResourceMetricItem> ResourceMetrics,
    IReadOnlyList<RestorePointItem> RestorePoints,
    IReadOnlyList<RepairResult> RepairHistory,
    string ProtectionStatus,
    string LogText);

public sealed record ReportResult(string HtmlPath, string TextPath);
