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

    public string SeverityBrush => Severity switch
    {
        Severity.Critical => "IndianRed",
        Severity.Warning => "Orange",
        Severity.Success => "MediumSeaGreen",
        _ => "DeepSkyBlue"
    };

    public string ConfidenceBrush => ConfidenceScore switch
    {
        >= 90 => "IndianRed",
        >= 75 => "Orange",
        >= 50 => "Gold",
        _ => "DeepSkyBlue"
    };
}

public sealed record BlueScreenRecord(string Title, string Summary, string TechnicalDetail, DateTime? TimeCreated);

public enum RootCauseCategory
{
    GraphicsDriver,
    KernelDriverConflict,
    MemoryInstability,
    CpuInstability,
    Storage,
    Hardware,
    Power,
    NetworkDriver,
    SecurityOrAntiCheatDriver,
    Unknown
}

public enum FaultEvidenceSource { Unknown, ExceptionAddressModuleRange }
public enum AnalysisMode { LocalComputer, ExternalCase }
public enum DataAvailability { Read, Inaccessible, Unsupported, Partial, Uninterpretable }
public enum RepairOutcome { Succeeded, PartiallySucceeded, Failed, RestartRequired, Unverified }

public sealed record DumpAnalysisContext(AnalysisMode Mode)
{
    public bool AllowLocalData => Mode == AnalysisMode.LocalComputer;
    public IReadOnlyList<EventRecordItem> CaseEvents { get; init; } = [];
    public IReadOnlyList<DriverInfoItem> CaseDrivers { get; init; } = [];
    public static DumpAnalysisContext Local { get; } = new(AnalysisMode.LocalComputer);
    public static DumpAnalysisContext External { get; } = new(AnalysisMode.ExternalCase);
}

public sealed record StackDriverEvidence(
    string DriverName,
    string DisplayName,
    string Category,
    int StackOccurrences,
    bool DirectFault,
    bool ProbablyCausedBy,
    bool IsImageName,
    bool IsModuleName,
    bool IsThirdParty,
    string Metadata)
{
    public string OccurrenceText => $"{DriverName} x{StackOccurrences}";
}

public sealed record RootCauseCandidate(
    RootCauseCategory Category,
    string Title,
    int EvidenceScore,
    string Strength,
    string Evidence,
    string Interpretation,
    string Recommendation)
{
    public IReadOnlyList<string> RuleIds { get; init; } = [];
    public string RuleIdsText => string.Join(", ", RuleIds);
}

public sealed record RecurringPattern(string Title, string Evidence, string Interpretation);

public sealed record CrossDumpAnalysisResult(
    string Summary,
    string CommonPattern,
    string Diagnosis,
    string EvidenceSummary,
    string InterpretationSummary,
    IReadOnlyList<RootCauseCandidate> Candidates,
    IReadOnlyList<RecurringPattern> Patterns,
    IReadOnlyList<string> TroubleshootingSteps)
{
    public static CrossDumpAnalysisResult Empty { get; } = new(
        "Henuz toplu dump analizi yapilmadi.",
        "Karsilastirilabilir dump deseni yok.",
        "Teshis icin dump verisi gerekli.",
        "Dogrudan dump kaniti yok.",
        "Eksik veri temiz sistem anlamina gelmez.",
        [],
        [],
        []);

    public string CandidateSummary => Candidates.Count == 0
        ? "Siralanabilir kok neden adayi yok."
        : string.Join(Environment.NewLine, Candidates.Select((x, i) => $"{i + 1}. {x.Title} - {x.Strength}{Environment.NewLine}   {x.Evidence}"));

    public string TroubleshootingSummary => TroubleshootingSteps.Count == 0
        ? "Kanita dayali islem sirasi olusturulamadi."
        : string.Join(Environment.NewLine, TroubleshootingSteps.Select((x, i) => $"{i + 1}. {x}"));
}

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
    public FaultEvidenceSource FaultEvidenceSource { get; init; }
    public AnalysisMode AnalysisMode { get; init; }
    public string TimeSource { get; init; } = "Bilinmiyor";
    public string DisassemblyContext { get; init; } = "";
    public string ProvenanceSummary => $"Mod: {AnalysisMode}; zaman kaynağı: {TimeSource}; doğrudan kanıt: {FaultEvidenceSource}.";
    public bool SymbolsIncomplete { get; init; }
    public string ExceptionCode { get; init; } = "";
    public string ExceptionName { get; init; } = "";
    public string BugCheckString { get; init; } = "";
    public string AccessType { get; init; } = "";
    public string AttemptedAddress { get; init; } = "";
    public string ExceptionRecord { get; init; } = "";
    public string ContextRecord { get; init; } = "";
    public string FaultingThread { get; init; } = "";
    public string ReadAddress { get; init; } = "";
    public string WriteAddress { get; init; } = "";
    public string FaultingAddress { get; init; } = "";
    public string FaultingModule { get; init; } = "";
    public string FaultingSymbol { get; init; } = "";
    public string FaultingInstruction { get; init; } = "";
    public string FaultingIp { get; init; } = "";
    public string ProbablyCausedBy { get; init; } = "";
    public string ImageName { get; init; } = "";
    public string ModuleName { get; init; } = "";
    public string SymbolName { get; init; } = "";
    public string StackText { get; init; } = "";
    public string StackCommand { get; init; } = "";
    public string FailureIdHash { get; init; } = "";
    public string CustomerCrashCount { get; init; } = "";
    public string DefaultBucketId { get; init; } = "";
    public string RegisterContextStatus { get; init; } = "Register context minidump icinde mevcut degil.";
    public string RegisterSummary { get; init; } = "";
    public string PointerAnalysis { get; init; } = "";
    public string TechnicalInterpretation { get; init; } = "";
    public IReadOnlyList<StackDriverEvidence> ImportantThirdPartyDrivers { get; init; } = [];
    public IReadOnlyDictionary<string, int> StackDriverOccurrences { get; init; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
    public IReadOnlyList<string> MemoryCorruptionIndicators { get; init; } = [];
    public IReadOnlyList<string> InvalidPointerIndicators { get; init; } = [];
    public IReadOnlyList<RootCauseCandidate> RootCauseCandidates { get; init; } = [];

    public string ImportantThirdPartyDriversText => ImportantThirdPartyDrivers.Count == 0
        ? "Belirgin ucuncu parti stack surucusu yok."
        : string.Join(", ", ImportantThirdPartyDrivers.Select(x => x.OccurrenceText));

    public string ExceptionSummary => string.IsNullOrWhiteSpace(ExceptionCode)
        ? "Mevcut degil"
        : $"{ExceptionCode} {ExceptionName}".Trim() +
          (string.IsNullOrWhiteSpace(AccessType) ? "" : $" | {AccessType}") +
          (string.IsNullOrWhiteSpace(AttemptedAddress) ? "" : $" | {AttemptedAddress}");

    public string ConfidenceBrush => Confidence switch
    {
        "Yuksek" => "IndianRed",
        "Orta-Yuksek" => "OrangeRed",
        "Orta" => "Orange",
        _ => "DeepSkyBlue"
    };
}

public sealed record BlueScreenScanResult(
    string Summary,
    IReadOnlyList<DumpAnalysisItem> DumpAnalyses,
    IReadOnlyList<BlueScreenRecord> Signals)
{
    public CrossDumpAnalysisResult CrossDumpAnalysis { get; init; } = CrossDumpAnalysisResult.Empty;
}

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

public sealed record ResourceMetricItem(string Name, string Value, string Status, string Detail)
{
    public DataAvailability Availability { get; init; } = DataAvailability.Read;
}

public sealed record HealthCheckItem(
    DateTime? ObservedAt,
    string Category,
    string Component,
    string Status,
    string Value,
    string Detail)
{
    public DataAvailability Availability => Status switch
    {
        "Okunamadi" or "Erisilemedi" => DataAvailability.Inaccessible,
        "Yorumlanamadi" => DataAvailability.Uninterpretable,
        "Kismi" => DataAvailability.Partial,
        _ when Value is "Veri sunulmadi" or "Okunamadi" or "Sonuc bulunamadi" => DataAvailability.Unsupported,
        _ => DataAvailability.Read
    };
}

public sealed record ScanCoverageItem(string Source, string Status, int RecordCount, string Detail)
{
    public DataAvailability Availability => Status switch
    {
        "Tamamlandi" => DataAvailability.Read,
        "Kismi" => DataAvailability.Partial,
        "Atlandi" => DataAvailability.Unsupported,
        _ => DataAvailability.Inaccessible
    };
}

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

public sealed record RepairResult(string Title, bool Success, int ExitCode, string Output, DateTime StartedAt, DateTime FinishedAt)
{
    public RepairOutcome Outcome { get; init; } = RepairOutcome.Unverified;
    public string OutcomeText => Outcome switch
    {
        RepairOutcome.Succeeded => "Başarılı",
        RepairOutcome.PartiallySucceeded => "Kısmen başarılı",
        RepairOutcome.RestartRequired => "Yeniden başlatma gerekli",
        RepairOutcome.Failed => "Başarısız",
        _ => "Komut tamamlandı; değişiklik doğrulanamadı"
    };
}

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
    IReadOnlyList<ResourceMetricItem> ResourceMetrics)
{
    public CrossDumpAnalysisResult CrossDumpAnalysis { get; init; } = CrossDumpAnalysisResult.Empty;
}

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
    string LogText)
{
    public CrossDumpAnalysisResult CrossDumpAnalysis { get; init; } = CrossDumpAnalysisResult.Empty;
}

public sealed record ReportResult(string HtmlPath, string TextPath);
