using System.IO;
using System.Globalization;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class SystemAnalysisService
{
    private readonly ICommandRunner _runner;
    private readonly Func<string, Task> _log;
    private readonly SystemInventoryService _inventory;
    private readonly ResourceAnalysisService _resources;
    private readonly AdvancedDumpAnalysisService _dumpAnalysis;
    private readonly SystemHealthAnalysisService _health;

    public SystemAnalysisService(ICommandRunner runner, Func<string, Task> log)
    {
        _runner = runner;
        _log = log;
        _inventory = new SystemInventoryService(runner, log);
        _resources = new ResourceAnalysisService(runner, log);
        _dumpAnalysis = new AdvancedDumpAnalysisService(runner, log);
        _health = new SystemHealthAnalysisService(runner, log);
    }

    public Task<IReadOnlyList<SystemInfoItem>> GetSystemDetailsAsync(CancellationToken cancellationToken)
    {
        return _inventory.GetSystemDetailsAsync(cancellationToken);
    }

    public Task<IReadOnlyList<DriverInfoItem>> GetDriverDetailsAsync(CancellationToken cancellationToken)
    {
        return _inventory.GetDriverDetailsAsync(cancellationToken);
    }

    public Task<IReadOnlyList<SystemInfoItem>> GetTemperaturesAsync(CancellationToken cancellationToken)
    {
        return _inventory.GetTemperaturesAsync(cancellationToken);
    }

    public async Task<GeneralScanResult> RunGeneralScanAsync(CancellationToken cancellationToken, bool quick = false)
    {
        await _log("Genel tarama: olay kayitlari, guvenilirlik gecmisi, kaynak kullanimi, aygitlar ve suruculer birlikte inceleniyor.");

        var eventsTask = GetImportantEventCollectionAsync(quick ? 7 : 30, cancellationToken);
        var reliabilityTask = GetReliabilityCollectionAsync(quick ? 7 : 30, cancellationToken);
        var problemDevicesTask = GetProblemDeviceScanAsync(cancellationToken);
        var systemDetailsTask = _inventory.GetSystemDetailsAsync(cancellationToken);
        var driversTask = _inventory.GetDriverDetailsAsync(cancellationToken);
        var resourcesTask = _resources.ScanAsync(cancellationToken);
        var healthTask = quick ? Task.FromResult(new SystemHealthScanResult([], [new("Derin sağlık denetimi", "Atlandi", 0, "Hızlı taramada DISM ve derin sağlık denetimi çalıştırılmaz.")])) : _health.ScanAsync(cancellationToken);

        await Task.WhenAll(
            eventsTask,
            reliabilityTask,
            problemDevicesTask,
            systemDetailsTask,
            driversTask,
            resourcesTask,
            healthTask);

        var eventCollection = await eventsTask;
        var reliabilityCollection = await reliabilityTask;
        var problemDeviceScan = await problemDevicesTask;
        var events = eventCollection.Events;
        var reliability = reliabilityCollection.Records;
        var problemDevices = problemDeviceScan.Devices;
        var systemDetails = await systemDetailsTask;
        var drivers = await driversTask;
        var resourceResult = await resourcesTask;
        var healthResult = await healthTask;
        var blueScreenResult = quick ? new BlueScreenScanResult("Hızlı taramada dump analizi yapılmadı.", [], []) : await AnalyzeBlueScreensAsync(events, cancellationToken);
        var blueScreens = blueScreenResult.Signals;
        var dumpAnalyses = blueScreenResult.DumpAnalyses;

        var coverage = BuildScanCoverage(
            eventCollection.Coverage,
            reliabilityCollection.Coverage,
            problemDeviceScan.Coverage,
            healthResult.Coverage,
            systemDetails,
            drivers,
            resourceResult,
            blueScreens,
            dumpAnalyses);
        var findings = BuildFindings(events, reliability, blueScreens, dumpAnalyses, problemDevices, healthResult.Checks);
        if (quick) coverage = coverage.Select(x => x.Source == "Mavi ekran dump kaynaklari"
            ? new ScanCoverageItem(x.Source, "Atlandi", 0, "Hızlı taramada dump analizi çalıştırılmadı.") : x).ToList();
        AddDiskSpaceFinding(findings);
        AddResourceFindings(findings, resourceResult);
        AddInventoryFindings(findings, systemDetails);

        if (findings.Count == 0)
        {
            var complete = coverage.All(x => x.Status == "Tamamlandi");
            findings.Add(new Finding(
                complete ? Severity.Success : Severity.Info,
                complete ? "Belirgin kritik bulgu bulunmadı." : "Okunan veride kritik bulgu yok; tarama kapsamı eksik.",
                "Okunan kayitlarda acil bir mavi ekran, donanim veya disk sorunu sinyali gorunmuyor.",
                "Event Viewer, Reliability Monitor, kaynak kullanimi, dump dosyalari, diskler, aygitlar ve suruculer tarandi.",
                "Sorun devam ediyorsa hatanin oldugu saat araliginda tekrar tarama yapin veya teknik detaylari raporlayin.")
            {
                ConfidenceScore = GetCoverageScore(coverage),
                Correlation = "Okunabilen tum kaynaklarda kritik sinyal yok",
                Component = "Genel sistem durumu",
                Role = "Tarama Sonucu",
                LatestOccurrence = DateTime.Now,
                OccurrenceCount = 0,
                IndependentSourceCount = coverage.Count(x => x.Status == "Tamamlandi"),
                CrashRelation = "Cokme nedeni saptanmadi",
                SearchKey = "Genel sistem durumu"
            });
        }

        var orderedFindings = findings
            .OrderBy(GetFindingRolePriority)
            .ThenBy(x => x.Severity)
            .ThenByDescending(x => x.ConfidenceScore)
            .ThenByDescending(x => x.LatestOccurrence)
            .ThenBy(x => x.Title)
            .ToList();

        var diagnosticLogs = BuildDiagnosticLogs(events, reliability, problemDevices, resourceResult, healthResult.Checks);
        var summary = BuildUserSummary(events, reliability, blueScreens, dumpAnalyses, problemDevices, resourceResult, healthResult.Checks, coverage, orderedFindings);
        var systemInfo = SystemInventoryService.BuildTextSummary(systemDetails);
        return new GeneralScanResult(
            summary,
            blueScreenResult.Summary,
            systemInfo,
            orderedFindings,
            blueScreens,
            dumpAnalyses,
            events,
            reliability,
            diagnosticLogs,
            healthResult.Checks,
            coverage,
            systemDetails,
            drivers,
            resourceResult.Metrics)
        {
            CrossDumpAnalysis = blueScreenResult.CrossDumpAnalysis
        };
    }

    public async Task<BlueScreenScanResult> AnalyzeBlueScreensAsync(CancellationToken cancellationToken)
    {
        var events = await GetImportantEventsAsync(30, cancellationToken);
        return await AnalyzeBlueScreensAsync(events, cancellationToken);
    }

    public async Task<BlueScreenScanResult> AnalyzeSelectedDumpAsync(string dumpPath, CancellationToken cancellationToken)
    {
        return await AnalyzeSelectedDumpsAsync([dumpPath], cancellationToken);
    }

    public async Task<BlueScreenScanResult> AnalyzeSelectedDumpsAsync(
        IReadOnlyList<string> dumpPaths,
        CancellationToken cancellationToken,
        DumpAnalysisContext? context = null)
    {
        context ??= DumpAnalysisContext.External;
        var events = context.AllowLocalData ? await GetImportantEventsAsync(30, cancellationToken) : context.CaseEvents;
        return await _dumpAnalysis.AnalyzeAsync(dumpPaths, events, cancellationToken, context);
    }

    private async Task<BlueScreenScanResult> AnalyzeBlueScreensAsync(
        IReadOnlyList<EventRecordItem> events,
        CancellationToken cancellationToken)
    {
        await _log("Mavi ekran derin analizi: dump butunlugu, WinDbg sembolleri, stop code, stack, surucu ve olay korelasyonu inceleniyor.");
        var discovery = DiscoverDumpFiles();
        var result = await _dumpAnalysis.AnalyzeAsync(discovery.Paths, events, cancellationToken, DumpAnalysisContext.Local);
        return result with { Signals = discovery.Signals.Concat(result.Signals).ToList() };
    }

    private static DumpDiscovery DiscoverDumpFiles()
    {
        var records = new List<BlueScreenRecord>();
        var paths = new List<string>();
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var minidump = Path.Combine(windows, "Minidump");

        if (Directory.Exists(minidump))
        {
            List<string> dumpFiles;
            var dumpFolderReadable = true;
            try
            {
                dumpFiles = Directory.GetFiles(minidump, "*.dmp")
                    .OrderByDescending(File.GetLastWriteTime)
                    .Take(10)
                    .ToList();
            }
            catch (UnauthorizedAccessException)
            {
                dumpFolderReadable = false;
                dumpFiles = [];
                records.Add(new BlueScreenRecord(
                    "Minidump klasorune erisim yok",
                    "Dump klasoru standart kullanici yetkisiyle okunamadi. Diger analiz kaynaklari taranmaya devam etti.",
                    "Tam dump incelemesi icin uygulamayi yonetici olarak calistirin.",
                    null));
            }
            catch (IOException ex)
            {
                dumpFolderReadable = false;
                dumpFiles = [];
                records.Add(new BlueScreenRecord(
                    "Minidump klasoru okunamadi",
                    "Dump klasoru okunurken dosya sistemi hatasi alindi. Diger analiz kaynaklari taranmaya devam etti.",
                    ex.Message,
                    null));
            }

            if (dumpFolderReadable && dumpFiles.Count == 0)
            {
                records.Add(new BlueScreenRecord(
                    "Minidump klasoru bos",
                    "C:\\Windows\\Minidump klasoru var ama icinde dump dosyasi yok. Bu tek basina hata degildir.",
                    "Dump yazimi kapali olabilir, son mavi ekran dump olusturmamis olabilir veya temizlenmis olabilir.",
                    null));
            }
            else
            {
                foreach (var file in dumpFiles)
                {
                    var info = new FileInfo(file);
                    paths.Add(info.FullName);
                    var sizeText = info.Length < 1024 ? $"{info.Length} byte" : $"{info.Length / 1024:N0} KB";
                    var suspicious = info.Length < 64 * 1024 ? " Dosya cok kucuk; bozuk veya eksik yazilmis olabilir." : "";
                    records.Add(new BlueScreenRecord(
                        "Minidump dosyasi kesfedildi",
                        $"Derin analize alindi. Olusma: {info.LastWriteTime:dd.MM.yyyy HH:mm}, boyut: {sizeText}.{suspicious}",
                        info.FullName,
                        info.LastWriteTime));
                }
            }
        }
        else
        {
            records.Add(new BlueScreenRecord(
                "Minidump klasoru yok",
                "C:\\Windows\\Minidump bulunamadi. Bu tek basina mavi ekran kaniti degildir.",
                "Dump ayarlari: sysdm.cpl > Gelismis > Baslangic ve Kurtarma.",
                null));
        }

        var memoryDump = Path.Combine(windows, "MEMORY.DMP");
        if (File.Exists(memoryDump))
        {
            var info = new FileInfo(memoryDump);
            paths.Add(info.FullName);
            records.Add(new BlueScreenRecord(
                "Kernel/Memory dump bulundu",
                $"MEMORY.DMP derin analize alindi. Tarih: {info.LastWriteTime:dd.MM.yyyy HH:mm}, boyut: {info.Length / 1024 / 1024:N0} MB.",
                info.FullName,
                info.LastWriteTime));
        }

        return new DumpDiscovery(paths, records);
    }

    public async Task<IReadOnlyList<EventRecordItem>> GetImportantEventsAsync(int days, CancellationToken cancellationToken)
    {
        return (await GetImportantEventCollectionAsync(days, cancellationToken)).Events;
    }

    private async Task<EventCollectionResult> GetImportantEventCollectionAsync(int days, CancellationToken cancellationToken)
    {
        await _log($"Event Viewer: son {days} günün olayları okunuyor.");
        var collection = await new EventCollectionService(_runner).ReadAsync(days, cancellationToken);
        foreach (var item in collection.Coverage.Where(x => x.Status != "Tamamlandi"))
            await _log($"Olay sorgusu kapsamı: {item.Source}; {item.Status}; {item.Detail}");
        return collection;
    }

    public async Task<IReadOnlyList<ReliabilityRecordItem>> GetReliabilityRecordsAsync(int days, CancellationToken cancellationToken)
    {
        return (await GetReliabilityCollectionAsync(days, cancellationToken)).Records;
    }

    private async Task<ReliabilityCollectionResult> GetReliabilityCollectionAsync(int days, CancellationToken cancellationToken)
    {
        await _log($"Reliability Monitor taraniyor: son {days} gunun cokme, update ve kurulum kayitlari.");
        var script = """
            $start = (Get-Date).AddDays(-{DAYS})
            Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction Stop |
              Where-Object { $_.TimeGenerated -ge $start } |
              Sort-Object TimeGenerated -Descending |
              Select-Object -First 500 @{N='TimeGenerated';E={$_.TimeGenerated.ToString('o')}},SourceName,ProductName,@{N='Message';E={$m=$_.Message; if ([string]::IsNullOrWhiteSpace($m)) { '' } else { $m=$m -replace '\s+',' '; if ($m.Length -gt 900) { $m.Substring(0,900) } else { $m } }}} |
              ConvertTo-Json -Depth 3 -Compress
            """.Replace("{DAYS}", days.ToString());

        var result = await _runner.RunPowerShellAsync(script, cancellationToken, false, "Guvenilirlik gecmisi okunuyor");
        var records = ParseReliability(result.Output);
        return new ReliabilityCollectionResult(
            records,
            new ScanCoverageItem(
                "Guvenilirlik Gecmisi",
                !result.Success ? "Erisilemedi" : records.Count >= 500 ? "Kismi" : "Tamamlandi",
                records.Count,
                !result.Success ? "Reliability verisi okunamadi veya hizmet kullanilamiyor." : records.Count >= 500 ? "500 kayit sinirina ulasildi; daha eski kayitlar rapora alinmamis olabilir." : "Win32_ReliabilityRecords okundu."));
    }

    private List<Finding> BuildFindings(
        IReadOnlyList<EventRecordItem> events,
        IReadOnlyList<ReliabilityRecordItem> reliability,
        IReadOnlyList<BlueScreenRecord> blueScreens,
        IReadOnlyList<DumpAnalysisItem> dumpAnalyses,
        IReadOnlyList<string> problemDevices,
        IReadOnlyList<HealthCheckItem> healthChecks)
    {
        var findings = new List<Finding>();
        var bugChecks = events.Where(IsBugCheck).ToList();
        var kernelPower = events.Where(IsKernelPower).ToList();
        var whea = events.Where(IsWhea).ToList();
        var severeWhea = whea.Where(IsSevereWhea).ToList();
        var correctedWhea = whea.Where(x => !IsSevereWhea(x)).ToList();
        var disk = events.Where(IsDiskOrStorage).ToList();
        var severeDisk = disk.Where(IsSevereStorageEvent).ToList();
        var update = events.Where(IsWindowsUpdate).ToList();
        var display = events.Where(IsDisplayDriver).ToList();
        var processorPower = events.Where(IsProcessorPower).ToList();
        var services = events.Where(IsServiceControl).ToList();
        var codeIntegrity = events.Where(IsCodeIntegrityFailure).ToList();
        var driverInfrastructure = events.Where(IsDriverInfrastructureFailure).ToList();
        var defenderDetections = events.Where(IsDefenderDetection).ToList();
        var dumpWriteFailures = events.Where(IsDumpWriteFailure).ToList();
        var applicationGroups = GetApplicationCrashGroups(events, reliability);
        var displayGroups = GetDisplayDriverGroups(display);
        var reliabilityUpdates = reliability.Where(IsReliabilityUpdateProblem).ToList();
        var dumpEvidenceCount = Math.Max(blueScreens.Count(IsDumpEvidence), dumpAnalyses.Count);
        var crashAnchors = bugChecks.Concat(kernelPower).ToList();
        var crashCorrelations = CountNearbyEvents(whea.Concat(disk).Concat(display), crashAnchors, TimeSpan.FromMinutes(20));

        if (bugChecks.Count > 0 || dumpEvidenceCount > 0)
        {
            findings.Add(CreateFinding(
                Severity.Critical,
                "Mavi ekran veya dump kaniti bulundu.",
                "Sistem bir BugCheck ile kapanmis olabilir. Bu surucu, RAM, disk/NVMe veya donanim kararsizligi kaynakli olabilir.",
                $"{bugChecks.Count} BugCheck kaydi, {dumpEvidenceCount} dump dosyasi ve cokme zamaninin +/-20 dakikasinda {crashCorrelations} donanim/surucu sinyali bulundu. {LatestEvidence(bugChecks)}",
                "Mavi Ekran sekmesindeki stop code, stack ve supheli surucuyu; ayni zamandaki WHEA, disk ve GPU olaylariyla birlikte kontrol edin.",
                68 + Math.Min(16, bugChecks.Count * 4) + Math.Min(10, dumpEvidenceCount * 5) + Math.Min(6, crashCorrelations * 2),
                BuildCorrelationText(bugChecks.Count > 0, dumpEvidenceCount > 0, crashCorrelations > 0),
                component: "Windows BugCheck",
                role: "Cokme Kaniti",
                latestOccurrence: LatestDate(bugChecks.Select(x => x.TimeCreated).Concat(blueScreens.Select(x => x.TimeCreated))),
                occurrenceCount: bugChecks.Count + dumpEvidenceCount,
                independentSourceCount: (bugChecks.Count > 0 ? 1 : 0) + (dumpEvidenceCount > 0 ? 1 : 0) + (crashCorrelations > 0 ? 1 : 0),
                crashRelation: crashCorrelations > 0 ? $"Cokme saatine yakin {crashCorrelations} ek sinyal var" : "Cokmenin kendisini kanitlar; kok nedeni tek basina gostermez",
                searchKey: "BugCheck"));
        }

        foreach (var dump in dumpAnalyses
                     .OrderBy(x => x.Confidence == "Yuksek" ? 0 : x.Confidence == "Orta-Yuksek" ? 1 : x.Confidence == "Orta" ? 2 : 3)
                     .ThenByDescending(x => x.CreatedAt)
                     .Take(3))
        {
            var severity = dump.Confidence is "Yuksek" or "Orta-Yuksek" ? Severity.Critical : Severity.Warning;
            findings.Add(CreateFinding(
                severity,
                $"Dump analizi {dump.SuspectedComponent} bilesenini isaret ediyor.",
                dump.RootCauseSummary,
                $"{dump.FileName}: {dump.BugCheckCode} {dump.BugCheckName}; Guven: {dump.Confidence}.{Environment.NewLine}{dump.Evidence}",
                dump.Recommendation,
                DumpConfidenceScore(dump.Confidence),
                string.IsNullOrWhiteSpace(dump.CorrelatedEvents) ? "Dump stack ve sembol kaniti" : "Dump stack, sembol ve zaman eslesmeli olay kaniti",
                component: dump.SuspectedComponent,
                role: "Kok Neden Adayi",
                latestOccurrence: dump.CreatedAt,
                occurrenceCount: 1,
                independentSourceCount: string.IsNullOrWhiteSpace(dump.CorrelatedEvents) ? 1 : 2,
                crashRelation: "Dump dosyasinin stack/stop code analiziyle dogrudan iliskili",
                directEvidence: true,
                searchKey: dump.SuspectedComponent));
        }

        if (dumpWriteFailures.Count > 0)
        {
            findings.Add(CreateFinding(
                Severity.Warning,
                "Windows cokme dokumunu diske yazamamis.",
                "Pagefile, bos alan, CrashControl ayari veya depolama erisimi nedeniyle mavi ekran dump dosyasi olusturulamamis olabilir.",
                $"{dumpWriteFailures.Count} volmgr dump yazma olayi bulundu. {TopSources(dumpWriteFailures)}",
                "Sistem diskinde Windows tarafindan yonetilen pagefile ve yeterli bos alan bulundurun; CrashControl dump ayarini kontrol edip yeniden baslatin.",
                76,
                "volmgr dogrudan dump olusturma basarisizligi",
                component: "Windows dump yapilandirmasi",
                role: "Yapilandirma",
                latestOccurrence: LatestDate(dumpWriteFailures.Select(x => x.TimeCreated)),
                occurrenceCount: dumpWriteFailures.Count,
                crashRelation: "Mavi ekranin nedeni olmayabilir; kok neden kanitinin yazilmasini engeller",
                searchKey: "volmgr"));
        }

        if (severeWhea.Count > 0)
        {
            var nearCrash = CountNearbyEvents(severeWhea, crashAnchors, TimeSpan.FromMinutes(20));
            findings.Add(CreateFinding(
                Severity.Critical,
                "Duzeltilemeyen WHEA donanim hatasi kaydedildi.",
                "WHEA 18/20 veya duzeltilemeyen hata metni CPU, RAM, anakart, PCIe, GPU ya da NVMe kaynakli gercek bir donanim kararsizligini gosterebilir.",
                $"{severeWhea.Count} ciddi WHEA kaydi bulundu; {nearCrash} tanesi cokme zamanina yakin. {TopSources(severeWhea)}",
                "BIOS'u varsayilana alin, XMP/EXPO/overclock'u kapatin; RAM, CPU ve depolamayi ayri test edin. WHEA mesajindaki hata turu ve APIC/PCIe kimligi teknisyen tarafindan incelenmeli.",
                Math.Min(94, 78 + Math.Min(12, severeWhea.Count * 4) + Math.Min(10, nearCrash * 5)),
                nearCrash > 0 ? "WHEA ve sistem cokmesi zaman olarak eslesti" : "Tekrarlayan WHEA donanim kaniti",
                component: "WHEA / Donanim",
                role: "Dogrudan Ariza",
                latestOccurrence: LatestDate(severeWhea.Select(x => x.TimeCreated)),
                occurrenceCount: severeWhea.Count,
                independentSourceCount: nearCrash > 0 ? 2 : 1,
                crashRelation: nearCrash > 0 ? $"{nearCrash} WHEA kaydi cokme saatine yakin" : "Cokme saatine yakin eslesme yok",
                directEvidence: true,
                searchKey: "WHEA"));
        }

        if (correctedWhea.Count > 0)
        {
            findings.Add(CreateFinding(
                correctedWhea.Count >= 3 ? Severity.Warning : Severity.Info,
                "Duzeltilmis WHEA donanim olaylari var.",
                "Duzeltilmis WHEA olayi tek basina ariza kaniti degildir; tekrar etmesi PCIe, RAM veya islemci kararliligi sorununa donusebilir.",
                $"{correctedWhea.Count} duzeltilmis WHEA kaydi bulundu. {TopSources(correctedWhea)}",
                "Kayitlar artiyorsa BIOS/chipset guncelligini, XMP/EXPO ayarini ve sicakliklari kontrol edin; tekil kaydi kritik ariza olarak yorumlamayin.",
                35 + Math.Min(30, correctedWhea.Count * 6),
                "Duzeltilmis WHEA; tekrar sayisina gore puanlandi",
                component: "WHEA / Donanim",
                role: "Izleme Bulgusu",
                latestOccurrence: LatestDate(correctedWhea.Select(x => x.TimeCreated)),
                occurrenceCount: correctedWhea.Count,
                crashRelation: "Duzeltilmis olay; tek basina mavi ekran nedeni sayilmaz",
                searchKey: "WHEA"));
        }

        if (disk.Count > 0)
        {
            var nearCrash = CountNearbyEvents(disk, crashAnchors, TimeSpan.FromMinutes(20));
            var severity = severeDisk.Count > 0 || disk.Count >= 4 ? Severity.Critical : Severity.Warning;
            findings.Add(CreateFinding(
                severity,
                "Disk veya depolama tarafi hata veriyor olabilir.",
                "Disk/NTFS/storport kayitlari fiziksel aygit, dosya sistemi, kablo, firmware veya depolama denetleyicisi sorununa isaret edebilir.",
                $"{disk.Count} depolama olayi; bunlarin {severeDisk.Count} tanesi ciddi sinifta, {nearCrash} tanesi cokme zamanina yakin. {TopSources(disk)}",
                "Onemli verileri yedekleyin; SMART/uretici tanilamasini ve chkdsk /scan kontrolunu calistirin. NVMe/SATA firmware ile chipset/depolama surucusunu uretici sitesinden kontrol edin.",
                Math.Min(88, 52 + Math.Min(24, severeDisk.Count * 8) + Math.Min(14, nearCrash * 4) + Math.Min(10, disk.Count * 2)),
                nearCrash > 0 ? "Depolama olayi sistem cokmesiyle zaman olarak eslesti" : "Event Viewer depolama saglayicilari",
                component: "Disk / Depolama",
                role: "Kok Neden Adayi",
                latestOccurrence: LatestDate(disk.Select(x => x.TimeCreated)),
                occurrenceCount: disk.Count,
                independentSourceCount: nearCrash > 0 ? 2 : 1,
                crashRelation: nearCrash > 0 ? $"{nearCrash} depolama olayi cokme saatine yakin" : "Cokme saatine yakin eslesme yok",
                searchKey: disk.GroupBy(x => x.Provider).OrderByDescending(x => x.Count()).First().Key));
        }

        foreach (var group in displayGroups.Take(2))
        {
            var groupEvents = display.Where(x => ResolveDisplayComponent(x).Equals(group.Name, StringComparison.OrdinalIgnoreCase)).ToList();
            var nearCrash = CountNearbyEvents(groupEvents, crashAnchors, TimeSpan.FromMinutes(20));
            findings.Add(CreateFinding(
                group.Count >= 2 || nearCrash > 0 ? Severity.Warning : Severity.Info,
                $"{group.Name} ekran surucusu/GPU hatasi veriyor.",
                "Display/nvlddmkm/amdkmdag/igfx benzeri kayitlar ekran surucusu cokmesi, TDR veya GPU kararsizligi ile iliskili olabilir.",
                $"{group.Count} ilgili olay bulundu; {nearCrash} tanesi sistem cokmesine yakin. Son kayit: {group.Latest:dd.MM.yyyy HH:mm}.",
                "Ekran karti surucusunu temiz kurulumla guncelleyin; sorun yuk altinda oluyorsa GPU sicakligi, guc kablosu ve PSU da kontrol edilmeli.",
                42 + Math.Min(28, group.Count * 7) + Math.Min(20, nearCrash * 10),
                nearCrash > 0 ? "GPU surucu olayi sistem cokmesiyle zaman olarak eslesti" : "Tekrarlayan ekran surucusu olayi",
                component: group.Name,
                role: "Kok Neden Adayi",
                latestOccurrence: group.Latest,
                occurrenceCount: group.Count,
                independentSourceCount: nearCrash > 0 ? 2 : 1,
                crashRelation: nearCrash > 0 ? $"{nearCrash} GPU/surucu olayi cokme saatine yakin" : "Cokme saatine yakin eslesme yok",
                searchKey: group.Name));
        }

        if (processorPower.Count > 0)
        {
            findings.Add(CreateFinding(
                processorPower.Count >= 5 ? Severity.Warning : Severity.Info,
                "CPU guc yonetimi veya BIOS/firmware hata kaydi olusturuyor.",
                "Kernel-Processor-Power kayitlari BIOS guc tablolari, islemci frekans siniri, chipset surucusu veya guc planiyla iliskili olabilir.",
                $"{processorPower.Count} Kernel-Processor-Power kaydi bulundu. {TopSources(processorPower)}",
                "BIOS ve chipset surumlerini uretici sayfasiyla karsilastirin; varsayilan BIOS ayarlari ve Dengeli guc planiyla tekrar kontrol edin.",
                30 + Math.Min(35, processorPower.Count * 6),
                "Kernel-Processor-Power tekrar sayisi",
                component: "CPU / BIOS Guc Yonetimi",
                role: "Izleme Bulgusu",
                latestOccurrence: LatestDate(processorPower.Select(x => x.TimeCreated)),
                occurrenceCount: processorPower.Count,
                crashRelation: "Tek basina mavi ekran nedeni degildir",
                searchKey: "Kernel-Processor-Power"));
        }

        if (kernelPower.Count > 0)
        {
            var relatedCauseCount = CountNearbyEvents(whea.Concat(disk).Concat(display).Concat(bugChecks), kernelPower, TimeSpan.FromMinutes(20));
            findings.Add(CreateFinding(
                Severity.Warning,
                "Beklenmedik kapanma veya zorla yeniden baslatma var.",
                "Kernel-Power 41 sebep degil, sonucu gosterir. Mavi ekran, guc kesintisi, PSU/adaptor, kilitlenme veya reset olabilir.",
                $"{kernelPower.Count} Kernel-Power 41 kaydi ve ayni zamanlarda {relatedCauseCount} olasi neden sinyali bulundu. {LatestEvidence(kernelPower)}",
                "Ayni saatlerdeki BugCheck, WHEA, disk veya GPU kaydini asil neden olarak onceleyin. Eslesen kayit yoksa PSU/adaptor, priz, reset ve donma senaryosunu kontrol edin.",
                32 + Math.Min(18, kernelPower.Count * 3) + Math.Min(20, relatedCauseCount * 5),
                relatedCauseCount > 0 ? "Kernel-Power sonuc olayi; yakin zamandaki neden sinyalleri eslesti" : "Kernel-Power yalnizca sonuc kaniti",
                component: "Kernel-Power 41",
                role: "Sonuc Olayi",
                latestOccurrence: LatestDate(kernelPower.Select(x => x.TimeCreated)),
                occurrenceCount: kernelPower.Count,
                independentSourceCount: relatedCauseCount > 0 ? 2 : 1,
                crashRelation: "Beklenmedik kapanmayi kanitlar; nedeni kanitlamaz",
                searchKey: "Kernel-Power"));
        }

        if (update.Count > 0 || reliabilityUpdates.Count > 0)
        {
            var updateLatest = LatestDate(update.Select(x => x.TimeCreated).Concat(reliabilityUpdates.Select(x => x.TimeGenerated)));
            var updateIsRecent = updateLatest.HasValue && DateTime.Now - updateLatest.Value <= TimeSpan.FromDays(7);
            findings.Add(CreateFinding(
                updateIsRecent ? Severity.Warning : Severity.Info,
                "Windows Update veya kurulum sorunu gorunuyor.",
                "Update onbellegi, Windows imaji, servisler veya kurulum paketi tarafinda sorun olabilir.",
                $"{update.Count} Event Log update olayi, {reliabilityUpdates.Count} Reliability update/kurulum kaydi bulundu.",
                "Bilesen deposu sonucunu kontrol edin. Gerekirse DISM ScanHealth calistirin; devam ederse Windows Update Reset aracini kullanin.",
                42 + Math.Min(24, update.Count * 3) + Math.Min(24, reliabilityUpdates.Count * 6),
                update.Count > 0 && reliabilityUpdates.Count > 0 ? "Event Viewer ve Guvenilirlik Gecmisi birlikte dogruluyor" : "Tek Windows guncelleme kaynagi",
                component: "Windows Update",
                role: "Yapilandirma",
                latestOccurrence: updateLatest,
                occurrenceCount: update.Count + reliabilityUpdates.Count,
                independentSourceCount: (update.Count > 0 ? 1 : 0) + (reliabilityUpdates.Count > 0 ? 1 : 0),
                crashRelation: "Mavi ekranla dogrudan zaman eslesmesi kurulmadikca ayri bir sorun olarak degerlendirilir",
                searchKey: "WindowsUpdate"));
        }

        foreach (var group in applicationGroups.Take(3))
        {
            var eventMatch = events.Any(x => IsApplicationCrash(x) && ResolveApplicationName(x).Equals(group.Name, StringComparison.OrdinalIgnoreCase));
            var reliabilityMatch = reliability.Any(x => IsReliabilityCrash(x) && (string.IsNullOrWhiteSpace(x.ProductName) ? x.SourceName : x.ProductName).Equals(group.Name, StringComparison.OrdinalIgnoreCase));
            findings.Add(CreateFinding(
                group.Count >= 3 ? Severity.Warning : Severity.Info,
                $"{group.Name} uygulamasinda cokme/hata tespit edildi.",
                "Bu durum her zaman Windows bozulmasi anlamina gelmez; belirli bir uygulama, .NET runtime, tarayici eklentisi veya surucu bagimli yazilim cokuyor olabilir.",
                $"Son 30 gunde {group.Count} kayit bulundu. Son kayit: {group.Latest:dd.MM.yyyy HH:mm}.",
                $"{group.Name} uygulamasini ve bagli eklenti/suruculerini guncelleyin; devam ederse yeniden kurulum veya temiz baslangic testi yapin.",
                28 + Math.Min(42, group.Count * 9) + (eventMatch && reliabilityMatch ? 15 : 0),
                eventMatch && reliabilityMatch ? "Event Viewer ve Guvenilirlik Gecmisi birlikte dogruluyor" : "Tek cokme kaynagi",
                component: group.Name,
                role: "Kok Neden Adayi",
                latestOccurrence: group.Latest,
                occurrenceCount: group.Count,
                independentSourceCount: (eventMatch ? 1 : 0) + (reliabilityMatch ? 1 : 0),
                crashRelation: "Uygulama cokmesi; Windows mavi ekraninin nedeni oldugu kanitlanmadi",
                searchKey: group.Name));
        }

        foreach (var group in services
                     .GroupBy(x => ResolveServiceName(x.Message), StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(x => x.Count())
                     .ThenByDescending(x => x.Max(y => y.TimeCreated))
                     .Take(4))
        {
            findings.Add(CreateFinding(
                group.Count() >= 3 ? Severity.Warning : Severity.Info,
                $"{group.Key} servisinde hata kayitlari var.",
                "Servis beklenmedik sekilde durmus veya baslatilamamis olabilir. Bu, ana sebep olabilecegi gibi baska bir hatanin sonucu da olabilir.",
                $"{group.Count()} Service Control Manager olayi bulundu. Son kayit: {group.Max(x => x.TimeCreated):dd.MM.yyyy HH:mm}.",
                "Hizmetler kisayolundan ilgili servisi kontrol edin; ayni saatte update, disk veya uygulama hatasi var mi karsilastirin.",
                24 + Math.Min(36, group.Count() * 6),
                "Ayni servis icin gruplanmis Service Control Manager kayitlari",
                component: group.Key,
                role: "Izleme Bulgusu",
                latestOccurrence: group.Max(x => x.TimeCreated),
                occurrenceCount: group.Count(),
                crashRelation: "Mavi ekranla dogrudan zaman eslesmesi kurulmadikca sonuc veya ikincil hata olabilir",
                searchKey: group.Key));
        }

        foreach (var device in problemDevices.Take(5))
        {
            var deviceName = device.Split('(')[0].Trim();
            findings.Add(CreateFinding(
                Severity.Warning,
                $"{deviceName} aygitinda surucu/donanim sorunu var.",
                "Bir donanim veya surucu Windows tarafindan problemli isaretlenmis.",
                device,
                "Aygit Yoneticisi kisayolunu acip hata kodunu, donanim kimligini ve surucu saglayicisini kontrol edin.",
                78,
                "Aygit Yoneticisi anlik ConfigManager hata kodu",
                component: deviceName,
                role: "Dogrudan Ariza",
                latestOccurrence: DateTime.Now,
                occurrenceCount: 1,
                crashRelation: "Sorunlu aygit mavi ekranla iliskili olabilir; zaman eslesmesi ayrica aranmalidir",
                directEvidence: true,
                searchKey: deviceName));
        }

        if (driverInfrastructure.Count > 0 && problemDevices.Count == 0)
        {
            foreach (var group in driverInfrastructure
                         .GroupBy(ResolveDriverFile, StringComparer.OrdinalIgnoreCase)
                         .OrderByDescending(x => x.Count())
                         .ThenByDescending(x => x.Max(y => y.TimeCreated))
                         .Take(4))
            {
                findings.Add(CreateFinding(
                    group.Count() >= 3 ? Severity.Warning : Severity.Info,
                    $"{group.Key} surucu/aygit baslatma hatasi olusturuyor.",
                    "Kernel-PnP, DriverFrameworks veya UserPnp kayitlari surucunun gec basladigini, baslatilamadigini ya da aygit kurulumunun tamamlanamadigini gosterebilir.",
                    $"{group.Count()} surucu/aygit altyapisi olayi bulundu. Son kayit: {group.Max(x => x.TimeCreated):dd.MM.yyyy HH:mm}.",
                    "Hata Analizi kayitlarinda aygit kimligini bulun ve Aygit Yoneticisi ile surucu durumunu karsilastirin.",
                    38 + Math.Min(32, group.Count() * 6),
                    "Ayni surucu/aygit icin gruplanmis Event Viewer kayitlari",
                    component: group.Key,
                    role: "Kok Neden Adayi",
                    latestOccurrence: group.Max(x => x.TimeCreated),
                    occurrenceCount: group.Count(),
                    crashRelation: "Mavi ekranla dogrudan zaman eslesmesi yok",
                    searchKey: group.Key));
            }
        }

        foreach (var group in codeIntegrity
                     .GroupBy(ResolveDriverFile, StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(x => x.Count())
                     .Take(3))
        {
            var groupEvents = group.ToList();
            var nearCrash = CountNearbyEvents(groupEvents, crashAnchors, TimeSpan.FromMinutes(20));
            findings.Add(CreateFinding(
                nearCrash > 0 ? Severity.Warning : Severity.Info,
                $"{group.Key} Code Integrity tarafindan engellendi.",
                "Imza, uyumluluk veya guvenlik politikasi nedeniyle kernel surucusu/modul yuklenememis olabilir.",
                $"{group.Count()} engelleme olayi bulundu; {nearCrash} tanesi cokme zamanina yakin. Son kayit: {group.Max(x => x.TimeCreated):dd.MM.yyyy HH:mm}. Kaynak: Code Integrity / Event {group.First().Id}.",
                "Olay mesajindaki dosya yolunu ve surucu adini inceleyin; yalnizca cihaz ureticisinden imzali ve uyumlu surum kurun.",
                65 + Math.Min(20, group.Count() * 5),
                "Windows Code Integrity dogrudan engelleme kaydi",
                component: group.Key,
                role: nearCrash > 0 ? "Kok Neden Adayi" : "Izleme Bulgusu",
                latestOccurrence: group.Max(x => x.TimeCreated),
                occurrenceCount: group.Count(),
                independentSourceCount: nearCrash > 0 ? 2 : 1,
                crashRelation: nearCrash > 0 ? $"{nearCrash} engelleme olayi cokme saatine yakin" : "Cokme saatine yakin eslesme yok; tek basina mavi ekran nedeni sayilmaz",
                directEvidence: true,
                searchKey: group.Key));
        }

        if (defenderDetections.Count > 0)
        {
            findings.Add(CreateFinding(
                Severity.Warning,
                "Microsoft Defender tehdit algilama kaydi olusturdu.",
                "Zararli veya istenmeyen yazilim sistem kararliligini ve uygulama davranisini etkileyebilir.",
                $"{defenderDetections.Count} tehdit algilama olayi bulundu. {LatestEvidence(defenderDetections)}",
                "Windows Guvenligi > Koruma gecmisi bolumunde tehdidin karantinaya alinip alinmadigini dogrulayin ve tam tarama calistirin.",
                75,
                "Microsoft Defender dogrudan tehdit algilama olayi",
                component: "Microsoft Defender",
                role: "Dogrudan Ariza",
                latestOccurrence: LatestDate(defenderDetections.Select(x => x.TimeCreated)),
                occurrenceCount: defenderDetections.Count,
                crashRelation: "Mavi ekranla dogrudan iliski kurulmadikca ayri bir guvenlik bulgusudur",
                directEvidence: true,
                searchKey: "Windows Defender"));
        }

        foreach (var check in healthChecks.Where(x => x.Status is "Kritik" or "Uyari"))
        {
            var score = GetHealthConfidenceScore(check);
            findings.Add(CreateFinding(
                check.Status == "Kritik" ? Severity.Critical : Severity.Warning,
                $"{check.Component}: {check.Value}.",
                GetHealthCause(check),
                $"{check.Category} saglik denetimi: {check.Detail}",
                GetHealthRecommendation(check),
                score,
                "Anlik sistem saglik denetimi",
                component: check.Component,
                role: GetHealthFindingRole(check),
                latestOccurrence: check.ObservedAt,
                occurrenceCount: 1,
                crashRelation: GetHealthCrashRelation(check),
                directEvidence: IsDirectHealthEvidence(check),
                searchKey: check.Component));
        }

        return findings;
    }

    private string BuildUserSummary(
        IReadOnlyList<EventRecordItem> events,
        IReadOnlyList<ReliabilityRecordItem> reliability,
        IReadOnlyList<BlueScreenRecord> blueScreens,
        IReadOnlyList<DumpAnalysisItem> dumpAnalyses,
        IReadOnlyList<string> problemDevices,
        ResourceScanResult resources,
        IReadOnlyList<HealthCheckItem> healthChecks,
        IReadOnlyList<ScanCoverageItem> coverage,
        IReadOnlyList<Finding> findings)
    {
        var coverageScore = GetCoverageScore(coverage);
        var completed = coverage.Count(x => x.Status == "Tamamlandi");
        var limited = coverage.Count - completed;
        var candidates = findings
            .Where(x => x.Severity != Severity.Success)
            .OrderBy(GetFindingRolePriority)
            .ThenByDescending(x => x.ConfidenceScore)
            .ThenBy(x => x.Severity)
            .ThenByDescending(x => x.LatestOccurrence)
            .ToList();
        var primary = candidates.FirstOrDefault(x => x.IsRootCauseCandidate) ??
                      candidates.FirstOrDefault(x => x.Role != "Sonuc Olayi") ??
                      candidates.FirstOrDefault();
        var builder = new StringBuilder();
        builder.AppendLine($"Tarama kapsami: %{coverageScore} ({completed}/{coverage.Count} kaynak tam, {limited} kaynak kismi veya erisilemedi). Event Viewer: {events.Count}, Guvenilirlik: {reliability.Count}, saglik denetimi: {healthChecks.Count}, dump analizi: {dumpAnalyses.Count}.");

        if (primary is null)
        {
            builder.Append(coverageScore >= 80
                ? "Okunabilen kaynaklarda belirgin kritik hata sinyali bulunmadi. Bu sonuc sorunun kesinlikle olmadigi anlamina gelmez; ariza tekrar ettikten hemen sonra yeniden tarama daha guclu kanit verir."
                : "Kritik sinyal bulunmadi ancak tarama kapsami sinirli. Erisilemeyen kaynaklar okunmadan sistemin temiz oldugu soylenemez; uygulamayi yonetici olarak calistirip tekrar tarayin.");
            return builder.ToString().Trim();
        }

        builder.AppendLine();
        builder.AppendLine(primary.IsRootCauseCandidate ? "EN GUCLU KOK NEDEN ADAYI" : "EN GUCLU BULGU");
        builder.AppendLine($"Bilesen: {primary.Component}");
        builder.AppendLine($"Kanıt puanı: {primary.ConfidenceScore}/100 ({primary.Confidence}) | Bağımsız kaynak: {primary.IndependentSourceCount} | Rol: {primary.Role}");
        builder.AppendLine($"Neden: {primary.Cause}");
        builder.AppendLine($"Mavi ekran iliskisi: {primary.CrashRelation}");
        builder.AppendLine($"Kanit gucu: {primary.OccurrenceCount} tekrar, {primary.IndependentSourceCount} bagimsiz kaynak, {primary.RecencyText.ToLowerInvariant()}.");
        builder.AppendLine($"Ilk yapilacak islem: {FirstSentence(primary.Recommendation)}");

        var otherCandidates = candidates
            .Where(x => !ReferenceEquals(x, primary) && x.Role != "Sonuc Olayi")
            .Take(3)
            .ToList();
        if (otherCandidates.Count > 0)
        {
            builder.AppendLine();
            builder.AppendLine("DIGER ONEMLI BULGULAR");
            for (var index = 0; index < otherCandidates.Count; index++)
            {
                var item = otherCandidates[index];
                builder.AppendLine($"{index + 1}. {item.Component}: {item.ConfidenceScore}/100 kanıt puanı, {item.IndependentSourceCount} bağımsız kaynak, {item.Role}, {item.OccurrenceCount} tekrar. {FirstSentence(item.Recommendation)}");
            }
        }

        var consequenceCount = candidates.Count(x => x.Role == "Sonuc Olayi");
        if (consequenceCount > 0)
        {
            builder.AppendLine();
            builder.AppendLine($"Not: {consequenceCount} sonuc olayi (ornegin Kernel-Power) kok neden puanlamasindan ayrildi.");
        }

        if (coverageScore < 80)
        {
            builder.AppendLine();
            builder.Append("Sinir: Bazi veri kaynaklari okunamadi. Bu nedenle sonuc eksik kanitla sinirli; Tarama Kapsami sekmesini kontrol edin.");
        }

        return builder.ToString().Trim();
    }

    private static string FirstSentence(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "Kanit detayini inceleyin.";
        var lineEnd = value.IndexOfAny(['\r', '\n']);
        var firstLine = lineEnd < 0 ? value.Trim() : value[..lineEnd].Trim();
        var sentenceBreak = Regex.Match(firstLine, @"(?<=[.!?])\s+");
        return sentenceBreak.Success ? firstLine[..sentenceBreak.Index].Trim() : firstLine;
    }

    private async Task<IReadOnlyList<EventRecordItem>> GetBugCheckFamilyEventsAsync(int days, CancellationToken cancellationToken)
    {
        var script = """
            $start = (Get-Date).AddDays(-{DAYS})
            Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start; Id=41,1001,18,19,20,47} -ErrorAction SilentlyContinue |
              Where-Object {
                ($_.Id -eq 41 -and $_.ProviderName -like '*Kernel-Power*') -or
                ($_.Id -eq 1001 -and ($_.ProviderName -like '*BugCheck*' -or $_.ProviderName -like '*SystemErrorReporting*')) -or
                ($_.Id -in @(18,19,20,47) -and $_.ProviderName -like '*WHEA*')
              } |
              Sort-Object TimeCreated -Descending |
              Select-Object -First 80 @{N='TimeCreated';E={$_.TimeCreated.ToString('o')}},LogName,ProviderName,Id,LevelDisplayName,@{N='Message';E={$m=$_.Message; if ([string]::IsNullOrWhiteSpace($m)) { '' } else { $m=$m -replace '\s+',' '; if ($m.Length -gt 800) { $m.Substring(0,800) } else { $m } }}} |
              ConvertTo-Json -Depth 3 -Compress
            """.Replace("{DAYS}", days.ToString());
        var result = await _runner.RunPowerShellAsync(script, cancellationToken, false, "Mavi ekran olaylari okunuyor");
        return ParseEvents(result.Output);
    }

    private async Task<ProblemDeviceScanResult> GetProblemDeviceScanAsync(CancellationToken cancellationToken)
    {
        await _log("Aygit Yoneticisi hata kodlari kontrol ediliyor.");
        var script = """
            Get-CimInstance Win32_PnPEntity -ErrorAction Stop |
              Where-Object {
                $_.ConfigManagerErrorCode -ne $null -and
                $_.ConfigManagerErrorCode -ne 0 -and
                $_.ConfigManagerErrorCode -notin @(22,24,45)
              } |
              Select-Object -First 30 Name,PNPClass,ConfigManagerErrorCode |
              ConvertTo-Json -Depth 3 -Compress
            """;

        var result = await _runner.RunPowerShellAsync(script, cancellationToken, false, "Sorunlu aygitlar okunuyor");
        var devices = new List<string>();
        foreach (var element in ParseJsonElements(result.Output))
        {
            var name = ReadString(element, "Name");
            var cls = ReadString(element, "PNPClass");
            var code = ReadInt(element, "ConfigManagerErrorCode");
            devices.Add($"{name} ({cls}) - Aygit hata kodu: {code}");
        }

        return new ProblemDeviceScanResult(
            devices,
            new ScanCoverageItem(
                "Aygit Yoneticisi",
                result.Success ? "Tamamlandi" : "Erisilemedi",
                devices.Count,
                result.Success ? "ConfigManager hata kodlari sorgulandi." : "PnP aygit durumlari okunamadi."));
    }

    private async Task<string> BuildSystemInfoAsync(IReadOnlyList<string> problemDevices, CancellationToken cancellationToken)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"Bilgisayar: {Environment.MachineName}");
        builder.AppendLine($"Kullanici: {Environment.UserName}");
        builder.AppendLine($"Yonetici: {IsAdministrator()}");
        builder.AppendLine();

        var script = """
            $os = Get-CimInstance Win32_OperatingSystem
            $cs = Get-CimInstance Win32_ComputerSystem
            $bios = Get-CimInstance Win32_BIOS
            $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
            Write-Output "Windows: $($os.Caption) $($os.Version) Build $($os.BuildNumber)"
            Write-Output "Kurulum tarihi: $($os.InstallDate)"
            Write-Output "Son acilis: $($os.LastBootUpTime)"
            Write-Output "Cihaz: $($cs.Manufacturer) $($cs.Model)"
            Write-Output "RAM: $([math]::Round($cs.TotalPhysicalMemory/1GB,2)) GB"
            Write-Output "CPU: $($cpu.Name)"
            Write-Output "BIOS: $($bios.SMBIOSBIOSVersion)"
            """;
        var result = await _runner.RunPowerShellAsync(script, cancellationToken, false, "Temel sistem bilgileri okunuyor");
        builder.AppendLine(result.Output.Trim());
        builder.AppendLine();

        var drive = DriveInfo.GetDrives().FirstOrDefault(x => x.Name.Equals(Path.GetPathRoot(Environment.SystemDirectory), StringComparison.OrdinalIgnoreCase));
        if (drive is { IsReady: true })
        {
            builder.AppendLine($"Sistem diski: {drive.Name}");
            builder.AppendLine($"Toplam alan: {drive.TotalSize / 1024 / 1024 / 1024:N1} GB");
            builder.AppendLine($"Bos alan: {drive.AvailableFreeSpace / 1024 / 1024 / 1024:N1} GB");
        }

        builder.AppendLine();
        builder.AppendLine(problemDevices.Count == 0
            ? "Aygit Yoneticisi: Sorunlu aygit bulunmadi."
            : $"Aygit Yoneticisi: {problemDevices.Count} sorunlu aygit bulundu.");

        foreach (var device in problemDevices.Take(5))
        {
            builder.AppendLine($"- {device}");
        }

        return builder.ToString();
    }

    private static IReadOnlyList<EventRecordItem> ParseEvents(string jsonText)
    {
        var list = new List<EventRecordItem>();
        foreach (var element in ParseJsonElements(jsonText))
        {
            list.Add(new EventRecordItem(
                ReadDate(element, "TimeCreated"),
                ReadString(element, "LogName"),
                ReadString(element, "ProviderName"),
                ReadInt(element, "Id"),
                ReadString(element, "LevelDisplayName"),
                ReadString(element, "Message")));
        }

        return list;
    }

    private static IReadOnlyList<ReliabilityRecordItem> ParseReliability(string jsonText)
    {
        var list = new List<ReliabilityRecordItem>();
        foreach (var element in ParseJsonElements(jsonText))
        {
            list.Add(new ReliabilityRecordItem(
                ReadDate(element, "TimeGenerated"),
                ReadString(element, "SourceName"),
                ReadString(element, "ProductName"),
                ReadString(element, "Message")));
        }

        return list;
    }

    private static IReadOnlyList<ScanCoverageItem> BuildScanCoverage(
        IReadOnlyList<ScanCoverageItem> eventCoverage,
        ScanCoverageItem reliabilityCoverage,
        ScanCoverageItem deviceCoverage,
        IReadOnlyList<ScanCoverageItem> healthCoverage,
        IReadOnlyList<SystemInfoItem> systemDetails,
        IReadOnlyList<DriverInfoItem> drivers,
        ResourceScanResult resources,
        IReadOnlyList<BlueScreenRecord> blueScreens,
        IReadOnlyList<DumpAnalysisItem> dumpAnalyses)
    {
        var coverage = new List<ScanCoverageItem>();
        coverage.AddRange(eventCoverage);
        coverage.Add(reliabilityCoverage);
        coverage.Add(deviceCoverage);
        coverage.AddRange(healthCoverage);
        coverage.Add(new ScanCoverageItem(
            "Sistem ve sensor envanteri",
            systemDetails.Count > 0 ? "Tamamlandi" : "Erisilemedi",
            systemDetails.Count,
            systemDetails.Count > 0 ? "Windows, donanim ve kullanilabilen sensorler okundu." : "Sistem envanteri alinamadi."));
        coverage.Add(new ScanCoverageItem(
            "BIOS ve surucu envanteri",
            drivers.Count > 0 ? "Tamamlandi" : "Kismi",
            drivers.Count,
            drivers.Count > 0 ? "BIOS, GPU, chipset ve depolama suruculeri sorgulandi." : "Surucu envanteri bos; WMI/CIM erisimi sinirli olabilir."));
        var resourceUnavailable = resources.Metrics.All(x => x.Availability == DataAvailability.Inaccessible);
        var resourcePartial = resources.Metrics.Any(x => x.Availability != DataAvailability.Read);
        coverage.Add(new ScanCoverageItem(
            "Kaynak kullanimi orneklemi",
            resourceUnavailable ? "Erisilemedi" : resourcePartial ? "Kismi" : "Tamamlandi",
            resources.Metrics.Count,
            resourceUnavailable ? "Performans sayaclari okunamadi." : resourcePartial ? "Bazı ölçümler eksik; kaynak tablosunda örnek sayıları ve erişim durumu gösterilir." : "CPU, RAM, disk, ag ve yogun islemler coklu orneklemlendi."));

        var dumpAccessFailure = blueScreens.Any(x => x.Title.Contains("erisim yok", StringComparison.OrdinalIgnoreCase) || x.Title.Contains("okunamadi", StringComparison.OrdinalIgnoreCase));
        var dumpCount = Math.Max(blueScreens.Count(IsDumpEvidence), dumpAnalyses.Count);
        coverage.Add(new ScanCoverageItem(
            "Mavi ekran dump kaynaklari",
            dumpAccessFailure || dumpAnalyses.Any(x => !x.AnalysisStatus.StartsWith("Tamamlandi", StringComparison.Ordinal) || x.SymbolsIncomplete) ? "Kismi" : "Tamamlandi",
            dumpCount,
            dumpAccessFailure
                ? "Dump klasorlerinden en az biri okunamadi; yonetici izniyle tekrar tarayin."
                : dumpCount > 0 ? "Bulunan dump dosyalari derin analize alindi." : "Dump klasorleri kontrol edildi; analiz edilebilir dosya bulunmadi."));
        return coverage;
    }

    private static int GetCoverageScore(IReadOnlyList<ScanCoverageItem> coverage)
    {
        if (coverage.Count == 0)
        {
            return 0;
        }

        var points = coverage.Sum(x => x.Status switch
        {
            "Tamamlandi" => 1.0,
            "Kismi" => 0.5,
            _ => 0.0
        });
        return (int)Math.Round(points / coverage.Count * 100);
    }

    private static Finding CreateFinding(
        Severity severity,
        string title,
        string cause,
        string evidence,
        string recommendation,
        int confidenceScore,
        string correlation,
        string component = "Windows",
        string role = "Kok Neden Adayi",
        DateTime? latestOccurrence = null,
        int occurrenceCount = 1,
        int independentSourceCount = 1,
        string crashRelation = "Dogrudan zaman eslesmesi yok",
        bool directEvidence = false,
        string? searchKey = null)
    {
        var adjustedScore = confidenceScore + GetRecencyAdjustment(latestOccurrence);
        var confidenceCap = directEvidence ? 98 : independentSourceCount >= 2 ? 92 : 85;
        confidenceCap = role switch
        {
            "Sonuc Olayi" => Math.Min(confidenceCap, 62),
            "Cokme Kaniti" => Math.Min(confidenceCap, 85),
            "Izleme Bulgusu" => Math.Min(confidenceCap, 75),
            "Yapilandirma" when !directEvidence => Math.Min(confidenceCap, 88),
            _ => confidenceCap
        };

        return new Finding(severity, title, cause, evidence, recommendation)
        {
            ConfidenceScore = Math.Clamp(Math.Min(adjustedScore, confidenceCap), 5, 98),
            Correlation = correlation,
            Component = string.IsNullOrWhiteSpace(component) ? "Windows" : component,
            Role = role,
            LatestOccurrence = latestOccurrence,
            OccurrenceCount = Math.Max(occurrenceCount, 0),
            IndependentSourceCount = Math.Max(independentSourceCount, 1),
            CrashRelation = crashRelation,
            SearchKey = string.IsNullOrWhiteSpace(searchKey) ? component : searchKey
        };
    }

    private static int GetRecencyAdjustment(DateTime? latestOccurrence)
    {
        if (!latestOccurrence.HasValue)
        {
            return 0;
        }

        var age = DateTime.Now - latestOccurrence.Value;
        if (age.TotalHours <= 24) return 8;
        if (age.TotalDays <= 7) return 4;
        if (age.TotalDays <= 14) return 1;
        if (age.TotalDays > 30) return -12;
        return -5;
    }

    private static int GetFindingRolePriority(Finding finding)
    {
        return finding.Role switch
        {
            "Dogrudan Ariza" => 0,
            "Kok Neden Adayi" => 1,
            "Yapilandirma" => 2,
            "Cokme Kaniti" => 3,
            "Sonuc Olayi" => 4,
            "Izleme Bulgusu" => 5,
            "Tarama Sonucu" => 6,
            _ => 5
        };
    }

    private static DateTime? LatestDate(IEnumerable<DateTime?> dates)
    {
        return dates.Where(x => x.HasValue).Select(x => x!.Value).DefaultIfEmpty().Max() is var latest && latest != default
            ? latest
            : null;
    }

    private static int DumpConfidenceScore(string confidence)
    {
        return confidence switch
        {
            "Yuksek" => 94,
            "Orta-Yuksek" => 82,
            "Orta" => 65,
            "Dusuk" => 38,
            _ => 45
        };
    }

    private static string BuildCorrelationText(bool hasBugCheck, bool hasDump, bool hasNearbySignal)
    {
        var sources = new List<string>();
        if (hasBugCheck) sources.Add("BugCheck olayi");
        if (hasDump) sources.Add("dump dosyasi");
        if (hasNearbySignal) sources.Add("yakin zamanli donanim/surucu olayi");
        return sources.Count == 0 ? "Tek cokme sinyali" : string.Join(" + ", sources);
    }

    private static int CountNearbyEvents(
        IEnumerable<EventRecordItem> candidates,
        IEnumerable<EventRecordItem> anchors,
        TimeSpan window)
    {
        var anchorTimes = anchors.Where(x => x.TimeCreated.HasValue).Select(x => x.TimeCreated!.Value).ToList();
        if (anchorTimes.Count == 0)
        {
            return 0;
        }

        return candidates.Count(candidate => candidate.TimeCreated.HasValue &&
            anchorTimes.Any(anchor => (candidate.TimeCreated.Value - anchor).Duration() <= window));
    }

    private static int GetHealthConfidenceScore(HealthCheckItem check)
    {
        if (check.Component.Contains("SMART", StringComparison.OrdinalIgnoreCase) && check.Status == "Kritik") return 98;
        if (check.Component.Contains("Bellek Tanilama", StringComparison.OrdinalIgnoreCase) && check.Status == "Kritik") return 96;
        if (check.Category == "Depolama" && check.Status == "Kritik") return 92;
        if (check.Component.Contains("Bilesen deposu", StringComparison.OrdinalIgnoreCase)) return 82;
        if (check.Component.Contains("Pagefile", StringComparison.OrdinalIgnoreCase)) return 68;
        if (check.Component.Contains("dump", StringComparison.OrdinalIgnoreCase)) return 62;
        if (check.Component.Contains("yeniden baslatma", StringComparison.OrdinalIgnoreCase)) return 48;
        return check.Status == "Kritik" ? 85 : 60;
    }

    private static string GetHealthFindingRole(HealthCheckItem check)
    {
        if (IsDirectHealthEvidence(check)) return "Dogrudan Ariza";
        if (check.Component.Contains("dump", StringComparison.OrdinalIgnoreCase) ||
            check.Component.Contains("Pagefile", StringComparison.OrdinalIgnoreCase) ||
            check.Component.Contains("yeniden baslatma", StringComparison.OrdinalIgnoreCase) ||
            check.Component.Contains("Bilesen deposu", StringComparison.OrdinalIgnoreCase))
        {
            return "Yapilandirma";
        }

        return "Izleme Bulgusu";
    }

    private static bool IsDirectHealthEvidence(HealthCheckItem check)
    {
        return check.Component.Contains("SMART", StringComparison.OrdinalIgnoreCase) ||
               check.Component.Contains("Bellek Tanilama", StringComparison.OrdinalIgnoreCase) ||
               check.Category == "Depolama";
    }

    private static string GetHealthCrashRelation(HealthCheckItem check)
    {
        if (check.Component.Contains("SMART", StringComparison.OrdinalIgnoreCase)) return "Disk arizasi mavi ekrana yol acabilir; dogrudan SMART kaniti var";
        if (check.Component.Contains("Bellek Tanilama", StringComparison.OrdinalIgnoreCase)) return "RAM hatasi mavi ekranla dogrudan iliskili olabilir";
        if (check.Component.Contains("dump", StringComparison.OrdinalIgnoreCase)) return "Kok neden degil; sonraki cokmenin kanitini kaydetmeyi etkiler";
        if (check.Component.Contains("Pagefile", StringComparison.OrdinalIgnoreCase)) return "Dump yazimini ve bellek baskisini etkileyebilir";
        return "Mavi ekranla zaman eslesmesi ayrica dogrulanmalidir";
    }

    private static string GetHealthCause(HealthCheckItem check)
    {
        if (check.Component.Contains("SMART", StringComparison.OrdinalIgnoreCase)) return "Disk firmware'i yaklasan ariza icin dogrudan tahmin sinyali bildirdi.";
        if (check.Component.Contains("Bellek Tanilama", StringComparison.OrdinalIgnoreCase)) return "Windows bellek testi fiziksel RAM veya bellek yolu sorunu algilamis olabilir.";
        if (check.Category == "Depolama") return "Disk ya da depolama havuzu Windows'a normal disi saglik/operasyon durumu bildirdi.";
        if (check.Component.Contains("Bilesen deposu", StringComparison.OrdinalIgnoreCase)) return "Windows bilesen deposu onarilabilir bozulma bildirdi.";
        if (check.Component.Contains("Pagefile", StringComparison.OrdinalIgnoreCase)) return "Pagefile eksikligi bellek baskisini ve dump yazimini etkileyebilir.";
        if (check.Component.Contains("dump", StringComparison.OrdinalIgnoreCase)) return "Windows cokme dokumu kapali oldugu icin sonraki mavi ekranin kok neden kaniti kaydedilmeyebilir.";
        if (check.Component.Contains("yeniden baslatma", StringComparison.OrdinalIgnoreCase)) return "Guncelleme veya kurulum islemleri tamamlanmak icin yeniden baslatma bekliyor.";
        return "Sistem saglik denetimi normal disi bir durum bildirdi.";
    }

    private static string GetHealthRecommendation(HealthCheckItem check)
    {
        if (check.Component.Contains("SMART", StringComparison.OrdinalIgnoreCase) || check.Category == "Depolama") return "Onemli verileri hemen yedekleyin ve ureticinin tanilama araci ile uzun test calistirin.";
        if (check.Component.Contains("Bellek Tanilama", StringComparison.OrdinalIgnoreCase)) return "XMP/EXPO'yu kapatip MemTest86 veya uretici tanilamasi ile her RAM modulunu ayri test edin.";
        if (check.Component.Contains("Bilesen deposu", StringComparison.OrdinalIgnoreCase)) return "DISM /Online /Cleanup-Image /RestoreHealth ardindan sfc /scannow calistirin.";
        if (check.Component.Contains("Pagefile", StringComparison.OrdinalIgnoreCase)) return "Sistem surucusunda Windows tarafindan yonetilen pagefile'i etkinlestirin ve yeniden baslatin.";
        if (check.Component.Contains("dump", StringComparison.OrdinalIgnoreCase)) return "Baslangic ve Kurtarma ayarlarinda Otomatik veya Kucuk bellek dokumunu etkinlestirin; sistem diskinde pagefile bulundurun.";
        if (check.Component.Contains("yeniden baslatma", StringComparison.OrdinalIgnoreCase)) return "Calismalari kaydedip Windows'u normal sekilde yeniden baslatin, sonra taramayi tekrarlayin.";
        return "Kanit detayini teknisyenle paylasin ve ilgili bileseni uretici tanilamasi ile dogrulayin.";
    }

    private static void AddDiskSpaceFinding(List<Finding> findings)
    {
        var drive = DriveInfo.GetDrives().FirstOrDefault(x => x.Name.Equals(Path.GetPathRoot(Environment.SystemDirectory), StringComparison.OrdinalIgnoreCase));
        if (drive is null || !drive.IsReady)
        {
            return;
        }

        var freePercent = drive.AvailableFreeSpace / (double)drive.TotalSize * 100;
        if (freePercent < 10)
        {
            findings.Add(CreateFinding(
                Severity.Warning,
                "Sistem diskinde bos alan dusuk.",
                "Dusuk bos alan Windows Update, dump yazimi, paging ve sistem kararliligini etkileyebilir.",
                $"{drive.Name} bos alan: {drive.AvailableFreeSpace / 1024 / 1024 / 1024:N1} GB (%{freePercent:N1}).",
                "Kullanici dosyalarini tasiyin veya gereksiz gecici dosyalari guvenli temizlik araci ile temizleyin.",
                88,
                "Dogrudan disk kapasitesi olcumu",
                component: $"Sistem diski {drive.Name}",
                role: "Yapilandirma",
                latestOccurrence: DateTime.Now,
                occurrenceCount: 1,
                crashRelation: "Dump yazimini ve sistem kararliligini etkileyebilir; tek basina mavi ekran nedeni degildir",
                directEvidence: true,
                searchKey: drive.Name));
        }
    }

    private static void AddResourceFindings(List<Finding> findings, ResourceScanResult resources)
    {
        if (resources.CpuAverage >= 85)
        {
            var process = string.IsNullOrWhiteSpace(resources.TopCpuProcess) ? "Bilinmeyen islem" : resources.TopCpuProcess;
            findings.Add(CreateFinding(
                resources.CpuAverage >= 95 ? Severity.Critical : Severity.Warning,
                $"{process} islemiyle birlikte CPU kullanimi yuksek.",
                "Islemci kullanimi tarama boyunca yuksek kaldi. Arka plan uygulamasi, surucu veya takilan bir islem buna neden olabilir.",
                $"CPU ortalama %{resources.CpuAverage:N1}, tepe %{resources.CpuPeak:N1}. {process}: %{resources.TopCpuPercent:N1}.",
                "Gorev Yoneticisi ve Kaynak Izleyicisi'nde ayni islemin surekli yuksek kalip kalmadigini kontrol edin.",
                64,
                "Coklu performans sayaci orneklemi",
                component: process,
                role: "Anlik Olcum",
                latestOccurrence: DateTime.Now,
                occurrenceCount: 5,
                crashRelation: "Tarama anindaki yuk; mavi ekranla zaman eslesmesi yok",
                searchKey: process));
        }

        if (resources.MemoryAverage >= 85)
        {
            var process = string.IsNullOrWhiteSpace(resources.TopMemoryProcess) ? "Bilinmeyen islem" : resources.TopMemoryProcess;
            findings.Add(CreateFinding(
                resources.MemoryAverage >= 95 ? Severity.Critical : Severity.Warning,
                $"RAM kullanimi yuksek; en cok kullanan islem {process}.",
                "Yuksek bellek kullanimi takilma, disk paging ve uygulama kapanmalarina yol acabilir.",
                $"RAM kullanimi %{resources.MemoryAverage:N1}. {process}: {resources.TopMemoryMb:N0} MB.",
                "Gorev Yoneticisi'nde bellek siralamasini kontrol edin; gereksiz baslangic uygulamalarini kapatin ve bellek sizintisi ihtimalini izleyin.",
                68,
                "Coklu bellek kullanim orneklemi",
                component: process,
                role: "Anlik Olcum",
                latestOccurrence: DateTime.Now,
                occurrenceCount: 5,
                crashRelation: "Tarama anindaki bellek baskisi; mavi ekranla zaman eslesmesi yok",
                searchKey: process));
        }

        if (resources.DiskAverage >= 80 || resources.DiskQueuePeak >= 2)
        {
            findings.Add(CreateFinding(
                resources.DiskAverage >= 95 || resources.DiskQueuePeak >= 4 ? Severity.Critical : Severity.Warning,
                "Disk etkinligi veya disk kuyrugu yuksek.",
                "Depolama aygiti yogun calisiyor, gecikiyor veya RAM yetersizligi nedeniyle paging yapiyor olabilir.",
                $"Disk ortalama %{resources.DiskAverage:N1}, tepe %{resources.DiskPeak:N1}, kuyruk tepe {resources.DiskQueuePeak:N2}.",
                "Kaynak Izleyicisi Disk bolumunde en cok okuma/yazma yapan islemi kontrol edin; disk sagligi ve bos alani da incelenmeli.",
                62,
                "Coklu disk performans sayaci orneklemi",
                component: "Disk performansi",
                role: "Anlik Olcum",
                latestOccurrence: DateTime.Now,
                occurrenceCount: 5,
                crashRelation: "Tarama anindaki yogunluk; mavi ekranla zaman eslesmesi yok",
                searchKey: "Disk"));
        }
    }

    private static void AddInventoryFindings(List<Finding> findings, IReadOnlyList<SystemInfoItem> systemDetails)
    {
        foreach (var sensor in systemDetails.Where(x =>
                     (x.Category == "CPU Sicakligi" || x.Category == "GPU Sicakligi") &&
                     (x.Status == "Yuksek" || x.Status == "Kritik")))
        {
            findings.Add(CreateFinding(
                sensor.Status == "Kritik" ? Severity.Critical : Severity.Warning,
                $"{sensor.Name} sicakligi {sensor.Status.ToLowerInvariant()}.",
                "Yuksek sicaklik performans dusmesine, kapanmaya veya kararsizliga neden olabilir.",
                $"Olculen deger: {sensor.Value}.",
                "Fan, hava kanali, termal macun ve yuk altindaki sicaklik davranisini kontrol edin.",
                78,
                "Donanim sensoru anlik olcumu",
                component: sensor.Name,
                role: "Anlik Olcum",
                latestOccurrence: DateTime.Now,
                occurrenceCount: 1,
                crashRelation: "Yuksek sicaklik kararsizlikla iliskili olabilir; cokme saatiyle eslesme yok",
                directEvidence: true,
                searchKey: sensor.Name));
        }

        foreach (var disk in systemDetails.Where(x =>
                     x.Category == "Depolama" &&
                     !string.IsNullOrWhiteSpace(x.Status) &&
                     !x.Status.Equals("Normal", StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(CreateFinding(
                Severity.Warning,
                $"{disk.Name} depolama aygiti normal durum bildirmiyor.",
                "Disk veya denetleyici Windows'a normal disinda bir durum bildirdi.",
                $"{disk.Value}; {disk.Status}",
                "Onemli verileri yedekleyin ve ureticinin SMART/diagnostic araci ile ayrintili test yapin.",
                74,
                "Win32_DiskDrive durum bildirimi",
                component: disk.Name,
                role: "Dogrudan Ariza",
                latestOccurrence: DateTime.Now,
                occurrenceCount: 1,
                crashRelation: "Depolama arizasi mavi ekrana yol acabilir; dogrudan aygit durum kaniti var",
                directEvidence: true,
                searchKey: disk.Name));
        }
    }

    private static IReadOnlyList<DiagnosticLogItem> BuildDiagnosticLogs(
        IReadOnlyList<EventRecordItem> events,
        IReadOnlyList<ReliabilityRecordItem> reliability,
        IReadOnlyList<string> problemDevices,
        ResourceScanResult resources,
        IReadOnlyList<HealthCheckItem> healthChecks)
    {
        var result = new List<DiagnosticLogItem>();
        foreach (var item in events)
        {
            var category = GetEventCategory(item);
            result.Add(new DiagnosticLogItem(
                item.TimeCreated,
                category,
                ResolveEventComponent(item),
                $"{item.LogName} / {item.Provider}",
                $"Event {item.Id}",
                Truncate(item.Message, 500)));
        }

        foreach (var item in reliability.Where(x => IsReliabilityCrash(x) || IsReliabilityUpdateProblem(x)))
        {
            var component = string.IsNullOrWhiteSpace(item.ProductName) ? item.SourceName : item.ProductName;
            result.Add(new DiagnosticLogItem(
                item.TimeGenerated,
                IsReliabilityCrash(item) ? "Uygulama" : "Update / Kurulum",
                component,
                "Guvenilirlik Gecmisi",
                item.SourceName,
                Truncate(item.Message, 500)));
        }

        foreach (var device in problemDevices)
        {
            result.Add(new DiagnosticLogItem(
                DateTime.Now,
                "Aygit / Surucu",
                device.Split('(')[0].Trim(),
                "Aygit Yoneticisi",
                "ConfigManager",
                device));
        }

        foreach (var metric in resources.Metrics.Where(x => x.Status is "Yuksek" or "Kritik"))
        {
            result.Add(new DiagnosticLogItem(
                DateTime.Now,
                "Kaynak Kullanimi",
                metric.Name,
                "Kaynak Izleyicisi",
                metric.Status,
                $"{metric.Value}. {metric.Detail}"));
        }

        foreach (var check in healthChecks.Where(x => x.Status is "Kritik" or "Uyari" or "Okunamadi"))
        {
            result.Add(new DiagnosticLogItem(
                check.ObservedAt,
                $"Saglik / {check.Category}",
                check.Component,
                "Sistem Saglik Denetimi",
                check.Status,
                $"{check.Value}. {check.Detail}"));
        }

        return result
            .OrderByDescending(x => x.TimeCreated ?? DateTime.MinValue)
            .ToList();
    }

    private static IReadOnlyList<ComponentCount> GetApplicationCrashGroups(
        IEnumerable<EventRecordItem> events,
        IEnumerable<ReliabilityRecordItem> reliability)
    {
        var occurrences = new List<ComponentOccurrence>();
        occurrences.AddRange(events
            .Where(IsApplicationCrash)
            .Select(x => new ComponentOccurrence(ResolveApplicationName(x), x.TimeCreated)));
        occurrences.AddRange(reliability
            .Where(IsReliabilityCrash)
            .Select(x => new ComponentOccurrence(
                string.IsNullOrWhiteSpace(x.ProductName) ? x.SourceName : x.ProductName,
                x.TimeGenerated)));

        return occurrences
            .Where(x => !string.IsNullOrWhiteSpace(x.Name))
            .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Select(x => new ComponentCount(
                x.Key,
                x.GroupBy(y => y.Time?.ToString("yyyyMMddHHmm") ?? Guid.NewGuid().ToString()).Count(),
                x.Max(y => y.Time)))
            .OrderByDescending(x => x.Count)
            .ThenByDescending(x => x.Latest)
            .ToList();
    }

    private static IReadOnlyList<ComponentCount> GetDisplayDriverGroups(IEnumerable<EventRecordItem> events)
    {
        return events
            .Select(x => new ComponentOccurrence(ResolveDisplayComponent(x), x.TimeCreated))
            .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Select(x => new ComponentCount(x.Key, x.Count(), x.Max(y => y.Time)))
            .OrderByDescending(x => x.Count)
            .ThenByDescending(x => x.Latest)
            .ToList();
    }

    private static string GetEventCategory(EventRecordItem item)
    {
        if (IsBugCheck(item) || IsKernelPower(item)) return "Sistem Cokmesi";
        if (IsDumpWriteFailure(item)) return "Mavi Ekran / Dump Yazma";
        if (IsWhea(item)) return "Donanim / WHEA";
        if (IsProcessorPower(item)) return "CPU / BIOS Guc Yonetimi";
        if (IsDiskOrStorage(item)) return "Disk / Depolama";
        if (IsDisplayDriver(item)) return "Ekran Surucusu / GPU";
        if (IsCodeIntegrityFailure(item)) return "Surucu / Code Integrity";
        if (IsDriverInfrastructureFailure(item)) return "Aygit / Surucu";
        if (IsDefenderDetection(item)) return "Guvenlik / Defender";
        if (IsWindowsUpdate(item)) return "Update / Kurulum";
        if (IsApplicationCrash(item)) return "Uygulama";
        if (IsServiceControl(item)) return "Windows Servisi";
        if (item.Provider.Contains("Diagnostics-Performance", StringComparison.OrdinalIgnoreCase)) return "Performans";
        return "Windows Olayi";
    }

    private static string ResolveEventComponent(EventRecordItem item)
    {
        if (IsApplicationCrash(item)) return ResolveApplicationName(item);
        if (IsDisplayDriver(item)) return ResolveDisplayComponent(item);
        if (IsDumpWriteFailure(item)) return "Windows dump yapilandirmasi";
        if (IsCodeIntegrityFailure(item)) return ResolveDriverFile(item);
        if (IsDriverInfrastructureFailure(item)) return ResolveDriverFile(item);
        if (IsDefenderDetection(item)) return "Microsoft Defender";
        if (IsProcessorPower(item)) return "CPU / BIOS Guc Yonetimi";
        if (IsDiskOrStorage(item)) return item.Provider;
        if (IsWindowsUpdate(item)) return item.Provider;
        if (IsWhea(item)) return "WHEA / Donanim";
        if (IsServiceControl(item)) return ResolveServiceName(item.Message);
        return string.IsNullOrWhiteSpace(item.Provider) ? "Windows" : item.Provider;
    }

    private static string ResolveApplicationName(EventRecordItem item)
    {
        var exe = Regex.Match(item.Message, @"(?i)\b[\w.()-]+\.exe\b");
        return exe.Success ? exe.Value : string.IsNullOrWhiteSpace(item.Provider) ? "Bilinmeyen uygulama" : item.Provider;
    }

    private static string ResolveDisplayComponent(EventRecordItem item)
    {
        var driver = Regex.Match(item.Message, @"(?i)\b[\w.-]+\.sys\b");
        if (driver.Success)
        {
            return driver.Value;
        }

        var known = Regex.Match(item.Message, @"(?i)\b(nvlddmkm|amdkmdag|amdwddmg|igdkmdn64|igfx)\b");
        return known.Success ? known.Value : item.Provider;
    }

    private static string ResolveDriverFile(EventRecordItem item)
    {
        var matches = Regex.Matches(item.Message, @"(?i)\b[\w.-]+\.(?:sys|dll|exe)\b");
        return matches.Count > 0
            ? matches[^1].Value
            : string.IsNullOrWhiteSpace(item.Provider) ? "Bilinmeyen surucu" : item.Provider;
    }

    private static string ResolveServiceName(string message)
    {
        var match = Regex.Match(message, @"(?i)(?<name>[\w ._()-]{2,80})\s+(?:service|hizmeti)\b");
        return match.Success ? match.Groups["name"].Value.Trim() : "Service Control Manager";
    }

    private static string Truncate(string value, int length)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "Mesaj yok";
        }

        return value.Length <= length ? value : value[..length] + "...";
    }

    private static bool IsDumpEvidence(BlueScreenRecord record)
    {
        return record.Title.Contains("Minidump dosyasi", StringComparison.OrdinalIgnoreCase) ||
               record.Title.Contains("Kernel/Memory dump", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsBugCheck(EventRecordItem item)
    {
        return item.Id == 1001 &&
               (item.Provider.Contains("BugCheck", StringComparison.OrdinalIgnoreCase) ||
                item.Provider.Contains("WER-SystemErrorReporting", StringComparison.OrdinalIgnoreCase) ||
                item.Message.Contains("bugcheck", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsKernelPower(EventRecordItem item)
    {
        return item.Id == 41 && item.Provider.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsWhea(EventRecordItem item)
    {
        return item.Provider.Contains("WHEA", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSevereWhea(EventRecordItem item)
    {
        var message = FoldText(item.Message);
        return item.Id is 18 or 20 ||
               message.Contains("uncorrectable", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("fatal hardware", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("duzeltilemeyen", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDiskOrStorage(EventRecordItem item)
    {
        var provider = item.Provider;
        return provider.Contains("disk", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("ntfs", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("storahci", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("stornvme", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("storport", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("iastor", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("storage", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("nvme", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("partmgr", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("spaceport", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSevereStorageEvent(EventRecordItem item)
    {
        var message = FoldText(item.Message);
        return item.Id is 7 or 11 or 15 or 55 or 140 or 157 ||
               message.Contains("bad block", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("bozuk sektor", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("corrupt", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDumpWriteFailure(EventRecordItem item)
    {
        return item.Provider.Contains("volmgr", StringComparison.OrdinalIgnoreCase) && item.Id is 45 or 46 or 49 or 161 or 162;
    }

    private static bool IsCodeIntegrityFailure(EventRecordItem item)
    {
        return (item.Provider.Contains("CodeIntegrity", StringComparison.OrdinalIgnoreCase) ||
                item.LogName.Contains("CodeIntegrity", StringComparison.OrdinalIgnoreCase)) &&
               item.Id is 3001 or 3023 or 3033 or 3077;
    }

    private static bool IsDriverInfrastructureFailure(EventRecordItem item)
    {
        return item.Provider.Contains("Kernel-PnP", StringComparison.OrdinalIgnoreCase) ||
               item.Provider.Contains("DriverFrameworks", StringComparison.OrdinalIgnoreCase) ||
               item.Provider.Contains("UserPnp", StringComparison.OrdinalIgnoreCase) ||
               item.Provider.Contains("DeviceSetupManager", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDefenderDetection(EventRecordItem item)
    {
        return item.Provider.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase) && item.Id == 1116;
    }

    private static bool IsWindowsUpdate(EventRecordItem item)
    {
        return item.Provider.Contains("WindowsUpdate", StringComparison.OrdinalIgnoreCase) ||
               item.Provider.Contains("Servicing", StringComparison.OrdinalIgnoreCase) ||
               item.Provider.Contains("SetupPlatform", StringComparison.OrdinalIgnoreCase) ||
               item.LogName.Equals("Setup", StringComparison.OrdinalIgnoreCase) ||
               item.Message.Contains("windows update", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsProcessorPower(EventRecordItem item)
    {
        return item.Provider.Contains("Kernel-Processor-Power", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDisplayDriver(EventRecordItem item)
    {
        return item.Provider.Contains("Display", StringComparison.OrdinalIgnoreCase) ||
               item.Message.Contains("display driver", StringComparison.OrdinalIgnoreCase) ||
               item.Message.Contains("nvlddmkm", StringComparison.OrdinalIgnoreCase) ||
               item.Message.Contains("amdkmdag", StringComparison.OrdinalIgnoreCase) ||
               item.Message.Contains("igdkmd", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsServiceControl(EventRecordItem item)
    {
        return item.Provider.Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsApplicationCrash(EventRecordItem item)
    {
        if (!item.LogName.Equals("Application", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return item.Provider.Contains("Application Error", StringComparison.OrdinalIgnoreCase) ||
               item.Provider.Contains("Application Hang", StringComparison.OrdinalIgnoreCase) ||
               item.Provider.Contains(".NET Runtime", StringComparison.OrdinalIgnoreCase) ||
               item.Provider.Contains("Windows Error Reporting", StringComparison.OrdinalIgnoreCase) ||
               item.Id is 1000 or 1001 or 1002;
    }

    private static bool IsReliabilityCrash(ReliabilityRecordItem item)
    {
        var message = FoldText(item.Message);
        var source = FoldText(item.SourceName);
        return message.Contains("stopped working", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("calismayi durdurdu", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("stopped responding", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("yanit vermeyi durdurdu", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("appcrash", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("apphang", StringComparison.OrdinalIgnoreCase) ||
               source.Contains("application error", StringComparison.OrdinalIgnoreCase) ||
               source.Contains("application hang", StringComparison.OrdinalIgnoreCase) ||
               source.Contains("windows error", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsReliabilityUpdateProblem(ReliabilityRecordItem item)
    {
        var message = FoldText(item.Message);
        var source = FoldText(item.SourceName);
        var updateRelated = message.Contains("update", StringComparison.OrdinalIgnoreCase) ||
                            message.Contains("guncelle", StringComparison.OrdinalIgnoreCase) ||
                            source.Contains("windows update", StringComparison.OrdinalIgnoreCase) ||
                            source.Contains("servicing", StringComparison.OrdinalIgnoreCase);
        var failure = message.Contains("fail", StringComparison.OrdinalIgnoreCase) ||
                      message.Contains("error", StringComparison.OrdinalIgnoreCase) ||
                      message.Contains("hata", StringComparison.OrdinalIgnoreCase) ||
                      message.Contains("basarisiz", StringComparison.OrdinalIgnoreCase) ||
                      message.Contains("0x", StringComparison.OrdinalIgnoreCase);
        return updateRelated && failure;
    }

    private static string FoldText(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        var decomposed = value.Replace('\u0131', 'i').Normalize(NormalizationForm.FormD);
        var builder = new StringBuilder(decomposed.Length);
        foreach (var character in decomposed)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(character) != UnicodeCategory.NonSpacingMark)
            {
                builder.Append(character);
            }
        }

        return builder.ToString().Normalize(NormalizationForm.FormC);
    }

    private static string LatestEvidence(IReadOnlyList<EventRecordItem> items)
    {
        var latest = items.OrderByDescending(x => x.TimeCreated).FirstOrDefault();
        return latest is null
            ? ""
            : $"Son kayit: {latest.TimeCreated:dd.MM.yyyy HH:mm}, {latest.Provider} / Event {latest.Id}.";
    }

    private static string TopSources(IReadOnlyList<EventRecordItem> items)
    {
        if (items.Count == 0)
        {
            return "";
        }

        var sources = items
            .GroupBy(x => $"{x.Provider} / {x.Id}")
            .OrderByDescending(x => x.Count())
            .Take(3)
            .Select(x => $"{x.Key}: {x.Count()} kez");
        return "En cok gorulen kaynaklar: " + string.Join(", ", sources) + ".";
    }

    private static string TopReliabilitySources(IReadOnlyList<ReliabilityRecordItem> items)
    {
        if (items.Count == 0)
        {
            return "";
        }

        var sources = items
            .GroupBy(x => string.IsNullOrWhiteSpace(x.ProductName) ? x.SourceName : x.ProductName)
            .OrderByDescending(x => x.Count())
            .Take(3)
            .Select(x => $"{x.Key}: {x.Count()} kez");
        return "En cok gorulen: " + string.Join(", ", sources) + ".";
    }

    private static IReadOnlyList<JsonElement> ParseJsonElements(string output)
    {
        foreach (var line in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Reverse())
        {
            var candidate = line.Trim();
            if (!candidate.StartsWith('[') && !candidate.StartsWith('{'))
            {
                continue;
            }

            try
            {
                using var document = JsonDocument.Parse(candidate);
                if (document.RootElement.ValueKind == JsonValueKind.Array)
                {
                    return document.RootElement.EnumerateArray().Select(x => x.Clone()).ToList();
                }

                if (document.RootElement.ValueKind == JsonValueKind.Object)
                {
                    return [document.RootElement.Clone()];
                }
            }
            catch (JsonException)
            {
            }
        }

        return [];
    }

    private static string ReadString(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null ? value.ToString() : "";
    }

    private static int ReadInt(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var value) && value.TryGetInt32(out var number) ? number : 0;
    }

    private static DateTime? ReadDate(JsonElement element, string name)
    {
        var text = ReadString(element, name);
        return DateTime.TryParse(text, out var date) ? date : null;
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private sealed record ComponentOccurrence(string Name, DateTime? Time);

    private sealed record ComponentCount(string Name, int Count, DateTime? Latest);

    private sealed record DumpDiscovery(IReadOnlyList<string> Paths, IReadOnlyList<BlueScreenRecord> Signals);


    private sealed record ReliabilityCollectionResult(
        IReadOnlyList<ReliabilityRecordItem> Records,
        ScanCoverageItem Coverage);

    private sealed record ProblemDeviceScanResult(
        IReadOnlyList<string> Devices,
        ScanCoverageItem Coverage);
}
