using System.IO;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class SystemAnalysisService
{
    private readonly CommandRunner _runner;
    private readonly Func<string, Task> _log;
    private readonly SystemInventoryService _inventory;
    private readonly ResourceAnalysisService _resources;
    private readonly AdvancedDumpAnalysisService _dumpAnalysis;

    public SystemAnalysisService(CommandRunner runner, Func<string, Task> log)
    {
        _runner = runner;
        _log = log;
        _inventory = new SystemInventoryService(runner, log);
        _resources = new ResourceAnalysisService(runner, log);
        _dumpAnalysis = new AdvancedDumpAnalysisService(runner, log);
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

    public async Task<GeneralScanResult> RunGeneralScanAsync(CancellationToken cancellationToken)
    {
        await _log("Genel tarama: olay kayitlari, guvenilirlik gecmisi, kaynak kullanimi, aygitlar ve suruculer birlikte inceleniyor.");

        var eventsTask = GetImportantEventsAsync(30, cancellationToken);
        var reliabilityTask = GetReliabilityRecordsAsync(30, cancellationToken);
        var problemDevicesTask = GetProblemDevicesAsync(cancellationToken);
        var systemDetailsTask = _inventory.GetSystemDetailsAsync(cancellationToken);
        var driversTask = _inventory.GetDriverDetailsAsync(cancellationToken);
        var resourcesTask = _resources.ScanAsync(cancellationToken);

        await Task.WhenAll(
            eventsTask,
            reliabilityTask,
            problemDevicesTask,
            systemDetailsTask,
            driversTask,
            resourcesTask);

        var events = await eventsTask;
        var reliability = await reliabilityTask;
        var problemDevices = await problemDevicesTask;
        var systemDetails = await systemDetailsTask;
        var drivers = await driversTask;
        var resourceResult = await resourcesTask;
        var blueScreenResult = await AnalyzeBlueScreensAsync(events, cancellationToken);
        var blueScreens = blueScreenResult.Signals;
        var dumpAnalyses = blueScreenResult.DumpAnalyses;

        var findings = BuildFindings(events, reliability, blueScreens, dumpAnalyses, problemDevices);
        AddDiskSpaceFinding(findings);
        AddResourceFindings(findings, resourceResult);
        AddInventoryFindings(findings, systemDetails);

        if (findings.Count == 0)
        {
            findings.Add(new Finding(
                Severity.Success,
                "Belirgin kritik bulgu bulunmadi.",
                "Okunan kayitlarda acil bir mavi ekran, donanim veya disk sorunu sinyali gorunmuyor.",
                "Event Viewer, Reliability Monitor, kaynak kullanimi, dump dosyalari, diskler, aygitlar ve suruculer tarandi.",
                "Sorun devam ediyorsa hatanin oldugu saat araliginda tekrar tarama yapin veya teknik detaylari raporlayin."));
        }

        var orderedFindings = findings
            .OrderBy(x => x.Severity)
            .ThenBy(x => x.Title)
            .ToList();

        var diagnosticLogs = BuildDiagnosticLogs(events, reliability, problemDevices, resourceResult);
        var summary = BuildUserSummary(events, reliability, blueScreens, dumpAnalyses, problemDevices, resourceResult, orderedFindings);
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
            systemDetails,
            drivers,
            resourceResult.Metrics);
    }

    public async Task<BlueScreenScanResult> AnalyzeBlueScreensAsync(CancellationToken cancellationToken)
    {
        var events = await GetImportantEventsAsync(30, cancellationToken);
        return await AnalyzeBlueScreensAsync(events, cancellationToken);
    }

    public async Task<BlueScreenScanResult> AnalyzeSelectedDumpAsync(string dumpPath, CancellationToken cancellationToken)
    {
        var events = await GetImportantEventsAsync(30, cancellationToken);
        return await _dumpAnalysis.AnalyzeAsync([dumpPath], events, cancellationToken);
    }

    private async Task<BlueScreenScanResult> AnalyzeBlueScreensAsync(
        IReadOnlyList<EventRecordItem> events,
        CancellationToken cancellationToken)
    {
        await _log("Mavi ekran derin analizi: dump butunlugu, WinDbg sembolleri, stop code, stack, surucu ve olay korelasyonu inceleniyor.");
        var discovery = DiscoverDumpFiles();
        var result = await _dumpAnalysis.AnalyzeAsync(discovery.Paths, events, cancellationToken);
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
        await _log($"Event Viewer taraniyor: son {days} gunun kritik/hata kayitlari ve servis/disk/update sinyalleri.");
        var script = """
            $start = (Get-Date).AddDays(-{DAYS})
            $events = @()
            try { $events += Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start; Level=1,2} -MaxEvents 220 -ErrorAction Stop } catch {}
            @(
              @{Provider='disk'; Id=@(7,11,51,153,157)},
              @{Provider='Microsoft-Windows-Ntfs'; Id=@(55,98,140)},
              @{Provider='storahci'; Id=@(129,153)},
              @{Provider='stornvme'; Id=@(129,153)},
              @{Provider='storport'; Id=@(129,153)},
              @{Provider='volmgr'; Id=@(46,161,162)},
              @{Provider='Microsoft-Windows-WHEA-Logger'; Id=@(18,19,20,47)},
              @{Provider='Service Control Manager'; Id=@(7000,7001,7009,7026,7031,7034)}
            ) | ForEach-Object {
              try { $events += Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start; ProviderName=$_.Provider; Id=$_.Id; Level=1,2,3} -MaxEvents 160 -ErrorAction Stop } catch {}
            }
            try { $events += Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$start; Level=1,2} -MaxEvents 220 -ErrorAction Stop } catch {}
            try { $events += Get-WinEvent -FilterHashtable @{LogName='Setup'; StartTime=$start; Level=1,2,3} -MaxEvents 120 -ErrorAction Stop } catch {}
            @(
              'Microsoft-Windows-DeviceSetupManager/Admin',
              'Microsoft-Windows-DriverFrameworks-UserMode/Operational',
              'Microsoft-Windows-WindowsUpdateClient/Operational',
              'Microsoft-Windows-Diagnostics-Performance/Operational'
            ) | ForEach-Object {
              try { $events += Get-WinEvent -FilterHashtable @{LogName=$_; StartTime=$start; Level=1,2,3} -MaxEvents 100 -ErrorAction Stop } catch {}
            }
            $events |
              Where-Object { $_ -ne $null } |
              Group-Object {$_.LogName + '|' + $_.RecordId} |
              ForEach-Object { $_.Group[0] } |
              Sort-Object TimeCreated -Descending |
              Select-Object -First 500 @{N='TimeCreated';E={$_.TimeCreated.ToString('o')}},LogName,ProviderName,Id,LevelDisplayName,@{N='Message';E={$m=$_.Message; if ([string]::IsNullOrWhiteSpace($m)) { '' } else { $m=$m -replace '\s+',' '; if ($m.Length -gt 900) { $m.Substring(0,900) } else { $m } }}} |
              ConvertTo-Json -Depth 3 -Compress
            """.Replace("{DAYS}", days.ToString());

        var result = await _runner.RunPowerShellAsync(script, cancellationToken, false, "Event Viewer kayitlari okunuyor");
        return ParseEvents(result.Output);
    }

    public async Task<IReadOnlyList<ReliabilityRecordItem>> GetReliabilityRecordsAsync(int days, CancellationToken cancellationToken)
    {
        await _log($"Reliability Monitor taraniyor: son {days} gunun cokme, update ve kurulum kayitlari.");
        var script = """
            $start = (Get-Date).AddDays(-{DAYS})
            Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction SilentlyContinue |
              Where-Object { $_.TimeGenerated -ge $start } |
              Sort-Object TimeGenerated -Descending |
              Select-Object -First 160 @{N='TimeGenerated';E={$_.TimeGenerated.ToString('o')}},SourceName,ProductName,@{N='Message';E={$m=$_.Message; if ([string]::IsNullOrWhiteSpace($m)) { '' } else { $m=$m -replace '\s+',' '; if ($m.Length -gt 700) { $m.Substring(0,700) } else { $m } }}} |
              ConvertTo-Json -Depth 3 -Compress
            """.Replace("{DAYS}", days.ToString());

        var result = await _runner.RunPowerShellAsync(script, cancellationToken, false, "Guvenilirlik gecmisi okunuyor");
        return ParseReliability(result.Output);
    }

    private List<Finding> BuildFindings(
        IReadOnlyList<EventRecordItem> events,
        IReadOnlyList<ReliabilityRecordItem> reliability,
        IReadOnlyList<BlueScreenRecord> blueScreens,
        IReadOnlyList<DumpAnalysisItem> dumpAnalyses,
        IReadOnlyList<string> problemDevices)
    {
        var findings = new List<Finding>();
        var bugChecks = events.Where(IsBugCheck).ToList();
        var kernelPower = events.Where(IsKernelPower).ToList();
        var whea = events.Where(IsWhea).ToList();
        var disk = events.Where(IsDiskOrStorage).ToList();
        var update = events.Where(IsWindowsUpdate).ToList();
        var display = events.Where(IsDisplayDriver).ToList();
        var processorPower = events.Where(IsProcessorPower).ToList();
        var services = events.Where(IsServiceControl).ToList();
        var applicationGroups = GetApplicationCrashGroups(events, reliability);
        var displayGroups = GetDisplayDriverGroups(display);
        var reliabilityUpdates = reliability.Where(IsReliabilityUpdateProblem).ToList();
        var dumpEvidenceCount = Math.Max(blueScreens.Count(IsDumpEvidence), dumpAnalyses.Count);

        if (bugChecks.Count > 0 || dumpEvidenceCount > 0)
        {
            findings.Add(new Finding(
                Severity.Critical,
                "Mavi ekran veya dump kaniti bulundu.",
                "Sistem bir BugCheck ile kapanmis olabilir. Bu surucu, RAM, disk/NVMe veya donanim kararsizligi kaynakli olabilir.",
                $"{bugChecks.Count} BugCheck kaydi, {dumpEvidenceCount} dump dosyasi bulundu. {LatestEvidence(bugChecks)}",
                "Mavi Ekran sekmesindeki BugCheck zamanlarini WHEA, disk ve yeni yuklenen suruculerle birlikte kontrol edin."));
        }

        foreach (var dump in dumpAnalyses
                     .OrderBy(x => x.Confidence == "Yuksek" ? 0 : x.Confidence == "Orta-Yuksek" ? 1 : x.Confidence == "Orta" ? 2 : 3)
                     .ThenByDescending(x => x.CreatedAt)
                     .Take(3))
        {
            var severity = dump.Confidence is "Yuksek" or "Orta-Yuksek" ? Severity.Critical : Severity.Warning;
            findings.Add(new Finding(
                severity,
                $"Dump analizi {dump.SuspectedComponent} bilesenini isaret ediyor.",
                dump.RootCauseSummary,
                $"{dump.FileName}: {dump.BugCheckCode} {dump.BugCheckName}; Guven: {dump.Confidence}.{Environment.NewLine}{dump.Evidence}",
                dump.Recommendation));
        }

        if (whea.Count > 0)
        {
            findings.Add(new Finding(
                Severity.Critical,
                "Donanim kararsizligi sinyali var.",
                "WHEA kayitlari CPU, RAM, anakart, PCIe, ekran karti veya NVMe tarafinda hata ihtimali gosterebilir.",
                $"{whea.Count} WHEA-Logger kaydi bulundu. {TopSources(whea)}",
                "BIOS guncellemesi, XMP/EXPO kapatma, sicaklik kontrolu, RAM testi ve disk/NVMe sagligi kontrolu onerilir."));
        }

        if (disk.Count > 0)
        {
            var severity = disk.Count >= 3 ? Severity.Critical : Severity.Warning;
            findings.Add(new Finding(
                severity,
                "Disk veya depolama tarafi hata veriyor olabilir.",
                "Disk, NTFS, storahci/stornvme, volmgr veya benzeri kayitlar depolama surucusu, dosya sistemi ya da kontrolcu sorununa isaret edebilir.",
                $"{disk.Count} depolama iliskili olay bulundu. {TopSources(disk)}",
                "SMART sagligini kontrol edin, chkdsk /scan calistirin ve NVMe/SATA/chipset suruculerini uretici sitesinden kontrol edin."));
        }

        foreach (var group in displayGroups.Take(2))
        {
            findings.Add(new Finding(
                Severity.Warning,
                $"{group.Name} ekran surucusu/GPU hatasi veriyor.",
                "Display/nvlddmkm/amdkmdag/igfx benzeri kayitlar ekran surucusu cokmesi, TDR veya GPU kararsizligi ile iliskili olabilir.",
                $"{group.Count} ilgili olay bulundu. Son kayit: {group.Latest:dd.MM.yyyy HH:mm}.",
                "Ekran karti surucusunu temiz kurulumla guncelleyin; sorun yuk altinda oluyorsa sicaklik ve guc kaynagi da kontrol edilmeli."));
        }

        if (processorPower.Count > 0)
        {
            findings.Add(new Finding(
                processorPower.Count >= 5 ? Severity.Warning : Severity.Info,
                "CPU guc yonetimi veya BIOS/firmware hata kaydi olusturuyor.",
                "Kernel-Processor-Power kayitlari BIOS guc tablolari, islemci frekans siniri, chipset surucusu veya guc planiyla iliskili olabilir.",
                $"{processorPower.Count} Kernel-Processor-Power kaydi bulundu. {TopSources(processorPower)}",
                "BIOS ve chipset surumlerini uretici sayfasiyla karsilastirin; varsayilan BIOS ayarlari ve Dengeli guc planiyla tekrar kontrol edin."));
        }

        if (kernelPower.Count > 0)
        {
            findings.Add(new Finding(
                Severity.Warning,
                "Beklenmedik kapanma veya zorla yeniden baslatma var.",
                "Kernel-Power 41 sebep degil, sonucu gosterir. Mavi ekran, guc kesintisi, PSU/adaptor, kilitlenme veya reset olabilir.",
                $"{kernelPower.Count} Kernel-Power 41 kaydi bulundu. {LatestEvidence(kernelPower)}",
                "Ayni saatlerde BugCheck, WHEA veya disk kaydi varsa asil sebep onlara gore degerlendirilmelidir."));
        }

        if (update.Count > 0 || reliabilityUpdates.Count > 0)
        {
            findings.Add(new Finding(
                Severity.Warning,
                "Windows Update veya kurulum sorunu gorunuyor.",
                "Update onbellegi, Windows imaji, servisler veya kurulum paketi tarafinda sorun olabilir.",
                $"{update.Count} Event Log update olayi, {reliabilityUpdates.Count} Reliability update/kurulum kaydi bulundu.",
                "Once DISM CheckHealth/ScanHealth calistirin. Devam ederse Windows Update Reset aracini kullanin."));
        }

        foreach (var group in applicationGroups.Take(3))
        {
            findings.Add(new Finding(
                group.Count >= 3 ? Severity.Warning : Severity.Info,
                $"{group.Name} uygulamasinda cokme/hata tespit edildi.",
                "Bu durum her zaman Windows bozulmasi anlamina gelmez; belirli bir uygulama, .NET runtime, tarayici eklentisi veya surucu bagimli yazilim cokuyor olabilir.",
                $"Son 30 gunde {group.Count} kayit bulundu. Son kayit: {group.Latest:dd.MM.yyyy HH:mm}.",
                $"{group.Name} uygulamasini ve bagli eklenti/suruculerini guncelleyin; devam ederse yeniden kurulum veya temiz baslangic testi yapin."));
        }

        if (services.Count > 0)
        {
            findings.Add(new Finding(
                services.Count >= 5 ? Severity.Warning : Severity.Info,
                "Windows servislerinde hata kayitlari var.",
                "Bazi servisler beklenmedik sekilde durmus veya baslatilamamis olabilir. Bu, ana sebep olabilecegi gibi baska bir hatanin sonucu da olabilir.",
                $"{services.Count} Service Control Manager olayi bulundu. {TopSources(services)}",
                "Hizmetler kisayolundan ilgili servisi kontrol edin; ayni saatte update, disk veya uygulama hatasi var mi karsilastirin."));
        }

        foreach (var device in problemDevices.Take(5))
        {
            var deviceName = device.Split('(')[0].Trim();
            findings.Add(new Finding(
                Severity.Warning,
                $"{deviceName} aygitinda surucu/donanim sorunu var.",
                "Bir donanim veya surucu Windows tarafindan problemli isaretlenmis.",
                device,
                "Aygit Yoneticisi kisayolunu acip sorunlu aygitin surucu durumunu kontrol edin."));
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
        IReadOnlyList<Finding> findings)
    {
        var conclusions = new List<SummaryConclusion>();
        var strongestDump = dumpAnalyses
            .OrderBy(x => x.Confidence == "Yuksek" ? 0 : x.Confidence == "Orta-Yuksek" ? 1 : x.Confidence == "Orta" ? 2 : 3)
            .ThenByDescending(x => x.CreatedAt)
            .FirstOrDefault();
        if (strongestDump is not null)
        {
            conclusions.Add(new SummaryConclusion(
                100,
                $"Derin dump analizi: {strongestDump.BugCheckCode} {strongestDump.BugCheckName}; asil supheli {strongestDump.SuspectedComponent}, guven {strongestDump.Confidence}."));
        }

        var application = GetApplicationCrashGroups(events, reliability).FirstOrDefault();
        if (application is not null)
        {
            conclusions.Add(new SummaryConclusion(
                application.Count * 3,
                $"{application.Name} uygulamasi son 30 gunde {application.Count} kez cokme/hata kaydi olusturmus."));
        }

        var display = GetDisplayDriverGroups(events.Where(IsDisplayDriver)).FirstOrDefault();
        if (display is not null)
        {
            conclusions.Add(new SummaryConclusion(
                display.Count * 5,
                $"{display.Name} ekran surucusu/GPU tarafinda {display.Count} hata kaydi var."));
        }

        if (problemDevices.Count > 0)
        {
            conclusions.Add(new SummaryConclusion(
                problemDevices.Count * 6,
                $"Aygit Yoneticisi {problemDevices[0]} aygitini problemli isaretliyor."));
        }

        var bugChecks = events.Count(IsBugCheck);
        var dumpEvidence = Math.Max(blueScreens.Count(IsDumpEvidence), dumpAnalyses.Count);
        if (bugChecks > 0 || dumpEvidence > 0)
        {
            conclusions.Add(new SummaryConclusion(
                bugChecks * 7 + dumpEvidence * 5,
                $"{bugChecks} BugCheck kaydi ve {dumpEvidence} dump dosyasi mavi ekran/sistem cokmesi kaniti veriyor."));
        }

        var whea = events.Count(IsWhea);
        if (whea > 0)
        {
            conclusions.Add(new SummaryConclusion(whea * 7, $"WHEA-Logger {whea} donanim kararsizligi kaydi olusturmus."));
        }

        var processorPower = events.Count(IsProcessorPower);
        if (processorPower > 0)
        {
            conclusions.Add(new SummaryConclusion(
                processorPower * 2,
                $"Microsoft-Windows-Kernel-Processor-Power {processorPower} CPU guc/BIOS yonetimi hatasi kaydetmis."));
        }

        var diskEvents = events.Where(IsDiskOrStorage).ToList();
        if (diskEvents.Count > 0)
        {
            var source = diskEvents.GroupBy(x => x.Provider).OrderByDescending(x => x.Count()).First();
            conclusions.Add(new SummaryConclusion(
                diskEvents.Count * 5,
                $"{source.Key} kaynaginda {source.Count()} tekrar eden disk/depolama hatasi var."));
        }

        var update = events.Count(IsWindowsUpdate) + reliability.Count(IsReliabilityUpdateProblem);
        if (update > 0)
        {
            conclusions.Add(new SummaryConclusion(update * 2, $"Windows Update/kurulum tarafinda {update} hata veya uyari kaydi var."));
        }

        if (resources.CpuAverage >= 85)
        {
            conclusions.Add(new SummaryConclusion(
                4,
                $"CPU kullanimi ortalama %{resources.CpuAverage:N1}; en yogun islem {resources.TopCpuProcess} (%{resources.TopCpuPercent:N1})."));
        }

        if (resources.MemoryAverage >= 85)
        {
            conclusions.Add(new SummaryConclusion(
                4,
                $"RAM kullanimi %{resources.MemoryAverage:N1}; en cok bellek kullanan islem {resources.TopMemoryProcess} ({resources.TopMemoryMb:N0} MB)."));
        }

        if (resources.DiskAverage >= 80 || resources.DiskQueuePeak >= 2)
        {
            conclusions.Add(new SummaryConclusion(
                5,
                $"Disk etkinligi ortalama %{resources.DiskAverage:N1}, kuyruk tepe degeri {resources.DiskQueuePeak:N2}; depolama darbogazi ihtimali var."));
        }

        if (conclusions.Count == 0)
        {
            return "Tarama sonucunda belirgin bir kritik hata sinyali bulunmadi. Event Viewer, Guvenilirlik Gecmisi, kaynak kullanimi, aygitlar, diskler ve dump kayitlari birlikte kontrol edildi. Sorun devam ediyorsa sorun yasandiktan hemen sonra tekrar tarama yapin.";
        }

        var prefix = findings.Any(x => x.Severity == Severity.Critical)
            ? "Tarama sonucu, once kritik bulgular incelenmeli: "
            : "Tarama sonucu: ";
        return prefix + string.Join(" ", conclusions
            .OrderByDescending(x => x.Score)
            .Take(4)
            .Select(x => x.Text)) + " Ayiklanan kayitlar Hata Analizi bolumunde tek tek listelendi.";
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

    private async Task<IReadOnlyList<string>> GetProblemDevicesAsync(CancellationToken cancellationToken)
    {
        await _log("Aygit Yoneticisi hata kodlari kontrol ediliyor.");
        var script = """
            Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
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

        return devices;
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
            findings.Add(new Finding(
                Severity.Warning,
                "Sistem diskinde bos alan dusuk.",
                "Dusuk bos alan Windows Update, dump yazimi, paging ve sistem kararliligini etkileyebilir.",
                $"{drive.Name} bos alan: {drive.AvailableFreeSpace / 1024 / 1024 / 1024:N1} GB (%{freePercent:N1}).",
                "Kullanici dosyalarini tasiyin veya gereksiz gecici dosyalari guvenli temizlik araci ile temizleyin."));
        }
    }

    private static void AddResourceFindings(List<Finding> findings, ResourceScanResult resources)
    {
        if (resources.CpuAverage >= 85)
        {
            var process = string.IsNullOrWhiteSpace(resources.TopCpuProcess) ? "Bilinmeyen islem" : resources.TopCpuProcess;
            findings.Add(new Finding(
                resources.CpuAverage >= 95 ? Severity.Critical : Severity.Warning,
                $"{process} islemiyle birlikte CPU kullanimi yuksek.",
                "Islemci kullanimi tarama boyunca yuksek kaldi. Arka plan uygulamasi, surucu veya takilan bir islem buna neden olabilir.",
                $"CPU ortalama %{resources.CpuAverage:N1}, tepe %{resources.CpuPeak:N1}. {process}: %{resources.TopCpuPercent:N1}.",
                "Gorev Yoneticisi ve Kaynak Izleyicisi'nde ayni islemin surekli yuksek kalip kalmadigini kontrol edin."));
        }

        if (resources.MemoryAverage >= 85)
        {
            var process = string.IsNullOrWhiteSpace(resources.TopMemoryProcess) ? "Bilinmeyen islem" : resources.TopMemoryProcess;
            findings.Add(new Finding(
                resources.MemoryAverage >= 95 ? Severity.Critical : Severity.Warning,
                $"RAM kullanimi yuksek; en cok kullanan islem {process}.",
                "Yuksek bellek kullanimi takilma, disk paging ve uygulama kapanmalarina yol acabilir.",
                $"RAM kullanimi %{resources.MemoryAverage:N1}. {process}: {resources.TopMemoryMb:N0} MB.",
                "Gorev Yoneticisi'nde bellek siralamasini kontrol edin; gereksiz baslangic uygulamalarini kapatin ve bellek sizintisi ihtimalini izleyin."));
        }

        if (resources.DiskAverage >= 80 || resources.DiskQueuePeak >= 2)
        {
            findings.Add(new Finding(
                resources.DiskAverage >= 95 || resources.DiskQueuePeak >= 4 ? Severity.Critical : Severity.Warning,
                "Disk etkinligi veya disk kuyrugu yuksek.",
                "Depolama aygiti yogun calisiyor, gecikiyor veya RAM yetersizligi nedeniyle paging yapiyor olabilir.",
                $"Disk ortalama %{resources.DiskAverage:N1}, tepe %{resources.DiskPeak:N1}, kuyruk tepe {resources.DiskQueuePeak:N2}.",
                "Kaynak Izleyicisi Disk bolumunde en cok okuma/yazma yapan islemi kontrol edin; disk sagligi ve bos alani da incelenmeli."));
        }
    }

    private static void AddInventoryFindings(List<Finding> findings, IReadOnlyList<SystemInfoItem> systemDetails)
    {
        foreach (var sensor in systemDetails.Where(x =>
                     (x.Category == "CPU Sicakligi" || x.Category == "GPU Sicakligi") &&
                     (x.Status == "Yuksek" || x.Status == "Kritik")))
        {
            findings.Add(new Finding(
                sensor.Status == "Kritik" ? Severity.Critical : Severity.Warning,
                $"{sensor.Name} sicakligi {sensor.Status.ToLowerInvariant()}.",
                "Yuksek sicaklik performans dusmesine, kapanmaya veya kararsizliga neden olabilir.",
                $"Olculen deger: {sensor.Value}.",
                "Fan, hava kanali, termal macun ve yuk altindaki sicaklik davranisini kontrol edin."));
        }

        foreach (var disk in systemDetails.Where(x =>
                     x.Category == "Depolama" &&
                     !string.IsNullOrWhiteSpace(x.Status) &&
                     !x.Status.Equals("Normal", StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(new Finding(
                Severity.Warning,
                $"{disk.Name} depolama aygiti normal durum bildirmiyor.",
                "Disk veya denetleyici Windows'a normal disinda bir durum bildirdi.",
                $"{disk.Value}; {disk.Status}",
                "Onemli verileri yedekleyin ve ureticinin SMART/diagnostic araci ile ayrintili test yapin."));
        }
    }

    private static IReadOnlyList<DiagnosticLogItem> BuildDiagnosticLogs(
        IReadOnlyList<EventRecordItem> events,
        IReadOnlyList<ReliabilityRecordItem> reliability,
        IReadOnlyList<string> problemDevices,
        ResourceScanResult resources)
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
        if (IsWhea(item)) return "Donanim / WHEA";
        if (IsProcessorPower(item)) return "CPU / BIOS Guc Yonetimi";
        if (IsDiskOrStorage(item)) return "Disk / Depolama";
        if (IsDisplayDriver(item)) return "Ekran Surucusu / GPU";
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
               provider.Contains("volmgr", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("partmgr", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("spaceport", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsWindowsUpdate(EventRecordItem item)
    {
        return item.Provider.Contains("WindowsUpdate", StringComparison.OrdinalIgnoreCase) ||
               item.Provider.Contains("Servicing", StringComparison.OrdinalIgnoreCase) ||
               item.Provider.Contains("SetupPlatform", StringComparison.OrdinalIgnoreCase) ||
               item.Provider.Contains("DeviceSetupManager", StringComparison.OrdinalIgnoreCase) ||
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
        return item.Message.Contains("stopped working", StringComparison.OrdinalIgnoreCase) ||
               item.Message.Contains("calismayi durdurdu", StringComparison.OrdinalIgnoreCase) ||
               item.Message.Contains("stopped responding", StringComparison.OrdinalIgnoreCase) ||
               item.Message.Contains("APPCRASH", StringComparison.OrdinalIgnoreCase) ||
               item.Message.Contains("AppHang", StringComparison.OrdinalIgnoreCase) ||
               item.SourceName.Contains("Application Error", StringComparison.OrdinalIgnoreCase) ||
               item.SourceName.Contains("Application Hang", StringComparison.OrdinalIgnoreCase) ||
               item.SourceName.Contains("Windows Error", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsReliabilityUpdateProblem(ReliabilityRecordItem item)
    {
        var updateRelated = item.Message.Contains("update", StringComparison.OrdinalIgnoreCase) ||
                            item.Message.Contains("guncelle", StringComparison.OrdinalIgnoreCase) ||
                            item.SourceName.Contains("Windows Update", StringComparison.OrdinalIgnoreCase) ||
                            item.SourceName.Contains("Servicing", StringComparison.OrdinalIgnoreCase);
        var failure = item.Message.Contains("fail", StringComparison.OrdinalIgnoreCase) ||
                      item.Message.Contains("error", StringComparison.OrdinalIgnoreCase) ||
                      item.Message.Contains("hata", StringComparison.OrdinalIgnoreCase) ||
                      item.Message.Contains("basarisiz", StringComparison.OrdinalIgnoreCase) ||
                      item.Message.Contains("0x", StringComparison.OrdinalIgnoreCase);
        return updateRelated && failure;
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

    private sealed record SummaryConclusion(int Score, string Text);

    private sealed record DumpDiscovery(IReadOnlyList<string> Paths, IReadOnlyList<BlueScreenRecord> Signals);
}
