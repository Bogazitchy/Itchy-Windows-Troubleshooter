using System.Diagnostics;
using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class AdvancedDumpAnalysisService
{
    private static readonly HashSet<string> GenericComponents = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe", "hal.dll",
        "memory_corruption", "hardware", "unknown_image", "win32kfull.sys", "win32kbase.sys"
    };

    private static readonly HashSet<string> StackFrameworkModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "nt", "ntkrnlmp", "ntoskrnl", "hal", "kd", "Wdf01000", "fltmgr", "storport",
        "stornvme", "storahci", "ndis", "tcpip", "CLASSPNP", "disk", "partmgr", "volmgr",
        "NTFS", "Fs_Rec", "CI", "dxgkrnl", "watchdog", "win32kfull", "win32kbase"
    };

    private static readonly IReadOnlyDictionary<string, BugCheckDescription> BugChecks =
        new Dictionary<string, BugCheckDescription>(StringComparer.OrdinalIgnoreCase)
        {
            ["0xA"] = new("IRQL_NOT_LESS_OR_EQUAL", "Surucu gecersiz bellek adresine yuksek IRQL seviyesinde eristi; RAM bozulmasi da ihtimaldir.", "Suruculeri, RAM'i ve varsa overclock/XMP ayarlarini kontrol edin."),
            ["0x1A"] = new("MEMORY_MANAGEMENT", "Bellek yonetimi tutarsizlik tespit etti. RAM, depolama paging veya bellek bozan surucu olabilir.", "Windows Memory Diagnostic yerine uzun MemTest86 testi, XMP/EXPO kapatma ve surucu kontrolu yapin."),
            ["0x3B"] = new("SYSTEM_SERVICE_EXCEPTION", "Kernel modunda sistem servisi istisnasi olustu; ucuncu taraf surucu veya bellek bozulmasi yaygin nedendir.", "Stack'teki ucuncu taraf surucuyu guncelleyin/kaldirin ve RAM testi yapin."),
            ["0x50"] = new("PAGE_FAULT_IN_NONPAGED_AREA", "Gecerli olmasi gereken kernel bellegine erisim basarisiz oldu. Surucu, RAM veya disk kaynakli olabilir.", "RAM, disk ve stack'te gorunen surucuyu birlikte kontrol edin."),
            ["0x7B"] = new("INACCESSIBLE_BOOT_DEVICE", "Windows acilis diskine erisemedi. NVMe/SATA/VMD modu, depolama surucusu veya disk sorunu olabilir.", "BIOS depolama modunu, NVMe/SATA sagligini ve chipset/depolama surucusunu kontrol edin."),
            ["0x7E"] = new("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "Bir sistem is parcaciginda yakalanmayan istisna olustu; genellikle surucu kaynaklidir.", "IMAGE_NAME ve stack'te gorunen ucuncu taraf surucuyu temiz kurulumla guncelleyin."),
            ["0x7F"] = new("UNEXPECTED_KERNEL_MODE_TRAP", "CPU trap hatasi; RAM, CPU, overclock, BIOS veya dusuk seviyeli surucu ihtimali vardir.", "BIOS varsayilanlari, RAM/CPU testi ve sicaklik kontrolu yapin."),
            ["0x9F"] = new("DRIVER_POWER_STATE_FAILURE", "Bir surucu guc durumu istegini zamaninda tamamlamadi.", "Uyku/uyanma ve kapanma ile ilgili aygit surucusunu, BIOS ve chipset surucusunu guncelleyin."),
            ["0xC2"] = new("BAD_POOL_CALLER", "Bir surucu kernel bellek havuzunu hatali kullandi.", "Verifier/stack tarafindan isaretlenen ucuncu taraf surucuyu kaldirin veya guncelleyin."),
            ["0xC4"] = new("DRIVER_VERIFIER_DETECTED_VIOLATION", "Driver Verifier bir surucu ihlali yakaladi.", "WinDbg'nin isaretledigi surucuyu duzeltin; test bitince Driver Verifier'i kapatin."),
            ["0xC5"] = new("DRIVER_CORRUPTED_EXPOOL", "Surucu kernel bellek havuzunu bozdu.", "Stack ve IMAGE_NAME alanindaki surucuyu onceleyin; RAM testi de yapin."),
            ["0xD1"] = new("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "Kernel surucusu gecersiz veya sayfalanabilir bellege yanlis IRQL seviyesinde eristi.", "Isaretlenen .sys surucusunu temiz kurulumla guncelleyin veya onceki kararli surume donun."),
            ["0xEF"] = new("CRITICAL_PROCESS_DIED", "Windows icin kritik bir surec beklenmedik sekilde sonlandi. Disk, sistem dosyasi veya surucu etkisi olabilir.", "Disk/NTFS olaylarini, SFC-DISM sonucunu ve PROCESS_NAME alanini birlikte inceleyin."),
            ["0xF4"] = new("CRITICAL_OBJECT_TERMINATION", "Kritik sistem sureci veya is parcacigi sonlandi; depolama ve sistem dosyalari sik nedendir.", "SMART, disk kablosu/denetleyicisi, sistem dosyalari ve ilgili sureci kontrol edin."),
            ["0x101"] = new("CLOCK_WATCHDOG_TIMEOUT", "Bir CPU cekirdegi beklenen clock kesmesini vermedi. CPU/BIOS/voltaj/overclock ihtimali yuksektir.", "BIOS varsayilanlari, BIOS guncellemesi, CPU sicakligi ve guc kaynagini kontrol edin."),
            ["0x109"] = new("CRITICAL_STRUCTURE_CORRUPTION", "Kernel kodu veya kritik veri bozuldu. Surucu, RAM ya da kernel degisikligi olabilir.", "RAM testi yapin; dusuk seviyeli guvenlik, RGB, overclock ve sanallastirma suruculerini kontrol edin."),
            ["0x10E"] = new("VIDEO_MEMORY_MANAGEMENT_INTERNAL", "Ekran bellegi yonetiminde kritik hata olustu.", "GPU surucusunu temiz kurun; VRAM/GPU sicakligi ve guc kaynagini kontrol edin."),
            ["0x116"] = new("VIDEO_TDR_FAILURE", "GPU zaman asimindan sonra ekran surucusu kurtarilamadi.", "GPU surucusunu temiz kurun; GPU sicakligi, guc ve donanim kararliligini kontrol edin."),
            ["0x117"] = new("VIDEO_TDR_TIMEOUT_DETECTED", "GPU veya ekran surucusu zaman asimina ugradi.", "Ekran surucusu, GPU sicakligi ve guc kaynagini kontrol edin."),
            ["0x119"] = new("VIDEO_SCHEDULER_INTERNAL_ERROR", "GPU zamanlayicisi kritik bir ihlal algiladi.", "Ekran surucusunu temiz kurun ve GPU/VRAM kararliligini test edin."),
            ["0x124"] = new("WHEA_UNCORRECTABLE_ERROR", "WHEA duzeltilemeyen donanim hatasi bildirdi. CPU, RAM, PCIe, GPU, NVMe veya anakart olabilir.", "WHEA kaydini, BIOS'u, XMP/overclock ayarlarini, sicakliklari ve donanim stres testlerini inceleyin."),
            ["0x12B"] = new("FAULTY_HARDWARE_CORRUPTED_PAGE", "Windows donanim kaynakli bozulmus bellek sayfasi tespit etti.", "RAM'i modulleri tek tek test ederek kontrol edin; CPU bellek denetleyicisi ve XMP/EXPO'yu da inceleyin."),
            ["0x133"] = new("DPC_WATCHDOG_VIOLATION", "Bir DPC/ISR rutini cok uzun surdu. Depolama, ag, GPU veya diger kernel suruculeri yaygin nedendir.", "Stack'teki surucuyu, NVMe/SATA ve chipset suruculerini guncelleyin."),
            ["0x139"] = new("KERNEL_SECURITY_CHECK_FAILURE", "Kernel veri yapisi bozuldu. Surucu bellek ihlali veya RAM sorunu olabilir.", "Stack'teki ucuncu taraf surucuyu ve RAM'i kontrol edin."),
            ["0x14F"] = new("PDC_WATCHDOG_TIMEOUT", "Guc yonetimi islemi zaman asimina ugradi.", "BIOS, chipset ve guc yonetimiyle iliskili aygit suruculerini guncelleyin."),
            ["0x154"] = new("UNEXPECTED_STORE_EXCEPTION", "Kernel depolama bileseni beklenmeyen istisna bildirdi. Disk/NVMe, dosya sistemi veya bellek etkili olabilir.", "SMART, NTFS/disk olaylari, NVMe firmware ve RAM'i kontrol edin.")
        };

    private readonly CommandRunner _runner;
    private readonly Func<string, Task> _log;

    public AdvancedDumpAnalysisService(CommandRunner runner, Func<string, Task> log)
    {
        _runner = runner;
        _log = log;
    }

    public async Task<BlueScreenScanResult> AnalyzeAsync(
        IReadOnlyList<string> dumpPaths,
        IReadOnlyList<EventRecordItem> contextEvents,
        CancellationToken cancellationToken)
    {
        var distinctPaths = dumpPaths
            .Where(File.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(SafeLastWriteTime)
            .Take(10)
            .ToList();

        var debugger = await FindDebuggerAsync(cancellationToken);
        if (debugger is null && distinctPaths.Count > 0)
        {
            await _log("WinDbg/KD bulunamadi. Dump basligi ve Event Viewer verileriyle sinirli analiz yapilacak.");
        }

        var analyses = new List<DumpAnalysisItem>();
        foreach (var path in distinctPaths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            analyses.Add(await AnalyzeSingleAsync(path, debugger, contextEvents, cancellationToken));
        }

        analyses = ApplyRecurringEvidence(analyses).ToList();
        var signals = BuildEventSignals(contextEvents);
        var summary = BuildOverallSummary(analyses, contextEvents, debugger);
        return new BlueScreenScanResult(summary, analyses, signals);
    }

    private async Task<DumpAnalysisItem> AnalyzeSingleAsync(
        string dumpPath,
        DebuggerTool? debugger,
        IReadOnlyList<EventRecordItem> contextEvents,
        CancellationToken cancellationToken)
    {
        var info = new FileInfo(dumpPath);
        var integrity = InspectDump(dumpPath);
        var correlated = GetCorrelatedEvents(info.LastWriteTime, contextEvents);
        var nearestBugCheck = contextEvents
            .Where(IsBugCheckEvent)
            .Where(x => x.TimeCreated.HasValue)
            .Where(x => Math.Abs((x.TimeCreated!.Value - info.LastWriteTime).TotalMinutes) <= 60)
            .OrderBy(x => Math.Abs((x.TimeCreated!.Value - info.LastWriteTime).TotalMinutes))
            .FirstOrDefault();

        var rawOutput = "";
        var debuggerUsed = debugger?.DisplayName ?? "WinDbg/KD bulunamadi";
        var analysisStatus = debugger is null
            ? "Sinirli analiz - WinDbg/KD gerekli"
            : "Debugger analizi baslatiliyor";

        if (debugger is not null && integrity.CanAttemptDebugger)
        {
            await _log($"Derin dump analizi: {info.Name} ({debugger.DisplayName}). Ilk sembol indirmesi zaman alabilir.");
            var rawDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ITCHY",
                "WindowsTroubleshooter",
                "DumpAnalysis");
            Directory.CreateDirectory(rawDirectory);
            var rawPath = Path.Combine(rawDirectory, $"{Path.GetFileNameWithoutExtension(info.Name)}-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            var symbolCache = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ITCHY",
                "WindowsTroubleshooter",
                "Symbols");
            Directory.CreateDirectory(symbolCache);

            var symbolPath = $"srv*{symbolCache}*https://msdl.microsoft.com/download/symbols";
            var commands = "!analyze -v; .bugcheck; kv; lm t n; !blackboxbsd; !blackboxntfs; !blackboxpnp; !blackboxwinlogon; q";
            var arguments = $"-z {Quote(dumpPath)} -y {Quote(symbolPath)} -logo {Quote(rawPath)} -c {Quote(commands)}";
            var commandResult = await _runner.RunExecutableAsync(
                debugger.Path,
                arguments,
                $"{info.Name} WinDbg analizi",
                cancellationToken,
                TimeSpan.FromMinutes(5));

            rawOutput = commandResult.Output;
            if (File.Exists(rawPath))
            {
                try
                {
                    var logOutput = await File.ReadAllTextAsync(rawPath, cancellationToken);
                    if (logOutput.Length > rawOutput.Length)
                    {
                        rawOutput = logOutput;
                    }
                }
                catch
                {
                }
            }

            analysisStatus = commandResult.Success || HasAnalysisFields(rawOutput)
                ? HasSymbolProblems(rawOutput) ? "Tamamlandi - bazi semboller eksik" : "Tamamlandi"
                : commandResult.ExitCode == -1 ? "Zaman asimi" : "Debugger dump'i tam cozumleyemedi";
        }

        var parsed = ParseDebuggerOutput(rawOutput, nearestBugCheck?.Message ?? "");
        if (string.IsNullOrWhiteSpace(parsed.BugCheckCode) && !string.IsNullOrWhiteSpace(integrity.BugCheckCode))
        {
            parsed = parsed with
            {
                BugCheckCode = integrity.BugCheckCode,
                Parameters = integrity.BugCheckParameters
            };
        }
        var bugCheck = DescribeBugCheck(parsed.BugCheckCode);
        var component = ResolveSuspectedComponent(parsed, bugCheck);
        var componentDetails = GetComponentDetails(component);
        var isExplicitThirdParty = IsExplicitThirdParty(component, componentDetails);
        var confidence = DetermineConfidence(parsed, bugCheck, component, isExplicitThirdParty, correlated);
        var rootCause = BuildRootCause(parsed, bugCheck, component, confidence, integrity);
        var evidence = BuildEvidence(parsed, integrity, correlated);
        var recommendation = BuildRecommendation(bugCheck, component, componentDetails);

        var rawForReport = string.IsNullOrWhiteSpace(rawOutput)
            ? "Debugger ciktisi yok. WinDbg/KD kurulumu ve yonetici izni gerekebilir."
            : rawOutput.Length > 160_000 ? rawOutput[..160_000] + Environment.NewLine + "[Cikti 160000 karakterde kesildi.]" : rawOutput;

        return new DumpAnalysisItem(
            info.Name,
            info.FullName,
            info.LastWriteTime,
            FormatSize(info.Length),
            integrity.Status,
            analysisStatus,
            parsed.BugCheckCode,
            string.IsNullOrWhiteSpace(parsed.BugCheckName) ? bugCheck.Name : parsed.BugCheckName,
            parsed.Parameters,
            component,
            componentDetails,
            parsed.ProcessName,
            parsed.FailureBucket,
            confidence,
            rootCause,
            evidence,
            correlated.Text,
            recommendation,
            debuggerUsed,
            rawForReport);
    }

    internal static ParsedDebuggerOutput ParseDebuggerOutput(string output, string eventMessage)
    {
        var bugCode = FirstValue(output, "BUGCHECK_CODE");
        var heading = Regex.Match(output, @"(?im)^\s*([A-Z][A-Z0-9_]+)\s+\(([0-9a-fA-F]+)\)\s*$");
        var bugName = heading.Success ? heading.Groups[1].Value.Trim() : "";
        if (string.IsNullOrWhiteSpace(bugCode) && heading.Success)
        {
            bugCode = heading.Groups[2].Value;
        }

        if (string.IsNullOrWhiteSpace(bugCode))
        {
            var commandBugCheck = Regex.Match(output, @"(?im)Bugcheck code\s+([0-9a-fA-F`]+)");
            if (commandBugCheck.Success)
            {
                bugCode = commandBugCheck.Groups[1].Value.Replace("`", "");
            }
        }

        var eventHexValues = Regex.Matches(eventMessage, @"(?i)0x[0-9a-f]{1,16}")
            .Select(x => x.Value)
            .ToList();
        if (string.IsNullOrWhiteSpace(bugCode) && eventHexValues.Count > 0)
        {
            bugCode = eventHexValues[0];
        }

        bugCode = NormalizeBugCheckCode(bugCode);
        var args = new List<string>();
        for (var i = 1; i <= 4; i++)
        {
            var arg = Regex.Match(output, $@"(?im)^\s*Arg{i}:\s*(.+)$");
            if (arg.Success)
            {
                args.Add($"Arg{i}: {arg.Groups[1].Value.Trim()}");
            }
        }

        if (args.Count == 0 && eventHexValues.Count > 1)
        {
            args.AddRange(eventHexValues.Skip(1).Take(4).Select((x, i) => $"Arg{i + 1}: {x}"));
        }

        var probable = Regex.Match(output, @"(?im)^\s*Probably caused by\s*:\s*(.+)$").Groups[1].Value.Trim();
        var image = FirstValue(output, "IMAGE_NAME");
        var module = FirstValue(output, "MODULE_NAME");
        var process = FirstValue(output, "PROCESS_NAME");
        var bucket = FirstValue(output, "FAILURE_BUCKET_ID");
        var symbol = FirstValue(output, "SYMBOL_NAME");
        var stackCandidates = ExtractStackCandidates(output);

        return new ParsedDebuggerOutput(
            bugCode,
            bugName,
            string.Join(Environment.NewLine, args),
            probable,
            image,
            module,
            process,
            bucket,
            symbol,
            stackCandidates);
    }

    private async Task<DebuggerTool?> FindDebuggerAsync(CancellationToken cancellationToken)
    {
        var candidates = new List<string>();
        foreach (var pathDirectory in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(pathDirectory)) continue;
            foreach (var executable in DebuggerExecutables)
            {
                candidates.Add(Path.Combine(pathDirectory.Trim(), executable));
            }
        }

        var kitsRoots = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Kits", "10", "Debuggers", "x64"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Kits", "10", "Debuggers", "x64"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps")
        };
        foreach (var root in kitsRoots)
        {
            foreach (var executable in DebuggerExecutables)
            {
                candidates.Add(Path.Combine(root, executable));
            }
        }

        var direct = RankDebuggerCandidates(candidates).FirstOrDefault(File.Exists);
        if (!string.IsNullOrWhiteSpace(direct))
        {
            return CreateTool(direct);
        }

        var script = """
            $locations = Get-AppxPackage -Name Microsoft.WinDbg -ErrorAction SilentlyContinue |
              Select-Object -ExpandProperty InstallLocation
            foreach ($location in $locations) {
              Get-ChildItem -LiteralPath $location -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -in @('kd.exe','cdb.exe','windbg.exe','WinDbgX.exe','DbgX.Shell.exe') } |
                Select-Object -ExpandProperty FullName
            }
            """;
        var result = await _runner.RunPowerShellAsync(script, cancellationToken, false, "WinDbg araniyor");
        var appxCandidate = RankDebuggerCandidates(result.Output
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim()))
            .FirstOrDefault(File.Exists);
        return string.IsNullOrWhiteSpace(appxCandidate) ? null : CreateTool(appxCandidate);
    }

    private static IReadOnlyList<DumpAnalysisItem> ApplyRecurringEvidence(IReadOnlyList<DumpAnalysisItem> analyses)
    {
        var recurring = analyses
            .Where(x => IsMeaningfulComponent(x.SuspectedComponent))
            .GroupBy(x => x.SuspectedComponent, StringComparer.OrdinalIgnoreCase)
            .Where(x => x.Count() >= 2)
            .ToDictionary(x => x.Key, x => x.Count(), StringComparer.OrdinalIgnoreCase);

        return analyses.Select(item =>
        {
            if (!recurring.TryGetValue(item.SuspectedComponent, out var count))
            {
                return item;
            }

            return item with
            {
                Confidence = "Yuksek",
                RootCauseSummary = $"{count} ayri dump dosyasinda ayni kaynak tekrar ediyor: {item.SuspectedComponent}. {item.RootCauseSummary}",
                Evidence = item.Evidence + Environment.NewLine + $"Tekrar kaniti: {count} dump ayni bileseni isaret ediyor."
            };
        }).ToList();
    }

    private static string BuildOverallSummary(
        IReadOnlyList<DumpAnalysisItem> analyses,
        IReadOnlyList<EventRecordItem> events,
        DebuggerTool? debugger)
    {
        if (analyses.Count == 0)
        {
            var bugCheckEvents = events.Where(IsBugCheckEvent).OrderByDescending(x => x.TimeCreated).ToList();
            var eventAnalysis = bugCheckEvents.Count > 0 ? ParseDebuggerOutput("", bugCheckEvents[0].Message) : null;
            var eventDescription = eventAnalysis is null ? new BugCheckDescription("", "", "") : DescribeBugCheck(eventAnalysis.BugCheckCode);
            var stopCode = eventAnalysis is null || string.IsNullOrWhiteSpace(eventAnalysis.BugCheckCode)
                ? "Stop code olay mesajinda ayristirilamadi."
                : $"Son stop code: {eventAnalysis.BugCheckCode} {eventDescription.Name}.";
            return bugCheckEvents.Count > 0
                ? $"{bugCheckEvents.Count} BugCheck olayi bulundu ancak okunabilir dump dosyasi yok. {stopCode} Asil surucu/stack tespiti icin dump olusturma ayarlarini ve disk bos alanini kontrol edin."
                : "Okunabilir dump veya BugCheck kaydi bulunmadi. Bu durum mavi ekran yasanmadigi anlamina gelmez; dump yazimi kapali, dosya temizlenmis veya klasor erisimi engellenmis olabilir.";
        }

        var recurring = analyses
            .Where(x => IsMeaningfulComponent(x.SuspectedComponent))
            .GroupBy(x => x.SuspectedComponent, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(x => x.Count())
            .FirstOrDefault();
        var latest = analyses.OrderByDescending(x => x.CreatedAt).First();
        var builder = new StringBuilder();
        if (recurring is not null && recurring.Count() >= 2)
        {
            builder.Append($"En guclu ortak kaynak: {recurring.Key}; {recurring.Count()} dump dosyasinda tekrar ediyor. ");
        }
        else
        {
            builder.Append($"En son dump sonucu: {latest.BugCheckCode} {latest.BugCheckName}; supheli kaynak {latest.SuspectedComponent}. ");
        }

        builder.Append($"Guven seviyesi: {latest.Confidence}. ");
        if (debugger is null)
        {
            builder.Append("WinDbg/KD bulunamadigi icin analiz Event Viewer ve dump butunlugu ile sinirli. Mavi Ekran sekmesindeki WinDbg Kur dugmesiyle tam sembol/stack analizini etkinlestirin.");
        }
        else
        {
            builder.Append("WinDbg sembolleri, !analyze, stack, modul ve olay zamani korelasyonu birlikte degerlendirildi. ntoskrnl.exe tek basina asil neden kabul edilmez.");
        }

        return builder.ToString();
    }

    private static IReadOnlyList<BlueScreenRecord> BuildEventSignals(IReadOnlyList<EventRecordItem> events)
    {
        return events
            .Where(x => IsBugCheckEvent(x) || IsBlueScreenContextEvent(x))
            .OrderByDescending(x => x.TimeCreated)
            .Take(80)
            .Select(x => new BlueScreenRecord(
                $"{x.Provider} / Event {x.Id}",
                IsBugCheckEvent(x) ? "BugCheck stop code kaydi." : x.Id == 41 ? "Beklenmedik kapanma kaydi; tek basina neden degildir." : "Dump zamaniyla iliskili olabilecek sistem olayi.",
                $"{x.TimeCreated:dd.MM.yyyy HH:mm:ss} - {x.Message}",
                x.TimeCreated))
            .ToList();
    }

    private static CorrelationResult GetCorrelatedEvents(DateTime dumpTime, IReadOnlyList<EventRecordItem> events)
    {
        var relevant = events
            .Where(x => x.TimeCreated.HasValue)
            .Where(IsBlueScreenContextEvent)
            .Where(x => Math.Abs((x.TimeCreated!.Value - dumpTime).TotalMinutes) <= 20)
            .OrderBy(x => Math.Abs((x.TimeCreated!.Value - dumpTime).TotalMinutes))
            .Take(10)
            .ToList();
        var text = relevant.Count == 0
            ? "Dump zamaninin +/-20 dakikasinda ek WHEA/disk/GPU/BugCheck olayi bulunmadi."
            : string.Join(Environment.NewLine, relevant.Select(x => $"{x.TimeCreated:dd.MM.yyyy HH:mm:ss} - {x.Provider} / Event {x.Id}: {Truncate(x.Message, 240)}"));
        return new CorrelationResult(
            text,
            relevant.Any(x => x.Provider.Contains("WHEA", StringComparison.OrdinalIgnoreCase)),
            relevant.Any(x => IsStorageProvider(x.Provider)),
            relevant.Any(x => IsDisplayProvider(x.Provider)));
    }

    private static string ResolveSuspectedComponent(ParsedDebuggerOutput parsed, BugCheckDescription bugCheck)
    {
        var probableToken = Regex.Match(parsed.ProbablyCausedBy, @"(?i)\b[\w.-]+\.(?:sys|dll|exe)\b");
        var explicitComponent = probableToken.Success ? probableToken.Value : parsed.ImageName;
        if (string.IsNullOrWhiteSpace(explicitComponent) && !string.IsNullOrWhiteSpace(parsed.ModuleName))
        {
            explicitComponent = parsed.ModuleName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)
                ? parsed.ModuleName
                : parsed.ModuleName + ".sys";
        }

        if (!string.IsNullOrWhiteSpace(explicitComponent) && !GenericComponents.Contains(explicitComponent))
        {
            return explicitComponent;
        }

        var stackModule = parsed.StackCandidates.FirstOrDefault(x => !StackFrameworkModules.Contains(x));
        if (!string.IsNullOrWhiteSpace(stackModule))
        {
            return stackModule.Contains('.') ? stackModule : stackModule + ".sys";
        }

        return parsed.BugCheckCode.ToUpperInvariant() switch
        {
            "0X124" or "0X101" or "0X12B" or "0X7F" => "Donanim / CPU / RAM / PCIe",
            "0X116" or "0X117" or "0X119" or "0X10E" => "GPU veya ekran surucusu",
            "0X7B" or "0X154" or "0XF4" => "Disk / NVMe / depolama denetleyicisi",
            "0X1A" or "0X50" or "0X109" or "0X139" or "0XC2" or "0XC5" => "RAM veya bellek bozan surucu",
            "0X9F" or "0X14F" => "Guc yonetimiyle iliskili surucu / BIOS",
            "0XEF" => string.IsNullOrWhiteSpace(parsed.ProcessName) ? "Kritik Windows sureci / disk / surucu" : parsed.ProcessName,
            _ => string.IsNullOrWhiteSpace(bugCheck.Name) ? "Belirlenemedi" : bugCheck.Name + " ile iliskili surucu/donanim"
        };
    }

    private static string DetermineConfidence(
        ParsedDebuggerOutput parsed,
        BugCheckDescription bugCheck,
        string component,
        bool isExplicitThirdParty,
        CorrelationResult correlated)
    {
        if (isExplicitThirdParty && !string.IsNullOrWhiteSpace(parsed.ProbablyCausedBy)) return "Yuksek";
        if (isExplicitThirdParty && !string.IsNullOrWhiteSpace(parsed.ImageName)) return "Orta-Yuksek";
        if (parsed.BugCheckCode.Equals("0x124", StringComparison.OrdinalIgnoreCase) && correlated.HasWhea) return "Yuksek";
        if (component.Contains("GPU", StringComparison.OrdinalIgnoreCase) && correlated.HasDisplay) return "Orta-Yuksek";
        if (component.Contains("Disk", StringComparison.OrdinalIgnoreCase) && correlated.HasStorage) return "Orta-Yuksek";
        if (!string.IsNullOrWhiteSpace(parsed.BugCheckCode) && !string.IsNullOrWhiteSpace(bugCheck.Name)) return "Orta";
        return "Dusuk";
    }

    private static string BuildRootCause(
        ParsedDebuggerOutput parsed,
        BugCheckDescription bugCheck,
        string component,
        string confidence,
        DumpIntegrity integrity)
    {
        if (!integrity.CanAttemptDebugger)
        {
            return $"Dump dosyasi bozuk veya eksik gorunuyor: {integrity.Status}. Asil kaynak stack uzerinden belirlenemedi.";
        }

        if (!GenericComponents.Contains(component) && component.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
        {
            return $"Birincil supheli {component}. {bugCheck.Explanation} Guven: {confidence}.";
        }

        if (!string.IsNullOrWhiteSpace(bugCheck.Explanation))
        {
            return $"En olasi sorun alani: {component}. {bugCheck.Explanation} Guven: {confidence}.";
        }

        return "Dump yeterli ve belirleyici sembol/stack kaniti vermedi. ntoskrnl.exe gorunmesi Windows kernelinin coktugunu gosterir; asil nedeni tek basina gostermez.";
    }

    private static string BuildEvidence(ParsedDebuggerOutput parsed, DumpIntegrity integrity, CorrelationResult correlated)
    {
        var lines = new List<string> { $"Dosya: {integrity.Status}" };
        if (!string.IsNullOrWhiteSpace(parsed.ProbablyCausedBy)) lines.Add($"WinDbg: Probably caused by: {parsed.ProbablyCausedBy}");
        if (!string.IsNullOrWhiteSpace(parsed.ImageName)) lines.Add($"IMAGE_NAME: {parsed.ImageName}");
        if (!string.IsNullOrWhiteSpace(parsed.ModuleName)) lines.Add($"MODULE_NAME: {parsed.ModuleName}");
        if (!string.IsNullOrWhiteSpace(parsed.SymbolName)) lines.Add($"SYMBOL_NAME: {parsed.SymbolName}");
        if (!string.IsNullOrWhiteSpace(parsed.FailureBucket)) lines.Add($"FAILURE_BUCKET_ID: {parsed.FailureBucket}");
        if (!string.IsNullOrWhiteSpace(parsed.ProcessName)) lines.Add($"PROCESS_NAME: {parsed.ProcessName}");
        if (parsed.StackCandidates.Count > 0) lines.Add("Stack modul adaylari: " + string.Join(", ", parsed.StackCandidates));
        if (!string.IsNullOrWhiteSpace(parsed.Parameters)) lines.Add(parsed.Parameters);
        lines.Add("Zaman korelasyonu: " + correlated.Text);
        return string.Join(Environment.NewLine, lines);
    }

    private static string BuildRecommendation(BugCheckDescription bugCheck, string component, string componentDetails)
    {
        var recommendation = string.IsNullOrWhiteSpace(bugCheck.Recommendation)
            ? "Supheli bilesenin surucusunu uretici sitesinden kontrol edin; BIOS, RAM ve disk bulgularini olay korelasyonuyla birlikte degerlendirin."
            : bugCheck.Recommendation;
        if (component.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
        {
            recommendation = $"{component} dosyasinin ait oldugu yazilim/aygit surucusunu uretici sitesinden guncelleyin veya son degisiklikten sonra basladiysa geri alin. {recommendation}";
        }

        if (!string.IsNullOrWhiteSpace(componentDetails))
        {
            recommendation += " Mevcut dosya: " + componentDetails;
        }

        return recommendation;
    }

    private static DumpIntegrity InspectDump(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (info.Length < 4_096)
            {
                return new DumpIntegrity($"Kritik derecede kucuk ({FormatSize(info.Length)}); kesilmis veya bozuk", false, "", "");
            }

            Span<byte> header = stackalloc byte[0x60];
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var read = stream.Read(header);
            if (read < 8)
            {
                return new DumpIntegrity("Dosya basligi eksik", false, "", "");
            }

            var signature = Encoding.ASCII.GetString(header[..4]);
            var marker = Encoding.ASCII.GetString(header[4..8]);
            if (signature == "MDMP")
            {
                return new DumpIntegrity($"Gecerli minidump basligi (MDMP), {FormatSize(info.Length)}", true, "", "");
            }

            if (signature == "PAGE" && (marker == "DUMP" || marker == "DU64"))
            {
                var headerBugCheck = ReadKernelHeaderBugCheck(header[..read], marker == "DU64");
                return new DumpIntegrity(
                    $"Gecerli kernel dump basligi ({signature}{marker}), {FormatSize(info.Length)}",
                    true,
                    headerBugCheck.Code,
                    headerBugCheck.Parameters);
            }

            if (signature == "PAGE")
            {
                return new DumpIntegrity($"Kernel dump benzeri baslik ({signature}{marker}), debugger dogrulamasi gerekli", true, "", "");
            }

            return new DumpIntegrity($"Bilinmeyen dump basligi ({SanitizeHeader(header[..8])}); dosya bozuk olabilir", true, "", "");
        }
        catch (UnauthorizedAccessException)
        {
            return new DumpIntegrity("Dosyaya erisim reddedildi; uygulamayi yonetici olarak calistirin", false, "", "");
        }
        catch (Exception ex)
        {
            return new DumpIntegrity("Dosya okunamadi: " + ex.Message, false, "", "");
        }
    }

    private static HeaderBugCheck ReadKernelHeaderBugCheck(ReadOnlySpan<byte> header, bool is64Bit)
    {
        try
        {
            if (is64Bit && header.Length >= 0x60)
            {
                var code = BinaryPrimitives.ReadUInt32LittleEndian(header[0x38..0x3C]);
                var parameters = new[]
                {
                    BinaryPrimitives.ReadUInt64LittleEndian(header[0x40..0x48]),
                    BinaryPrimitives.ReadUInt64LittleEndian(header[0x48..0x50]),
                    BinaryPrimitives.ReadUInt64LittleEndian(header[0x50..0x58]),
                    BinaryPrimitives.ReadUInt64LittleEndian(header[0x58..0x60])
                };
                return new HeaderBugCheck(
                    NormalizeBugCheckCode(code.ToString("X", CultureInfo.InvariantCulture)),
                    string.Join(Environment.NewLine, parameters.Select((x, i) => $"Arg{i + 1}: 0x{x:X16}")));
            }

            if (!is64Bit && header.Length >= 0x3C)
            {
                var code = BinaryPrimitives.ReadUInt32LittleEndian(header[0x28..0x2C]);
                var parameters = new[]
                {
                    BinaryPrimitives.ReadUInt32LittleEndian(header[0x2C..0x30]),
                    BinaryPrimitives.ReadUInt32LittleEndian(header[0x30..0x34]),
                    BinaryPrimitives.ReadUInt32LittleEndian(header[0x34..0x38]),
                    BinaryPrimitives.ReadUInt32LittleEndian(header[0x38..0x3C])
                };
                return new HeaderBugCheck(
                    NormalizeBugCheckCode(code.ToString("X", CultureInfo.InvariantCulture)),
                    string.Join(Environment.NewLine, parameters.Select((x, i) => $"Arg{i + 1}: 0x{x:X8}")));
            }
        }
        catch
        {
        }

        return new HeaderBugCheck("", "");
    }

    private static BugCheckDescription DescribeBugCheck(string code)
    {
        return BugChecks.TryGetValue(code, out var description)
            ? description
            : new BugCheckDescription("", "", "");
    }

    private static string GetComponentDetails(string component)
    {
        if (string.IsNullOrWhiteSpace(component) || !component.Contains('.')) return "";
        try
        {
            var candidates = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers", component),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), component)
            };
            var path = candidates.FirstOrDefault(File.Exists);
            if (path is null) return "Dosya Windows surucu klasorunde bulunamadi; kaldirilmis veya dump baska sisteme ait olabilir.";
            var version = FileVersionInfo.GetVersionInfo(path);
            return $"{version.FileDescription}; Uretici: {version.CompanyName}; Surum: {version.FileVersion}; Tarih: {File.GetLastWriteTime(path):dd.MM.yyyy}";
        }
        catch
        {
            return "";
        }
    }

    private static bool IsExplicitThirdParty(string component, string details)
    {
        return component.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) &&
               !GenericComponents.Contains(component) &&
               !string.IsNullOrWhiteSpace(details) &&
               !details.StartsWith("Dosya Windows", StringComparison.OrdinalIgnoreCase) &&
               !details.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<string> ExtractStackCandidates(string output)
    {
        if (string.IsNullOrWhiteSpace(output)) return [];

        return Regex.Matches(
                output,
                @"(?im)^\s*[0-9a-f`]{8,}\s+[0-9a-f`]{8,}.*?\b([a-z0-9_.-]+)![^\s]+")
            .Select(x => x.Groups[1].Value.Trim())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .ToList();
    }

    private static bool IsMeaningfulComponent(string component)
    {
        return !string.IsNullOrWhiteSpace(component) &&
               !component.Equals("Belirlenemedi", StringComparison.OrdinalIgnoreCase) &&
               !GenericComponents.Contains(component);
    }

    private static string FirstValue(string output, string key)
    {
        var match = Regex.Match(output, $@"(?im)^\s*{Regex.Escape(key)}\s*:\s*(.+)$");
        return match.Success ? match.Groups[1].Value.Trim() : "";
    }

    private static string NormalizeBugCheckCode(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        var cleaned = value.Trim().Replace("`", "");
        if (cleaned.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) cleaned = cleaned[2..];
        cleaned = cleaned.TrimStart('0');
        if (cleaned.Length == 0) cleaned = "0";
        return ulong.TryParse(cleaned, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code)
            ? $"0x{code:X}"
            : value.Trim();
    }

    private static bool HasAnalysisFields(string output)
    {
        return output.Contains("BUGCHECK_CODE", StringComparison.OrdinalIgnoreCase) ||
               output.Contains("Probably caused by", StringComparison.OrdinalIgnoreCase) ||
               output.Contains("FAILURE_BUCKET_ID", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasSymbolProblems(string output)
    {
        return output.Contains("symbols are wrong", StringComparison.OrdinalIgnoreCase) ||
               output.Contains("symbol file could not be found", StringComparison.OrdinalIgnoreCase) ||
               output.Contains("unable to load image", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsBugCheckEvent(EventRecordItem item)
    {
        return item.Id == 1001 &&
               (item.Provider.Contains("BugCheck", StringComparison.OrdinalIgnoreCase) ||
                item.Provider.Contains("SystemErrorReporting", StringComparison.OrdinalIgnoreCase) ||
                item.Message.Contains("bugcheck", StringComparison.OrdinalIgnoreCase) ||
                item.Message.Contains("hata denetimi", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsBlueScreenContextEvent(EventRecordItem item)
    {
        return IsBugCheckEvent(item) ||
               (item.Id == 41 && item.Provider.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase)) ||
               item.Provider.Contains("WHEA", StringComparison.OrdinalIgnoreCase) ||
               IsStorageProvider(item.Provider) ||
               IsDisplayProvider(item.Provider) ||
               item.Provider.Contains("volmgr", StringComparison.OrdinalIgnoreCase) ||
               item.Provider.Contains("Kernel-PnP", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsStorageProvider(string provider)
    {
        return provider.Contains("disk", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("ntfs", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("stor", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("nvme", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("volmgr", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDisplayProvider(string provider)
    {
        return provider.Contains("display", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("nvlddmkm", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("amdkmd", StringComparison.OrdinalIgnoreCase) ||
               provider.Contains("igfx", StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> RankDebuggerCandidates(IEnumerable<string> candidates)
    {
        return candidates
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => DebuggerRank(Path.GetFileName(x)));
    }

    private static int DebuggerRank(string fileName)
    {
        if (fileName.Equals("kd.exe", StringComparison.OrdinalIgnoreCase)) return 0;
        if (fileName.Equals("cdb.exe", StringComparison.OrdinalIgnoreCase)) return 1;
        if (fileName.Equals("windbg.exe", StringComparison.OrdinalIgnoreCase)) return 2;
        if (fileName.Equals("WinDbgX.exe", StringComparison.OrdinalIgnoreCase)) return 3;
        return 4;
    }

    private static DebuggerTool CreateTool(string path)
    {
        return new DebuggerTool(path, Path.GetFileName(path));
    }

    private static string Quote(string value) => '"' + value.Replace("\"", "\\\"") + '"';

    private static string FormatSize(long length)
    {
        if (length >= 1024L * 1024 * 1024) return $"{length / (1024d * 1024 * 1024):N2} GB";
        if (length >= 1024L * 1024) return $"{length / (1024d * 1024):N1} MB";
        if (length >= 1024) return $"{length / 1024d:N0} KB";
        return $"{length} byte";
    }

    private static DateTime SafeLastWriteTime(string path)
    {
        try { return File.GetLastWriteTime(path); }
        catch { return DateTime.MinValue; }
    }

    private static string SanitizeHeader(ReadOnlySpan<byte> header)
    {
        return string.Concat(header.ToArray().Select(x => x is >= 32 and <= 126 ? (char)x : '.'));
    }

    private static string Truncate(string value, int length)
    {
        if (string.IsNullOrWhiteSpace(value)) return "Mesaj yok";
        return value.Length <= length ? value : value[..length] + "...";
    }

    private static readonly string[] DebuggerExecutables =
        ["kd.exe", "cdb.exe", "windbg.exe", "WinDbgX.exe", "DbgX.Shell.exe"];

    private sealed record DebuggerTool(string Path, string Name)
    {
        public string DisplayName => $"{Name} ({Path})";
    }

    private sealed record DumpIntegrity(string Status, bool CanAttemptDebugger, string BugCheckCode, string BugCheckParameters);

    private sealed record HeaderBugCheck(string Code, string Parameters);

    private sealed record BugCheckDescription(string Name, string Explanation, string Recommendation);

    private sealed record CorrelationResult(string Text, bool HasWhea, bool HasStorage, bool HasDisplay);

    internal sealed record ParsedDebuggerOutput(
        string BugCheckCode,
        string BugCheckName,
        string Parameters,
        string ProbablyCausedBy,
        string ImageName,
        string ModuleName,
        string ProcessName,
        string FailureBucket,
        string SymbolName,
        IReadOnlyList<string> StackCandidates);
}
