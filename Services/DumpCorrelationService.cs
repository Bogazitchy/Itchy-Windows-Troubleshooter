using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class DumpCorrelationService
{
    public CrossDumpAnalysisResult Analyze(
        IReadOnlyList<DumpAnalysisItem> dumps,
        IReadOnlyList<EventRecordItem> events)
    {
        if (dumps.Count == 0) return CrossDumpAnalysisResult.Empty;

        var patterns = BuildPatterns(dumps);
        var scores = ScoreCategories(dumps, events);
        var candidates = scores
            .Where(x => x.Value.Score >= 20)
            .Select(x => BuildCandidate(x.Key, x.Value))
            .OrderByDescending(x => x.EvidenceScore)
            .ThenBy(x => x.Title)
            .ToList();
        var summary = BuildSummary(dumps);
        var commonPattern = BuildCommonPattern(dumps);
        var diagnosis = BuildDiagnosis(dumps, candidates);
        var evidenceSummary = string.Join(Environment.NewLine, patterns.Select(x => $"- {x.Evidence}"));
        var interpretation = string.Join(Environment.NewLine, patterns.Select(x => $"- {x.Interpretation}"));
        var steps = BuildTroubleshootingSteps(candidates, dumps);
        return new CrossDumpAnalysisResult(
            summary,
            commonPattern,
            diagnosis,
            string.IsNullOrWhiteSpace(evidenceSummary) ? "Ortak dogrudan kanit bulunamadi." : evidenceSummary,
            string.IsNullOrWhiteSpace(interpretation) ? "Dump'lar arasinda teknik yorum uretecek ortak desen sinirli." : interpretation,
            candidates,
            patterns,
            steps);
    }

    public IReadOnlyList<RootCauseCandidate> AnalyzeSingle(DumpAnalysisItem dump)
    {
        return Analyze([dump], []).Candidates;
    }

    private static IReadOnlyList<RecurringPattern> BuildPatterns(IReadOnlyList<DumpAnalysisItem> dumps)
    {
        var patterns = new List<RecurringPattern>();
        var exceptionGroups = dumps.Where(x => !string.IsNullOrWhiteSpace(x.ExceptionCode))
            .GroupBy(x => x.ExceptionCode, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(x => x.Count())
            .ToList();
        foreach (var group in exceptionGroups.Where(x => x.Count() >= 2 || dumps.Count == 1))
        {
            var name = group.Select(x => x.ExceptionName).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "Exception";
            patterns.Add(new RecurringPattern(
                "Tekrarlayan exception",
                $"{group.Count()}/{dumps.Count} dump: {group.Key} {name}.",
                group.Key.Equals("0xC0000005", StringComparison.OrdinalIgnoreCase)
                    ? "Kernel modunda gecersiz bellek adresine erisim sinifi tekrar ediyor."
                    : "Ayni exception sinifi birden fazla cokmede goruluyor."));
        }

        var attemptedGroups = dumps.Where(x => !string.IsNullOrWhiteSpace(x.AttemptedAddress))
            .GroupBy(x => x.AttemptedAddress, StringComparer.OrdinalIgnoreCase)
            .Where(x => x.Count() >= 2)
            .OrderByDescending(x => x.Count());
        foreach (var group in attemptedGroups)
        {
            patterns.Add(new RecurringPattern(
                "Tekrarlayan pointer deseni",
                $"{group.Count()} dump ayni erisilmeye calisilan adresi gosteriyor: {group.Key}.",
                "Ayni gecersiz pointer deseni kernel veri yapisi bozulmasi, hatali surucu veya bellek kararsizligi ihtimalini guclendirir."));
        }

        var processes = DistinctMeaningful(dumps.Select(x => x.ProcessName));
        if (processes.Count >= 2)
        {
            patterns.Add(new RecurringPattern(
                "Farkli aktif islemler",
                $"Cokmeler {processes.Count} farkli process sirasinda olustu: {string.Join(", ", processes.Take(6))}.",
                "PROCESS_NAME yalnizca cokme aninda aktif islemdir; farkli uygulamalarda ayni sorun sinifi tek bir kullanici uygulamasini zayif kok neden yapar."));
        }

        var directDrivers = dumps.SelectMany(x => x.ImportantThirdPartyDrivers)
            .Where(x => x.DirectFault)
            .GroupBy(x => x.DriverName, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(x => x.Count());
        foreach (var group in directDrivers)
        {
            patterns.Add(new RecurringPattern(
                "Dogrudan faulting surucu",
                $"{group.Count()} dump'in faulting instruction/module kaniti {group.Key} icinde.",
                $"{group.First().DisplayName} bu dumplar icin guclu yazilimsal suphelidir; diger dumplarla korelasyon yine gereklidir."));
        }

        var stackDrivers = dumps.SelectMany(x => x.ImportantThirdPartyDrivers)
            .GroupBy(x => x.DriverName, StringComparer.OrdinalIgnoreCase)
            .Select(x => new { Driver = x.Key, Dumps = x.Count(), Occurrences = x.Sum(y => y.StackOccurrences), Sample = x.First() })
            .Where(x => x.Occurrences >= 2)
            .OrderByDescending(x => x.Occurrences);
        foreach (var item in stackDrivers.Take(5))
        {
            patterns.Add(new RecurringPattern(
                "Ucuncu parti stack surucusu",
                $"{item.Driver} {item.Dumps} dump'ta, stack uzerinde toplam {item.Occurrences} kez goruluyor.",
                item.Sample.DirectFault || item.Sample.ProbablyCausedBy
                    ? "Surucu dogrudan kanitla destekleniyor."
                    : "Stack varligi tek basina sucluluk kaniti degildir; ikincil supheli ve izolasyon adayi olarak degerlendirilir."));
        }

        return patterns;
    }

    private static Dictionary<RootCauseCategory, CategoryScore> ScoreCategories(
        IReadOnlyList<DumpAnalysisItem> dumps,
        IReadOnlyList<EventRecordItem> events)
    {
        var scores = Enum.GetValues<RootCauseCategory>().ToDictionary(x => x, _ => new CategoryScore());
        var allDrivers = dumps.SelectMany(x => x.ImportantThirdPartyDrivers).ToList();
        var distinctDrivers = allDrivers.Select(x => x.DriverName).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var exceptionAv = dumps.Count(x => x.ExceptionCode.Equals("0xC0000005", StringComparison.OrdinalIgnoreCase));
        var distinctProcesses = DistinctMeaningful(dumps.Select(x => x.ProcessName)).Count;
        var distinctBugChecks = dumps.Select(x => x.BugCheckCode).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).Count();

        foreach (var dump in dumps)
        {
            var graphics = dump.ImportantThirdPartyDrivers.Where(x => x.Category == "Graphics").ToList();
            if (graphics.Any(x => x.DirectFault)) Add(scores, RootCauseCategory.GraphicsDriver, 80, $"{dump.FileName}: faulting module/instruction {graphics.First(x => x.DirectFault).DriverName} icinde.");
            else if (graphics.Any(x => x.ProbablyCausedBy)) Add(scores, RootCauseCategory.GraphicsDriver, 40, $"{dump.FileName}: WinDbg Probably caused by GPU surucusunu gosteriyor.");
            else if (graphics.Any(x => x.IsImageName || x.IsModuleName)) Add(scores, RootCauseCategory.GraphicsDriver, 25, $"{dump.FileName}: IMAGE_NAME/MODULE_NAME GPU surucusu.");
            else if (graphics.Count > 0) Add(scores, RootCauseCategory.GraphicsDriver, 8, $"{dump.FileName}: GPU surucusu stack'te mevcut.");
            if (BugCheckKnowledgeBase.IsVideoBugCheck(dump.BugCheckCode)) Add(scores, RootCauseCategory.GraphicsDriver, 35, $"{dump.FileName}: {dump.BugCheckCode} video bugcheck ailesinde.");

            if (dump.MemoryCorruptionIndicators.Count > 0) Add(scores, RootCauseCategory.MemoryInstability, 3, $"{dump.FileName}: {string.Join(", ", dump.MemoryCorruptionIndicators.Take(2))}.");
            if (dump.InvalidPointerIndicators.Count > 0) Add(scores, RootCauseCategory.MemoryInstability, 7, $"{dump.FileName}: debugger kanitli gecersiz pointer deseni.");
            if (BugCheckKnowledgeBase.IsMemoryBugCheck(dump.BugCheckCode)) Add(scores, RootCauseCategory.MemoryInstability, 20, $"{dump.FileName}: bellek bozulmasi bugcheck ailesi.");
            if (BugCheckKnowledgeBase.IsCpuOrHardwareBugCheck(dump.BugCheckCode))
            {
                Add(scores, RootCauseCategory.CpuInstability, 28, $"{dump.FileName}: CPU/donanim bugcheck ailesi.");
                Add(scores, RootCauseCategory.Hardware, 20, $"{dump.FileName}: donanim sinifi stop code.");
            }
            if (BugCheckKnowledgeBase.IsStorageBugCheck(dump.BugCheckCode)) Add(scores, RootCauseCategory.Storage, 35, $"{dump.FileName}: depolama bugcheck ailesi.");
            if (dump.BugCheckCode.Equals("0x9F", StringComparison.OrdinalIgnoreCase) || dump.BugCheckCode.Equals("0x14F", StringComparison.OrdinalIgnoreCase))
            {
                Add(scores, RootCauseCategory.Power, 35, $"{dump.FileName}: guc durumu/watchdog bugcheck ailesi.");
            }

            foreach (var driver in dump.ImportantThirdPartyDrivers)
            {
                if (driver.Category is "Security/AntiCheat" or "Security") Add(scores, RootCauseCategory.SecurityOrAntiCheatDriver, driver.DirectFault ? 40 : 12, $"{driver.DriverName} kernel guvenlik/anti-cheat surucusu aktif.");
                if (driver.Category is "Network" or "NetworkFilter") Add(scores, RootCauseCategory.NetworkDriver, driver.DirectFault ? 40 : 10, $"{driver.DriverName} ag/filter stack'inde.");
            }
        }

        if (exceptionAv >= 2)
        {
            var ratio = exceptionAv == dumps.Count ? 35 : 25;
            Add(scores, RootCauseCategory.MemoryInstability, ratio, $"{exceptionAv}/{dumps.Count} dump 0xC0000005 Access Violation.");
            Add(scores, RootCauseCategory.KernelDriverConflict, 20, $"{exceptionAv}/{dumps.Count} dump ayni kernel bellek erisim sinifinda.");
        }
        if (distinctBugChecks >= 2 && exceptionAv >= 2) Add(scores, RootCauseCategory.MemoryInstability, 14, "Farkli stop code'larda ayni erisim ihlali tekrar ediyor.");
        if (distinctProcesses >= 2 && exceptionAv >= 2)
        {
            Add(scores, RootCauseCategory.MemoryInstability, 12, "Ayni bellek erisim sinifi farkli process'lerde olustu.");
            Add(scores, RootCauseCategory.KernelDriverConflict, 14, "Farkli kullanici process'lerinde ortak kernel sorun sinifi.");
        }
        if (distinctDrivers.Count >= 2) Add(scores, RootCauseCategory.KernelDriverConflict, 20, $"{distinctDrivers.Count} farkli ucuncu parti kernel surucusu crash stack'lerinde.");
        if (distinctDrivers.Count >= 4) Add(scores, RootCauseCategory.KernelDriverConflict, 15, "Cok sayida dusuk seviyeli ucuncu parti surucu ayni crash doneminde aktif.");
        if (allDrivers.Select(x => x.Category).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= 2) Add(scores, RootCauseCategory.KernelDriverConflict, 12, "Birden fazla kernel surucu ailesi stack'lerde birlikte goruluyor.");

        var correlatedEvents = events.Where(item => item.TimeCreated.HasValue && dumps.Any(dump =>
            dump.CreatedAt.HasValue && Math.Abs((item.TimeCreated.Value - dump.CreatedAt.Value).TotalMinutes) <= 20));
        foreach (var item in correlatedEvents)
        {
            if (item.Provider.Contains("WHEA", StringComparison.OrdinalIgnoreCase))
            {
                Add(scores, RootCauseCategory.Hardware, 25, $"WHEA-Logger Event {item.Id}.");
                Add(scores, RootCauseCategory.CpuInstability, 15, $"WHEA-Logger Event {item.Id}.");
                Add(scores, RootCauseCategory.MemoryInstability, 10, $"WHEA-Logger Event {item.Id}.");
            }
            if (IsDisplay(item.Provider)) Add(scores, RootCauseCategory.GraphicsDriver, 15, $"{item.Provider} Event {item.Id} dump doneminde kayitli.");
            if (IsStorage(item.Provider)) Add(scores, RootCauseCategory.Storage, 18, $"{item.Provider} Event {item.Id} dump doneminde kayitli.");
            // Kernel-Power 41 yalnizca beklenmeyen kapanma kanitidir; skor uretmez.
        }

        var hasDirectMemoryHardwareEvidence = dumps.Any(x =>
            x.BugCheckCode.Equals("0x12B", StringComparison.OrdinalIgnoreCase) ||
            x.MemoryCorruptionIndicators.Any(y => y.Contains("memory_corruption", StringComparison.OrdinalIgnoreCase))) ||
            correlatedEvents.Any(y => y.Provider.Contains("WHEA", StringComparison.OrdinalIgnoreCase));
        foreach (var pair in scores)
        {
            pair.Value.Score = Math.Min(pair.Value.Score, 100);
            if (pair.Key == RootCauseCategory.MemoryInstability && !hasDirectMemoryHardwareEvidence)
            {
                pair.Value.Score = Math.Min(pair.Value.Score, 64);
            }
        }
        return scores;
    }

    private static RootCauseCandidate BuildCandidate(RootCauseCategory category, CategoryScore score)
    {
        var title = category switch
        {
            RootCauseCategory.GraphicsDriver => "Ekran karti surucusu",
            RootCauseCategory.KernelDriverConflict => "Ucuncu parti kernel surucusu cakismasi",
            RootCauseCategory.MemoryInstability => "RAM / XMP / CPU bellek kararliligi",
            RootCauseCategory.CpuInstability => "CPU / BIOS / voltaj kararliligi",
            RootCauseCategory.Storage => "Disk / NVMe / depolama yolu",
            RootCauseCategory.Hardware => "Donanim kararliligi",
            RootCauseCategory.Power => "Guc kararliligi",
            RootCauseCategory.NetworkDriver => "Ag veya paket filtre surucusu",
            RootCauseCategory.SecurityOrAntiCheatDriver => "Guvenlik / anti-cheat kernel surucusu",
            _ => "Belirlenemeyen kernel bileseni"
        };
        var interpretation = category switch
        {
            RootCauseCategory.GraphicsDriver => "Dogrudan GPU surucusu veya video stack kaniti bu kategoriyi destekliyor.",
            RootCauseCategory.KernelDriverConflict => "Dump, belleği daha once hangi surucunun bozdugunu her zaman gostermez; kontrollu surucu izolasyonu gerekir.",
            RootCauseCategory.MemoryInstability => "Desen RAM/XMP/CPU bellek denetleyicisi kararsizligiyla uyumlu; fiziksel ariza ancak testle dogrulanabilir.",
            RootCauseCategory.CpuInstability => "CPU, BIOS, voltaj veya overclock kararliligi test edilmelidir.",
            RootCauseCategory.Storage => "Depolama surucusu, firmware, disk veya dosya sistemi yolu birlikte incelenmelidir.",
            RootCauseCategory.Power => "Beklenmeyen kapanma kaydi degil, guc durumu bugcheck parametreleri bu kategoriyi destekliyor.",
            RootCauseCategory.SecurityOrAntiCheatDriver => "Kernel guvenlik surucusu stack'te aktiftir; dogrudan fault yoksa bu ikincil suphelidir.",
            RootCauseCategory.NetworkDriver => "Ag/filter surucusu dusuk seviyede calisir; dogrulama icin izolasyon gerekir.",
            _ => "Kategori dump ve olay kanitlariyla uyumludur; ek test gerekir."
        };
        return new RootCauseCandidate(
            category,
            title,
            score.Score,
            Strength(score.Score),
            string.Join(" ", score.Evidence.Distinct(StringComparer.OrdinalIgnoreCase).Take(4)),
            interpretation,
            Recommendation(category));
    }

    private static string BuildSummary(IReadOnlyList<DumpAnalysisItem> dumps)
    {
        var lines = new List<string> { $"{dumps.Count} dump dosyasi incelendi." };
        lines.AddRange(dumps.Where(x => !string.IsNullOrWhiteSpace(x.BugCheckCode))
            .GroupBy(x => $"{x.BugCheckCode} {x.BugCheckName}".Trim(), StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(x => x.Count())
            .Select(x => $"{x.Count()} x {x.Key}"));
        lines.AddRange(dumps.Where(x => !string.IsNullOrWhiteSpace(x.ExceptionCode))
            .GroupBy(x => $"{x.ExceptionCode} {x.ExceptionName}".Trim(), StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(x => x.Count())
            .Select(x => $"{x.Count()}/{dumps.Count} dump: {x.Key}."));
        return string.Join(Environment.NewLine, lines);
    }

    private static string BuildCommonPattern(IReadOnlyList<DumpAnalysisItem> dumps)
    {
        var avCount = dumps.Count(x => x.ExceptionCode.Equals("0xC0000005", StringComparison.OrdinalIgnoreCase));
        var processCount = DistinctMeaningful(dumps.Select(x => x.ProcessName)).Count;
        var invalidCount = dumps.Count(x => x.InvalidPointerIndicators.Count > 0);
        var lines = new List<string>();
        if (avCount >= 2) lines.Add($"{avCount}/{dumps.Count} dump ayni 0xC0000005 bellek erisim ihlalini gosteriyor.");
        if (invalidCount > 0) lines.Add($"{invalidCount}/{dumps.Count} dump'ta debugger kanitli gecersiz pointer/adres deseni var.");
        if (processCount >= 2) lines.Add("Cokmeler farkli kullanici islemleri sirasinda olustugu icin tek bir uygulama ortak kok neden olarak zayiftir.");
        if (lines.Count == 0) lines.Add("Dump'larda tek ve baskin bir ortak hata deseni kanitlanamadi; her dump ayri degerlendirilmelidir.");
        else lines.Add("Ortak desen kernel seviyesinde surucu veya bellek/pointer kararliligi problemine isaret ediyor.");
        return string.Join(Environment.NewLine, lines);
    }

    private static string BuildDiagnosis(IReadOnlyList<DumpAnalysisItem> dumps, IReadOnlyList<RootCauseCandidate> candidates)
    {
        if (candidates.Count == 0) return "Mevcut dump verisi belirli bir kok nedeni siralamak icin yetersiz. Eksik sembol veya context guveni dusurur.";
        var primary = candidates[0];
        var secondary = candidates.Skip(1).Take(2).Select(x => $"{x.Title} ({x.Strength})").ToList();
        var directGraphics = dumps.SelectMany(x => x.ImportantThirdPartyDrivers).FirstOrDefault(x => x.DirectFault && x.Category == "Graphics");
        var opening = directGraphics is null
            ? $"En guclu kok neden adayi {primary.Title} ({primary.Strength})."
            : $"En guclu yazilimsal supheli {directGraphics.DisplayName} ({directGraphics.DriverName}); en az bir dump'in faulting instruction/module kaniti dogrudan bu surucudadir.";
        if (secondary.Count > 0) opening += " Ikincil adaylar: " + string.Join(", ", secondary) + ".";
        return opening + " Bunlar kesin olasilik degil, dump ve olay kanitlarinin goreli guc siralamasidir.";
    }

    private static IReadOnlyList<string> BuildTroubleshootingSteps(IReadOnlyList<RootCauseCandidate> candidates, IReadOnlyList<DumpAnalysisItem> dumps)
    {
        var steps = new List<string>();
        var categories = candidates.Select(x => x.Category).ToHashSet();
        if (categories.Contains(RootCauseCategory.GraphicsDriver))
        {
            steps.Add("GPU overclock/undervolt ayarlarini kapatin; DDU ile Guvenli Mod'da mevcut ekran surucusunu temizleyin.");
            steps.Add("Ureticinin temiz ekran surucusunu kurun; ilk testte overlay ve ek bilesenleri minimumda tutun.");
            steps.Add("Sorun surerse onceki kararli ekran surucusunu deneyin ve GPU sicaklik/guc/VRAM kararliligini kontrol edin.");
        }
        if (categories.Contains(RootCauseCategory.MemoryInstability) || categories.Contains(RootCauseCategory.CpuInstability))
        {
            steps.Add("BIOS varsayilanlarini yukleyin; XMP/EXPO, CPU/RAM overclock ve undervolt ayarlarini kapatin.");
        }
        if (categories.Contains(RootCauseCategory.KernelDriverConflict) || categories.Contains(RootCauseCategory.SecurityOrAntiCheatDriver))
        {
            var names = dumps.SelectMany(x => x.ImportantThirdPartyDrivers)
                .Where(x => x.Category is "Security/AntiCheat" or "Security" or "NetworkFilter" or "VirtualAudio" or "Virtualization")
                .Select(x => x.DisplayName).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToList();
            steps.Add(names.Count == 0
                ? "Dusuk seviyeli ucuncu parti kernel suruculerini temiz baslangicla ve tek tek kaldirarak izole edin."
                : $"Sorun devam ederse kernel suruculerini tek tek izole edin: {string.Join(", ", names)}.");
        }
        if (categories.Contains(RootCauseCategory.Storage)) steps.Add("SMART durumunu, NVMe/SATA firmware'ini, NTFS/disk olaylarini ve chipset/depolama surucusunu kontrol edin.");
        if (categories.Contains(RootCauseCategory.Power)) steps.Add("BIOS/chipset guc yonetimi suruculerini, uyku-uyanma aygitlarini ve guc kaynagi kararliligini kontrol edin.");
        if (categories.Contains(RootCauseCategory.MemoryInstability)) steps.Add("MemTest86 ile uzun test yapin; hata veya tekrar surerse RAM modullerini tek tek test edin.");
        steps.Add("Her degisiklikten sonra sistemi ayni is yukunde yeniden test edin ve yeni dump'lari onceki grupla karsilastirin.");
        return steps.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string Recommendation(RootCauseCategory category) => category switch
    {
        RootCauseCategory.GraphicsDriver => "DDU ile temiz surucu kurulumu, OC/undervolt kapatma ve GPU/VRAM testi.",
        RootCauseCategory.KernelDriverConflict => "Ucuncu parti kernel suruculerini kontrollu olarak tek tek izole edin.",
        RootCauseCategory.MemoryInstability => "XMP/EXPO ve OC kapali uzun MemTest86; gerekirse modulleri tek tek test.",
        RootCauseCategory.CpuInstability => "BIOS varsayilanlari, BIOS guncellemesi ve CPU/voltaj/sicaklik testi.",
        RootCauseCategory.Storage => "SMART, firmware, Event Viewer ve depolama surucusu kontrolu.",
        RootCauseCategory.Power => "BIOS, chipset, uyku-uyanma aygitlari ve guc kaynagi kontrolu.",
        RootCauseCategory.SecurityOrAntiCheatDriver => "Anti-cheat/guvenlik surucusunu gecici kaldirarak tekrar test edin.",
        RootCauseCategory.NetworkDriver => "Ag/filter surucusunu guncelleyin veya gecici kaldirarak test edin.",
        _ => "Ilgili donanim ve surucuyu izole ederek dogrulayin."
    };

    private static string Strength(int score) => score switch
    {
        >= 80 => "Cok guclu",
        >= 65 => "Guclu",
        >= 50 => "Orta-Guclu",
        >= 35 => "Orta",
        _ => "Zayif"
    };

    private static void Add(IDictionary<RootCauseCategory, CategoryScore> scores, RootCauseCategory category, int amount, string evidence)
    {
        scores[category].Score += amount;
        scores[category].Evidence.Add(evidence);
    }

    private static List<string> DistinctMeaningful(IEnumerable<string> values) => values
        .Where(x => !string.IsNullOrWhiteSpace(x) && !x.Equals("Bilinmiyor", StringComparison.OrdinalIgnoreCase))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    private static bool IsDisplay(string provider) =>
        provider.Contains("display", StringComparison.OrdinalIgnoreCase) ||
        provider.Contains("nvlddmkm", StringComparison.OrdinalIgnoreCase) ||
        provider.Contains("amdkmd", StringComparison.OrdinalIgnoreCase) ||
        provider.Contains("igfx", StringComparison.OrdinalIgnoreCase);

    private static bool IsStorage(string provider) =>
        provider.Contains("disk", StringComparison.OrdinalIgnoreCase) ||
        provider.Contains("ntfs", StringComparison.OrdinalIgnoreCase) ||
        provider.Contains("stor", StringComparison.OrdinalIgnoreCase) ||
        provider.Contains("nvme", StringComparison.OrdinalIgnoreCase);

    private sealed class CategoryScore
    {
        public int Score { get; set; }
        public List<string> Evidence { get; } = [];
    }
}
