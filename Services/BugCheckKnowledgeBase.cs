using System.Globalization;

namespace ItchyWindowsTroubleshooter.Services;

public sealed record BugCheckInfo(
    string Code,
    string Name,
    string Explanation,
    string Recommendation,
    IReadOnlyList<string> ParameterMeanings);

public static class BugCheckKnowledgeBase
{
    private static readonly IReadOnlyDictionary<string, BugCheckInfo> Items = BuildItems();

    public static BugCheckInfo Get(string code)
    {
        var normalized = NormalizeCode(code);
        return Items.TryGetValue(normalized, out var item)
            ? item
            : new BugCheckInfo(normalized, "", "", "", []);
    }

    public static string NormalizeCode(string value)
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

    public static string InferExceptionCode(string bugCheckCode, IReadOnlyList<string> arguments)
    {
        return NormalizeCode(bugCheckCode) switch
        {
            "0x1E" or "0x3B" or "0x7E" => NormalizeNtStatus(Argument(arguments, 0)),
            _ => ""
        };
    }

    public static string InferFaultingAddress(string bugCheckCode, IReadOnlyList<string> arguments)
    {
        return NormalizeCode(bugCheckCode) switch
        {
            "0x1E" or "0x3B" or "0x7E" => NormalizeAddress(Argument(arguments, 1)),
            _ => ""
        };
    }

    public static string InferAttemptedAddress(string bugCheckCode, IReadOnlyList<string> arguments)
    {
        return NormalizeCode(bugCheckCode) switch
        {
            "0xA" or "0x50" or "0xD1" => NormalizeAddress(Argument(arguments, 0)),
            _ => ""
        };
    }

    public static string InferAccessType(string bugCheckCode, IReadOnlyList<string> arguments)
    {
        var normalized = NormalizeCode(bugCheckCode);
        var index = normalized is "0xA" or "0xD1" ? 2 : normalized == "0x50" ? 1 : -1;
        if (index < 0 || !TryParseHex(Argument(arguments, index), out var value)) return "";
        return value switch
        {
            0 => "Read",
            1 or 2 => "Write",
            8 or 0x10 => "Execute",
            _ => ""
        };
    }

    public static string TryGetContextRecord(string bugCheckCode, IReadOnlyList<string> arguments, string parsedContext)
    {
        if (IsUsableAddress(parsedContext)) return NormalizeAddress(parsedContext);
        var index = NormalizeCode(bugCheckCode) switch
        {
            "0x3B" => 2,
            "0x7E" => 3,
            _ => -1
        };
        var candidate = index >= 0 ? NormalizeAddress(Argument(arguments, index)) : "";
        return IsUsableAddress(candidate) ? candidate : "";
    }

    public static string DescribeParameters(string bugCheckCode, IReadOnlyList<string> arguments)
    {
        var info = Get(bugCheckCode);
        if (arguments.Count == 0) return "";
        return string.Join(Environment.NewLine, arguments.Take(4).Select((value, index) =>
        {
            var meaning = index < info.ParameterMeanings.Count ? info.ParameterMeanings[index] : "BugCheck parametresi";
            return $"P{index + 1}: {NormalizeAddress(value)} - {meaning}";
        }));
    }

    public static bool IsVideoBugCheck(string code) => NormalizeCode(code) is "0x10E" or "0x116" or "0x117" or "0x119";
    public static bool IsMemoryBugCheck(string code) => NormalizeCode(code) is "0x1A" or "0x50" or "0x109" or "0x12B" or "0x139";
    public static bool IsCpuOrHardwareBugCheck(string code) => NormalizeCode(code) is "0x7F" or "0x101" or "0x124";
    public static bool IsStorageBugCheck(string code) => NormalizeCode(code) is "0x7B" or "0x154" or "0xF4";

    private static string Argument(IReadOnlyList<string> arguments, int index) => index >= 0 && index < arguments.Count ? arguments[index] : "";

    private static string NormalizeNtStatus(string value)
    {
        if (!TryParseHex(value, out var parsed)) return "";
        return $"0x{unchecked((uint)parsed):X8}";
    }

    public static string NormalizeAddress(string value)
    {
        if (!TryParseHex(value, out var parsed)) return value.Trim();
        return parsed <= uint.MaxValue ? $"0x{parsed:X8}" : $"0x{parsed:X16}";
    }

    public static bool TryParseHex(string value, out ulong parsed)
    {
        var token = value?.Trim().Replace("`", "") ?? "";
        var separator = token.IndexOfAny([' ', ',', '-', ')']);
        if (separator >= 0) token = token[..separator];
        if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) token = token[2..];
        return ulong.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsed);
    }

    private static bool IsUsableAddress(string value) => TryParseHex(value, out var parsed) && parsed > 0x1000;

    private static IReadOnlyDictionary<string, BugCheckInfo> BuildItems()
    {
        var items = new[]
        {
            I("0xA", "IRQL_NOT_LESS_OR_EQUAL", "Yuksek IRQL seviyesinde gecersiz bellek erisimi. Surucu veya bellek kararliligi arastirilmalidir.", "Stack suruculerini, RAM'i ve OC/XMP ayarlarini kontrol edin.", "Erisilen adres", "IRQL", "Erisim tipi", "Komut adresi"),
            I("0x1E", "KMODE_EXCEPTION_NOT_HANDLED", "Kernel modunda yakalanmayan bir istisna olustu. Exception code ve faulting instruction asil kanittir.", "Faulting surucuyu temiz kurun; tekrarlayan erisim ihlalinde bellek kararliligini da test edin.", "Exception code", "Exception adresi", "Exception parametresi 0", "Exception parametresi 1"),
            I("0x1A", "MEMORY_MANAGEMENT", "Bellek yonetimi tutarsizlik tespit etti. RAM, paging veya bellek bozan surucu olabilir.", "XMP/EXPO'yu kapatin ve uzun MemTest86 testi uygulayin.", "Alt tur", "Alt ture ozel", "Alt ture ozel", "Alt ture ozel"),
            I("0x3B", "SYSTEM_SERVICE_EXCEPTION", "Kernel sistem servisi bir istisna uretti. Ucuncu parti surucu veya bellek bozulmasi yaygin nedendir.", "Context ve stack'teki surucuyu inceleyin; RAM kararliligini test edin.", "Exception code", "Exception adresi", "Context record", "Ayrilmis"),
            I("0x50", "PAGE_FAULT_IN_NONPAGED_AREA", "Kernel, gecerli olmasi gereken bir bellek adresine erisemedi.", "Surucu, RAM ve paging/depolama bulgularini birlikte kontrol edin.", "Erisilen adres", "Erisim tipi", "Alt ture ozel", "Komut adresi"),
            I("0x7B", "INACCESSIBLE_BOOT_DEVICE", "Windows acilis aygitina erisemedi.", "BIOS depolama modunu, NVMe/SATA sagligini ve chipset surucusunu kontrol edin.", "Aygit nesnesi", "Durum", "Ayrilmis", "Ayrilmis"),
            I("0x7E", "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "Bir sistem is parcaciginda yakalanmayan istisna olustu.", "Exception context'i ve ucuncu parti stack suruculerini inceleyin.", "Exception code", "Exception adresi", "Exception record", "Context record"),
            I("0x7F", "UNEXPECTED_KERNEL_MODE_TRAP", "CPU trap hatasi; CPU, RAM, BIOS, OC veya dusuk seviyeli surucu ihtimali vardir.", "BIOS varsayilanlariyla RAM/CPU testi ve sicaklik kontrolu yapin.", "Trap numarasi", "Alt ture ozel", "Alt ture ozel", "Alt ture ozel"),
            I("0x9F", "DRIVER_POWER_STATE_FAILURE", "Bir surucu guc durumu istegini zamaninda tamamlamadi.", "Uyku/uyanma ile ilgili aygit, BIOS ve chipset suruculerini guncelleyin.", "Guc gecisi", "Alt ture ozel", "Aygit nesnesi", "IRP"),
            I("0xC2", "BAD_POOL_CALLER", "Bir surucu kernel bellek havuzunu hatali kullandi.", "Stack veya Verifier tarafindan isaretlenen surucuyu izole edin.", "Ihlal turu", "Alt ture ozel", "Alt ture ozel", "Alt ture ozel"),
            I("0xC4", "DRIVER_VERIFIER_DETECTED_VIOLATION", "Driver Verifier bir surucu ihlali yakaladi.", "Isaretlenen surucuyu guncelleyin veya kaldirin; test bitince Verifier'i kapatin.", "Ihlal kodu", "Alt ture ozel", "Alt ture ozel", "Alt ture ozel"),
            I("0xC5", "DRIVER_CORRUPTED_EXPOOL", "Bir surucu kernel bellek havuzunu bozdu.", "Faulting stack ve IMAGE_NAME surucusunu onceleyin; RAM'i de test edin.", "Erisilen adres", "IRQL", "Erisim tipi", "Komut adresi"),
            I("0xD1", "DRIVER_IRQL_NOT_LESS_OR_EQUAL", "Bir kernel surucusu yanlis IRQL seviyesinde gecersiz bellege eristi.", "Isaretlenen surucuyu temiz kurun veya onceki kararli surume donun.", "Erisilen adres", "IRQL", "Erisim tipi", "Komut adresi"),
            I("0xEF", "CRITICAL_PROCESS_DIED", "Windows icin kritik bir surec beklenmedik sekilde sonlandi.", "Disk/NTFS, sistem dosyalari ve sureci etkileyen kernel suruculerini inceleyin.", "Surec nesnesi", "0=surec, 1=is parcacigi", "Alt ture ozel", "Alt ture ozel"),
            I("0x101", "CLOCK_WATCHDOG_TIMEOUT", "Bir CPU cekirdegi beklenen clock kesmesini vermedi.", "BIOS varsayilanlari, CPU sicakligi, voltaj ve guc kaynagini kontrol edin.", "Kesme araligi", "Ayrilmis", "PRCB", "Islemci indeksi"),
            I("0x109", "CRITICAL_STRUCTURE_CORRUPTION", "Kritik kernel kodu veya verisi bozuldu.", "RAM testi yapin ve dusuk seviyeli suruculeri izole edin.", "Ayrilmis", "Ayrilmis", "Ariza turu", "Bozulma turu"),
            I("0x10E", "VIDEO_MEMORY_MANAGEMENT_INTERNAL", "Video bellek yonetiminde kritik hata olustu.", "GPU surucusunu temiz kurun; VRAM, sicaklik ve gucu kontrol edin.", "Alt tur", "Alt ture ozel", "Alt ture ozel", "Alt ture ozel"),
            I("0x116", "VIDEO_TDR_FAILURE", "GPU zaman asimindan sonra ekran surucusu kurtarilamadi.", "GPU surucusunu temiz kurun; sicaklik, guc ve kararliligi test edin.", "Adapter", "Surucu modulu", "Hata kodu", "Dahili veri"),
            I("0x117", "VIDEO_TDR_TIMEOUT_DETECTED", "GPU veya ekran surucusu zaman asimina ugradi.", "Ekran surucusu, GPU sicakligi ve guc kaynagini kontrol edin.", "Adapter", "Surucu modulu", "Dahili veri", "Dahili veri"),
            I("0x119", "VIDEO_SCHEDULER_INTERNAL_ERROR", "GPU zamanlayicisi kritik bir ihlal algiladi.", "Ekran surucusunu temiz kurun ve GPU/VRAM kararliligini test edin.", "Alt tur", "Alt ture ozel", "Alt ture ozel", "Alt ture ozel"),
            I("0x124", "WHEA_UNCORRECTABLE_ERROR", "WHEA duzeltilemeyen donanim hatasi bildirdi.", "WHEA kaydini, BIOS'u, XMP/OC ayarlarini ve donanim testlerini inceleyin.", "Hata kaynagi", "WHEA error record", "MCi_STATUS yuksek", "MCi_STATUS dusuk"),
            I("0x12B", "FAULTY_HARDWARE_CORRUPTED_PAGE", "Windows donanim kaynakli bozulmus bellek sayfasi tespit etti.", "RAM modullerini tek tek, XMP kapali olarak test edin.", "Sanal adres", "Fiziksel adres", "Alt tur", "Alt ture ozel"),
            I("0x133", "DPC_WATCHDOG_VIOLATION", "Bir DPC/ISR rutini izin verilenden uzun surdu.", "Stack'teki surucu ile NVMe/SATA ve chipset suruculerini kontrol edin.", "Ihlal turu", "Timeout", "Triyaj blogu", "Ayrilmis"),
            I("0x139", "KERNEL_SECURITY_CHECK_FAILURE", "Kernel veri yapisi bozuldu.", "Ucuncu parti stack suruculerini ve RAM'i kontrol edin.", "Ihlal turu", "Trap frame", "Exception record", "Ayrilmis"),
            I("0x154", "UNEXPECTED_STORE_EXCEPTION", "Kernel depolama bileseni beklenmeyen istisna bildirdi.", "SMART, NTFS/disk olaylari, NVMe firmware ve RAM'i kontrol edin.", "Store context", "Exception bilgisi", "Alt ture ozel", "Alt ture ozel")
        };
        return items.ToDictionary(x => x.Code, StringComparer.OrdinalIgnoreCase);
    }

    private static BugCheckInfo I(string code, string name, string explanation, string recommendation, params string[] meanings) =>
        new(code, name, explanation, recommendation, meanings);
}
