using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class DriverClassificationService
{
    private static readonly HashSet<string> FrameworkModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "nt", "ntoskrnl", "ntkrnlmp", "ntkrnlpa", "ntkrpamp", "hal", "kd", "Wdf01000",
        "fltmgr", "storport", "stornvme", "storahci", "ndis", "tcpip", "CLASSPNP", "disk",
        "partmgr", "volmgr", "NTFS", "Fs_Rec", "CI", "dxgkrnl", "watchdog", "win32kfull",
        "win32kbase", "memory_corruption", "hardware"
    };

    private static readonly DriverRule[] Rules =
    {
        new(@"^nvlddmkm$", "NVIDIA Display Driver", "Graphics", RootCauseCategory.GraphicsDriver),
        new(@"^amdkmdag$|^atikmdag$", "AMD Display Driver", "Graphics", RootCauseCategory.GraphicsDriver),
        new(@"^igdkmd(?:32|64)$|^igfx", "Intel Graphics Driver", "Graphics", RootCauseCategory.GraphicsDriver),
        new(@"^vgk$", "Riot Vanguard", "Security/AntiCheat", RootCauseCategory.SecurityOrAntiCheatDriver),
        new(@"^BEDaisy$", "BattlEye", "Security/AntiCheat", RootCauseCategory.SecurityOrAntiCheatDriver),
        new(@"^EasyAntiCheat", "Easy Anti-Cheat", "Security/AntiCheat", RootCauseCategory.SecurityOrAntiCheatDriver),
        new(@"^eaanticheat", "EA AntiCheat", "Security/AntiCheat", RootCauseCategory.SecurityOrAntiCheatDriver),
        new(@"^RTKVHD64$", "Realtek Audio", "Audio", RootCauseCategory.KernelDriverConflict),
        new(@"^Netwtw", "Intel Wi-Fi", "Network", RootCauseCategory.NetworkDriver),
        new(@"^rt640x64$", "Realtek Ethernet", "Network", RootCauseCategory.NetworkDriver),
        new(@"^WinDivert", "WinDivert Network Filter", "NetworkFilter", RootCauseCategory.NetworkDriver),
        new(@"SteelSeries.*Sonar|^SS.*VAD", "SteelSeries Sonar Virtual Audio", "VirtualAudio", RootCauseCategory.KernelDriverConflict),
        new(@"^asw|^avp|^klif|^WdFilter$", "Security Filter Driver", "Security", RootCauseCategory.SecurityOrAntiCheatDriver),
        new(@"^VBox|^vmnet|^vmusb|^hv", "Virtualization Driver", "Virtualization", RootCauseCategory.KernelDriverConflict)
    };

    public IReadOnlyList<StackDriverEvidence> BuildEvidence(ParsedDebuggerOutput parsed)
    {
        var modules = new HashSet<string>(parsed.StackModuleOccurrences.Keys, StringComparer.OrdinalIgnoreCase);
        AddModule(modules, parsed.FaultingModule);
        AddModule(modules, parsed.ImageName);
        AddModule(modules, parsed.ModuleName);
        AddModule(modules, ExtractProbablyCausedBy(parsed.ProbablyCausedBy));

        return modules
            .Select(module => Build(module, parsed))
            .Where(x => x.IsThirdParty)
            .OrderByDescending(x => x.DirectFault)
            .ThenByDescending(x => x.ProbablyCausedBy)
            .ThenByDescending(x => x.StackOccurrences)
            .ThenBy(x => x.DriverName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public bool IsFramework(string module) => FrameworkModules.Contains(Identity(module));

    public bool IsGraphics(string module) => MatchRule(module)?.RootCategory == RootCauseCategory.GraphicsDriver;

    public string GetDisplayName(string module) => MatchRule(module)?.DisplayName ?? NormalizeDriverName(module);

    public string GetMetadata(string module)
    {
        var name = NormalizeDriverName(module);
        if (string.IsNullOrWhiteSpace(name)) return "";
        try
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var candidates = new[]
            {
                Path.Combine(windows, "System32", "drivers", name),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name)
            };
            var path = candidates.FirstOrDefault(File.Exists);
            if (path is null) return "Dosya bu bilgisayarin Windows surucu klasorunde bulunamadi; dump baska sisteme ait olabilir.";
            var version = FileVersionInfo.GetVersionInfo(path);
            return string.Join("; ", new[]
            {
                version.FileDescription,
                string.IsNullOrWhiteSpace(version.CompanyName) ? "" : $"Uretici: {version.CompanyName}",
                string.IsNullOrWhiteSpace(version.ProductName) ? "" : $"Urun: {version.ProductName}",
                string.IsNullOrWhiteSpace(version.FileVersion) ? "" : $"Surum: {version.FileVersion}",
                $"Tarih: {File.GetLastWriteTime(path):dd.MM.yyyy}"
            }.Where(x => !string.IsNullOrWhiteSpace(x)));
        }
        catch
        {
            return "";
        }
    }

    private StackDriverEvidence Build(string module, ParsedDebuggerOutput parsed)
    {
        var normalized = NormalizeDriverName(module);
        var identity = Identity(normalized);
        var rule = MatchRule(identity);
        var metadata = GetMetadata(normalized);
        var isMicrosoft = metadata.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase) || IsFramework(identity);
        var probable = SameModule(normalized, ExtractProbablyCausedBy(parsed.ProbablyCausedBy));
        var direct = SameModule(normalized, parsed.FaultingModule);
        var image = SameModule(normalized, parsed.ImageName);
        var namedModule = SameModule(normalized, parsed.ModuleName);
        var occurrences = parsed.StackModuleOccurrences
            .Where(x => SameModule(x.Key, normalized))
            .Sum(x => x.Value);
        var thirdParty = !isMicrosoft && (rule is not null || normalized.EndsWith(".sys", StringComparison.OrdinalIgnoreCase));
        return new StackDriverEvidence(
            normalized,
            rule?.DisplayName ?? normalized,
            rule?.Category ?? "ThirdPartyKernelDriver",
            occurrences,
            direct,
            probable,
            image,
            namedModule,
            thirdParty,
            metadata);
    }

    private static void AddModule(ISet<string> target, string value)
    {
        if (!string.IsNullOrWhiteSpace(value)) target.Add(value);
    }

    private static DriverRule? MatchRule(string module)
    {
        var identity = Identity(module);
        return Rules.FirstOrDefault(x => Regex.IsMatch(identity, x.Pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
    }

    private static string ExtractProbablyCausedBy(string value)
    {
        var match = Regex.Match(value ?? "", @"(?i)\b[\w.-]+\.(?:sys|dll|exe)\b");
        return match.Success ? match.Value : "";
    }

    private static string NormalizeDriverName(string value)
    {
        var token = Regex.Match(value ?? "", @"(?i)\b[a-z0-9_.-]+(?:\.sys|\.dll|\.exe)?\b").Value;
        if (string.IsNullOrWhiteSpace(token)) return "";
        var identity = Identity(token);
        return token.Contains('.') ? token : identity + ".sys";
    }

    private static string Identity(string value)
    {
        var name = Path.GetFileName(value ?? "").Trim();
        foreach (var extension in new[] { ".sys", ".dll", ".exe" })
        {
            if (name.EndsWith(extension, StringComparison.OrdinalIgnoreCase)) return name[..^extension.Length];
        }
        return name;
    }

    private static bool SameModule(string left, string right) =>
        !string.IsNullOrWhiteSpace(left) && !string.IsNullOrWhiteSpace(right) &&
        Identity(left).Equals(Identity(right), StringComparison.OrdinalIgnoreCase);

    private sealed record DriverRule(string Pattern, string DisplayName, string Category, RootCauseCategory RootCategory);
}
