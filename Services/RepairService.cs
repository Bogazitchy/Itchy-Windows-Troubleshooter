using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class RepairService
{
    private readonly CommandRunner _runner;
    private readonly Dictionary<string, RepairPlan> _plans;

    public RepairService(CommandRunner runner)
    {
        _runner = runner;
        _plans = BuildPlans().ToDictionary(x => x.Id);
    }

    public RepairPlan? GetPlan(string id) => _plans.TryGetValue(id, out var plan) ? plan : null;

    public async Task<RepairResult> RunAsync(string id, CancellationToken cancellationToken)
    {
        var plan = GetPlan(id) ?? throw new InvalidOperationException("Bilinmeyen onarim.");
        var started = DateTime.Now;
        CommandResult result = id switch
        {
            "sfc" => await _runner.RunCmdAsync("sfc /scannow", cancellationToken),
            "dism-check" => await _runner.RunCmdAsync("DISM /Online /Cleanup-Image /CheckHealth", cancellationToken),
            "dism-scan" => await _runner.RunCmdAsync("DISM /Online /Cleanup-Image /ScanHealth", cancellationToken),
            "dism-restore" => await _runner.RunCmdAsync("DISM /Online /Cleanup-Image /RestoreHealth", cancellationToken),
            "chkdsk-scan" => await _runner.RunCmdAsync("chkdsk C: /scan", cancellationToken),
            "chkdsk-repair" => await _runner.RunCmdAsync("echo Y|chkdsk C: /f /r", cancellationToken),
            "wu-reset" => await _runner.RunPowerShellAsync(WindowsUpdateResetScript, cancellationToken),
            "network-reset" => await _runner.RunCmdAsync("ipconfig /flushdns && netsh winsock reset && netsh int ip reset", cancellationToken),
            "dns" => await _runner.RunCmdAsync("ipconfig /flushdns", cancellationToken),
            "store" => await _runner.RunCmdAsync("wsreset.exe", cancellationToken),
            "defender" => await _runner.RunPowerShellAsync(DefenderScript, cancellationToken),
            "temp" => await _runner.RunPowerShellAsync(TempCleanScript, cancellationToken),
            "spooler" => await _runner.RunPowerShellAsync(SpoolerScript, cancellationToken),
            _ => throw new InvalidOperationException("Bilinmeyen onarim.")
        };

        return new RepairResult(plan.Title, result.Success, result.ExitCode, result.Output, started, DateTime.Now);
    }

    private static IReadOnlyList<RepairPlan> BuildPlans()
    {
        return
        [
            new("sfc", "SFC Taramasi", "Windows sistem dosyalarini kontrol eder ve bozuk dosyalari onarmaya calisir.", "Guvenli sistem araci.", "10-45 dakika", "Genelde gerekmez.", "Gerekir."),
            new("dism-check", "DISM CheckHealth", "Windows imajinda bozulma isareti olup olmadigini hizlica kontrol eder.", "Guvenli okuma agirlikli kontrol.", "1-5 dakika", "Gerekmez.", "Gerekir."),
            new("dism-scan", "DISM ScanHealth", "Windows imajini daha detayli tarar.", "Guvenli kontrol.", "5-30 dakika", "Gerekmez.", "Gerekir."),
            new("dism-restore", "DISM RestoreHealth", "Windows imajindaki bozulmalari onarmaya calisir. Internet gerekebilir.", "Guvenli ama sistem bilesenlerini onarir.", "10-60 dakika", "Bazen gerekir.", "Gerekir."),
            new("chkdsk-scan", "CHKDSK Kontrolu", "Sistem diskinde dosya sistemi hatalarini kontrol eder.", "Guvenli tarama.", "5-30 dakika", "Gerekmez.", "Gerekir."),
            new("chkdsk-repair", "CHKDSK Onarim Zamanla", "C: surucusu icin /f /r onarimini sonraki acilisa zamanlar.", "Disk uzerinde uzun onarim yapabilir.", "Saatler surebilir.", "Gerekir.", "Gerekir."),
            new("wu-reset", "Windows Update Reset", "Update servislerini durdurur, SoftwareDistribution ve catroot2 klasorlerini yeniden adlandirir, servisleri baslatir.", "Guvenli ama update gecici onbellegini sifirlar.", "3-10 dakika", "Bazen gerekir.", "Gerekir."),
            new("network-reset", "Ag Onarimi", "DNS, Winsock ve IP yiginini sifirlar.", "Guvenli ama ag ayarlari yeniden baslatma isteyebilir.", "1-5 dakika", "Gerekebilir.", "Gerekir."),
            new("dns", "DNS Temizle", "DNS onbellegini temizler.", "Guvenli.", "Saniyeler", "Gerekmez.", "Gerekmez."),
            new("store", "Windows Store Cache Reset", "Microsoft Store onbellegini sifirlar.", "Guvenli.", "1-3 dakika", "Gerekmez.", "Gerekmez."),
            new("defender", "Defender Hizli Tarama", "Microsoft Defender hizli taramasi baslatir.", "Guvenli.", "5-30 dakika", "Gerekmez.", "Gerekebilir."),
            new("temp", "Gecici Dosya Temizleme", "Kullanici temp ve Windows temp icindeki silinebilen gecici dosyalari temizler. Registry temizlemez.", "Guvenli sinirli temizlik.", "1-10 dakika", "Gerekmez.", "Windows temp icin gerekebilir."),
            new("spooler", "Yazici Spooler Onarimi", "Yazdirma kuyrugunu temizler ve Print Spooler servisini yeniden baslatir.", "Kuyruktaki bekleyen isleri siler.", "1-3 dakika", "Gerekmez.", "Gerekir.")
        ];
    }

    private const string WindowsUpdateResetScript = """
        Stop-Service wuauserv,bits,cryptsvc -Force -ErrorAction SilentlyContinue
        $stamp = Get-Date -Format yyyyMMddHHmmss
        if (Test-Path "$env:SystemRoot\SoftwareDistribution") { Rename-Item "$env:SystemRoot\SoftwareDistribution" "SoftwareDistribution.itchy-$stamp" -ErrorAction SilentlyContinue }
        if (Test-Path "$env:SystemRoot\System32\catroot2") { Rename-Item "$env:SystemRoot\System32\catroot2" "catroot2.itchy-$stamp" -ErrorAction SilentlyContinue }
        Start-Service cryptsvc,bits,wuauserv -ErrorAction SilentlyContinue
        Write-Output "Windows Update onbellegi yeniden olusturulacak sekilde sifirlandi."
        """;

    private const string DefenderScript = """
        $mp = Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"
        if (Test-Path $mp) { & $mp -Scan -ScanType 1 } else { Start-MpScan -ScanType QuickScan }
        """;

    private const string TempCleanScript = """
        $paths = @($env:TEMP, "$env:SystemRoot\Temp")
        foreach ($path in $paths) {
            if (Test-Path $path) {
                Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Write-Output "Temizlendi: $path"
            }
        }
        """;

    private const string SpoolerScript = """
        Stop-Service Spooler -Force
        Remove-Item "$env:SystemRoot\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue
        Start-Service Spooler
        Write-Output "Yazdirma kuyrugu temizlendi ve Spooler baslatildi."
        """;
}
