using ItchyWindowsTroubleshooter.Models;
using System.Text;
using System.Text.Json;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class RepairService
{
    private readonly ICommandRunner _runner;
    private readonly Dictionary<string, RepairPlan> _plans;

    public RepairService(ICommandRunner runner)
    {
        _runner = runner;
        _plans = BuildPlans().ToDictionary(x => x.Id);
    }

    public RepairPlan? GetPlan(string id) => _plans.TryGetValue(id, out var plan) ? plan : null;

    public static bool CanCancel(string id) => id is "dism-check" or "dism-scan" or "chkdsk-scan";

    public async Task<string> PreviewTempAsync(CancellationToken token)
    {
        var result = await _runner.RunPowerShellAsync(RepairScripts.TempPreview, token, false, "Geçici dosya önizlemesi");
        if (!result.Success) throw new InvalidOperationException(result.Output);
        var json = result.Output.Trim();
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidOperationException("Önizleme okunamadı.");
        return json;
    }

    public async Task<RepairResult> RunAsync(string id, CancellationToken cancellationToken, string? drive = null, string? tempManifest = null)
    {
        var plan = GetPlan(id) ?? throw new InvalidOperationException("Bilinmeyen onarim.");
        var started = DateTime.Now;
        cancellationToken.ThrowIfCancellationRequested();
        var policy = CanCancel(id) ? CommandCancellationPolicy.StopProcessTree : CommandCancellationPolicy.WaitForCompletion;
        drive ??= System.IO.Path.GetPathRoot(Environment.SystemDirectory)?.TrimEnd('\\') ?? "";
        CommandResult result = id switch
        {
            "sfc" => await _runner.RunCmdAsync("sfc /scannow", cancellationToken, policy),
            "dism-check" => await _runner.RunCmdAsync("DISM /Online /Cleanup-Image /CheckHealth", cancellationToken),
            "dism-scan" => await _runner.RunCmdAsync("DISM /Online /Cleanup-Image /ScanHealth", cancellationToken),
            "dism-restore" => await _runner.RunCmdAsync("DISM /Online /Cleanup-Image /RestoreHealth", cancellationToken, policy),
            "chkdsk-scan" or "chkdsk-repair" or "chkdsk-surface" => await _runner.RunPowerShellAsync(RepairScripts.Disk(drive, id != "chkdsk-scan", id == "chkdsk-surface"), cancellationToken, policy: policy),
            "wu-reset" => await _runner.RunPowerShellAsync(RepairScripts.WindowsUpdateReset, cancellationToken, policy: policy),
            "network-reset" => await _runner.RunPowerShellAsync(RepairScripts.NetworkReset, cancellationToken, policy: policy),
            "dns" => await _runner.RunCmdAsync("ipconfig /flushdns", cancellationToken, policy),
            "store" => await _runner.RunCmdAsync("wsreset.exe", cancellationToken, policy),
            "defender" => await _runner.RunPowerShellAsync(DefenderScript, cancellationToken, policy: policy),
            "temp" when tempManifest is not null => await _runner.RunPowerShellAsync(RepairScripts.CleanTemp(Convert.ToBase64String(Encoding.UTF8.GetBytes(tempManifest))), cancellationToken, policy: policy),
            "temp" => throw new InvalidOperationException("Temizlik için dosya önizlemesi onaylanmalı."),
            "spooler" => await _runner.RunPowerShellAsync(SpoolerScript, cancellationToken, policy: policy),
            _ => throw new InvalidOperationException("Bilinmeyen onarim.")
        };

        var outcome = RepairOutcomeParser.Parse(result);
        return new RepairResult(plan.Title, outcome is RepairOutcome.Succeeded or RepairOutcome.RestartRequired, result.ExitCode, result.Output, started, DateTime.Now) { Outcome = outcome };
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
            new("chkdsk-repair", "CHKDSK /f", "Seçilen NTFS birimini onarır; kilitliyse açılışa zamanlar. Zamanlama WMI dönüş koduyla doğrulanır.", "Dosya sistemini değiştirir.", "Dakikalar veya saatler", "Kilitli birimde gerekir.", "Gerekir."),
            new("chkdsk-surface", "CHKDSK /r", "Seçilen NTFS biriminde bozuk sektörleri tarar ve okunabilir veriyi kurtarmayı dener; /f işlemini içerir.", "Uzun disk işlemi; önce önemli verileri yedekleyin.", "Saatler", "Kilitli birimde gerekir.", "Gerekir."),
            new("wu-reset", "Windows Update Reset", "Update servislerini durdurur, SoftwareDistribution ve catroot2 klasorlerini yeniden adlandirir, servisleri baslatir.", "Guvenli ama update gecici onbellegini sifirlar.", "3-10 dakika", "Bazen gerekir.", "Gerekir."),
            new("network-reset", "Ag Onarimi", "DNS, Winsock ve IP yiginini sifirlar.", "Guvenli ama ag ayarlari yeniden baslatma isteyebilir.", "1-5 dakika", "Gerekebilir.", "Gerekir."),
            new("dns", "DNS Temizle", "DNS onbellegini temizler.", "Guvenli.", "Saniyeler", "Gerekmez.", "Gerekmez."),
            new("store", "Windows Store Cache Reset", "Microsoft Store onbellegini sifirlar.", "Guvenli.", "1-3 dakika", "Gerekmez.", "Gerekmez."),
            new("defender", "Defender Hizli Tarama", "Microsoft Defender hizli taramasi baslatir.", "Guvenli.", "5-30 dakika", "Gerekmez.", "Gerekebilir."),
            new("temp", "Gecici Dosya Temizleme", "Kullanici temp ve Windows temp icindeki silinebilen gecici dosyalari temizler. Registry temizlemez.", "Guvenli sinirli temizlik.", "1-10 dakika", "Gerekmez.", "Windows temp icin gerekebilir."),
            new("spooler", "Yazici Spooler Onarimi", "Yazdirma kuyrugunu temizler ve Print Spooler servisini yeniden baslatir.", "Kuyruktaki bekleyen isleri siler.", "1-3 dakika", "Gerekmez.", "Gerekir.")
        ];
    }

    private const string DefenderScript = """
        $mp = Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"
        if (Test-Path $mp) { & $mp -Scan -ScanType 1; exit $LASTEXITCODE } else { Start-MpScan -ScanType QuickScan -ErrorAction Stop }
        """;

    private const string SpoolerScript = """
        Stop-Service Spooler -Force -ErrorAction Stop
        try {
          Get-ChildItem -LiteralPath "$env:SystemRoot\\System32\\spool\\PRINTERS" -File -ErrorAction Stop | Remove-Item -Force -ErrorAction Stop
        } finally { Start-Service Spooler -ErrorAction Stop }
        (Get-Service Spooler).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        Write-Output "Spooler Running; kuyruk temizleme komutu tamamlandı."
        """;
}
