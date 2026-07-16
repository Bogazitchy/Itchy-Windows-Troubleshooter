using System.Text.Json;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class SystemHealthAnalysisService
{
    private readonly CommandRunner _runner;
    private readonly Func<string, Task> _log;

    public SystemHealthAnalysisService(CommandRunner runner, Func<string, Task> log)
    {
        _runner = runner;
        _log = log;
    }

    public async Task<SystemHealthScanResult> ScanAsync(CancellationToken cancellationToken)
    {
        await _log("Sistem sagligi: disk/SMART, dump ayari, pagefile, bellek testi ve Windows bilesen deposu kontrol ediliyor.");
        var healthTask = _runner.RunPowerShellAsync(
            BuildHealthScript(),
            cancellationToken,
            false,
            "Sistem saglik denetimleri calistiriliyor");
        var dismTask = _runner.RunExecutableAsync(
            "dism.exe",
            "/Online /Cleanup-Image /CheckHealth /English",
            "DISM CheckHealth",
            cancellationToken,
            TimeSpan.FromMinutes(2));

        await Task.WhenAll(healthTask, dismTask);
        var checks = ParseChecks((await healthTask).Output).ToList();
        var coverage = new List<ScanCoverageItem>();
        var healthResult = await healthTask;
        coverage.Add(new ScanCoverageItem(
            "Yerel sistem sagligi",
            healthResult.Success && checks.Count > 0 ? "Tamamlandi" : "Kismi",
            checks.Count,
            healthResult.Success ? "Disk, dump, pagefile, bellek ve yeniden baslatma durumu sorgulandi." : "Bazi yerel saglik verileri okunamadi."));

        var dism = await dismTask;
        checks.Add(BuildDismCheck(dism));
        coverage.Add(new ScanCoverageItem(
            "Windows bilesen deposu",
            dism.Success ? "Tamamlandi" : "Erisilemedi",
            dism.Success ? 1 : 0,
            dism.Success ? "DISM /CheckHealth salt okunur denetimi tamamlandi." : "DISM denetimi tamamlanamadi; yonetici izni gerekebilir."));

        return new SystemHealthScanResult(checks, coverage);
    }

    private static string BuildHealthScript()
    {
        return """
            $checks = [System.Collections.Generic.List[object]]::new()
            function Add-Check($category, $component, $status, $value, $detail) {
              $checks.Add([pscustomobject]@{
                ObservedAt=(Get-Date).ToString('o'); Category=[string]$category; Component=[string]$component
                Status=[string]$status; Value=[string]$value; Detail=[string]$detail
              }) | Out-Null
            }

            try {
              $crash = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction Stop
              $dumpNames = @{ 0='Kapali'; 1='Tam bellek dokumu'; 2='Kernel bellek dokumu'; 3='Kucuk bellek dokumu'; 7='Otomatik bellek dokumu' }
              $dumpType = if ($dumpNames.ContainsKey([int]$crash.CrashDumpEnabled)) { $dumpNames[[int]$crash.CrashDumpEnabled] } else { "Bilinmeyen ($($crash.CrashDumpEnabled))" }
              $dumpStatus = if ([int]$crash.CrashDumpEnabled -eq 0) { 'Uyari' } else { 'Normal' }
              Add-Check 'Cokme Kaydi' 'Windows dump yapilandirmasi' $dumpStatus $dumpType "MinidumpDir: $($crash.MinidumpDir); LogEvent: $($crash.LogEvent); AlwaysKeepMemoryDump: $($crash.AlwaysKeepMemoryDump)"
            } catch {
              Add-Check 'Cokme Kaydi' 'Windows dump yapilandirmasi' 'Okunamadi' 'Erisilemedi' $_.Exception.Message
            }

            try {
              $pageFiles = @(Get-CimInstance Win32_PageFileUsage -ErrorAction Stop)
              if ($pageFiles.Count -eq 0) {
                Add-Check 'Bellek' 'Pagefile' 'Uyari' 'Yapilandirilmamis' 'Pagefile olmamasi dump yazimini ve bellek baskisi altindaki kararliligi etkileyebilir.'
              } else {
                $total = ($pageFiles | Measure-Object AllocatedBaseSize -Sum).Sum
                $names = ($pageFiles | ForEach-Object { $_.Name }) -join ', '
                Add-Check 'Bellek' 'Pagefile' 'Normal' "$total MB" $names
              }
            } catch {
              Add-Check 'Bellek' 'Pagefile' 'Okunamadi' 'Erisilemedi' $_.Exception.Message
            }

            $storageRead = $false
            try {
              $physicalDisks = @(Get-PhysicalDisk -ErrorAction Stop)
              foreach ($disk in $physicalDisks) {
                $storageRead = $true
                $operational = (@($disk.OperationalStatus) -join ', ')
                $status = if ($disk.HealthStatus -eq 'Healthy' -and $operational -match 'OK') { 'Normal' } elseif ($disk.HealthStatus -eq 'Unhealthy') { 'Kritik' } else { 'Uyari' }
                $detailParts = [System.Collections.Generic.List[string]]::new()
                $detailParts.Add("Media: $($disk.MediaType); Bus: $($disk.BusType); Operational: $operational") | Out-Null
                try {
                  $counter = $disk | Get-StorageReliabilityCounter -ErrorAction Stop
                  if ($null -ne $counter.Temperature) { $detailParts.Add("Sicaklik: $($counter.Temperature) C") | Out-Null }
                  if ($null -ne $counter.Wear) { $detailParts.Add("Asinma: $($counter.Wear)%") | Out-Null }
                  if ($null -ne $counter.ReadErrorsTotal) { $detailParts.Add("Okuma hatasi: $($counter.ReadErrorsTotal)") | Out-Null }
                  if ($null -ne $counter.WriteErrorsTotal) { $detailParts.Add("Yazma hatasi: $($counter.WriteErrorsTotal)") | Out-Null }
                  if ($counter.ReadErrorsTotal -gt 0 -or $counter.WriteErrorsTotal -gt 0) { if ($status -eq 'Normal') { $status = 'Uyari' } }
                } catch {}
                Add-Check 'Depolama' $disk.FriendlyName $status "$($disk.HealthStatus), $([math]::Round($disk.Size / 1GB, 1)) GB" ($detailParts -join '; ')
              }
            } catch {}

            if (-not $storageRead) {
              try {
                @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop) | ForEach-Object {
                  $status = if ($_.Status -eq 'OK') { 'Normal' } else { 'Uyari' }
                  Add-Check 'Depolama' $_.Model $status "$($_.Status), $([math]::Round($_.Size / 1GB, 1)) GB" "Arabirim: $($_.InterfaceType); Get-PhysicalDisk verisi kullanilamadi."
                }
              } catch {
                Add-Check 'Depolama' 'Fiziksel disk sagligi' 'Okunamadi' 'Erisilemedi' $_.Exception.Message
              }
            }

            try {
              $smart = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop)
              $failed = @($smart | Where-Object { $_.PredictFailure })
              if ($failed.Count -gt 0) {
                Add-Check 'Depolama' 'SMART ariza tahmini' 'Kritik' "$($failed.Count) aygit ariza tahmini bildirdi" (($failed | ForEach-Object { $_.InstanceName }) -join '; ')
              } elseif ($smart.Count -gt 0) {
                Add-Check 'Depolama' 'SMART ariza tahmini' 'Normal' "$($smart.Count) aygit, ariza tahmini yok" 'Bu sinyal tam yuzey testi yerine gecmez.'
              } else {
                Add-Check 'Depolama' 'SMART ariza tahmini' 'Bilgi' 'Veri sunulmadi' 'NVMe/RAID denetleyicileri bu eski SMART arabirimini sunmayabilir.'
              }
            } catch {
              Add-Check 'Depolama' 'SMART ariza tahmini' 'Bilgi' 'Okunamadi' 'Denetleyici SMART tahmin arabirimini sunmuyor olabilir.'
            }

            try {
              $memoryEvent = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-MemoryDiagnostics-Results'; Id=1101,1201} -MaxEvents 1 -ErrorAction Stop
              $message = [string]$memoryEvent.Message
              $status = if ($message -match 'detected hardware problems|hardware problems were detected|donan.m sorun') { 'Kritik' } elseif ($message -match 'no errors|no memory errors|hata alg.lanmad.|sorun alg.lanmad.') { 'Normal' } else { 'Bilgi' }
              Add-Check 'Bellek' 'Windows Bellek Tanilama' $status $memoryEvent.TimeCreated.ToString('dd.MM.yyyy HH:mm') (($message -replace '\s+',' ').Trim())
            } catch {
              Add-Check 'Bellek' 'Windows Bellek Tanilama' 'Bilgi' 'Sonuc bulunamadi' 'Windows Bellek Tanilama yakin zamanda calistirilmamis olabilir.'
            }

            $pending = [System.Collections.Generic.List[string]]::new()
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending.Add('Component Based Servicing') | Out-Null }
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending.Add('Windows Update') | Out-Null }
            try {
              $session = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop
              if ($session.PendingFileRenameOperations) { $pending.Add('Bekleyen dosya yeniden adlandirma') | Out-Null }
            } catch {}
            Add-Check 'Windows' 'Bekleyen yeniden baslatma' $(if ($pending.Count -gt 0) { 'Uyari' } else { 'Normal' }) $(if ($pending.Count -gt 0) { 'Var' } else { 'Yok' }) $(if ($pending.Count -gt 0) { $pending -join ', ' } else { 'Bekleyen yeniden baslatma isareti bulunmadi.' })

            try {
              $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
              $uptime = (Get-Date) - $os.LastBootUpTime
              Add-Check 'Windows' 'Sistem calisma suresi' 'Bilgi' "$([math]::Floor($uptime.TotalDays)) gun $($uptime.Hours) saat" "Son acilis: $($os.LastBootUpTime.ToString('dd.MM.yyyy HH:mm'))"
            } catch {}

            $checks | ConvertTo-Json -Depth 5 -Compress
            """;
    }

    private static HealthCheckItem BuildDismCheck(CommandResult result)
    {
        var normalized = result.Output.Replace("\r", " ").Replace("\n", " ");
        var detail = normalized.Length > 700 ? normalized[..700] + "..." : normalized;
        if (!result.Success)
        {
            return new HealthCheckItem(DateTime.Now, "Windows", "Bilesen deposu", "Okunamadi", $"Cikis kodu {result.ExitCode}", detail);
        }

        var corruption = normalized.Contains("component store corruption detected", StringComparison.OrdinalIgnoreCase) &&
                         !normalized.Contains("no component store corruption detected", StringComparison.OrdinalIgnoreCase);
        return new HealthCheckItem(
            DateTime.Now,
            "Windows",
            "Bilesen deposu",
            corruption ? "Uyari" : "Normal",
            corruption ? "Bozulma algilandi" : "Bozulma algilanmadi",
            detail);
    }

    private static IReadOnlyList<HealthCheckItem> ParseChecks(string output)
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
                var elements = document.RootElement.ValueKind == JsonValueKind.Array
                    ? document.RootElement.EnumerateArray().Select(x => x.Clone()).ToList()
                    : [document.RootElement.Clone()];
                return elements.Select(x => new HealthCheckItem(
                        ReadDate(x, "ObservedAt"),
                        ReadString(x, "Category"),
                        ReadString(x, "Component"),
                        ReadString(x, "Status"),
                        ReadString(x, "Value"),
                        ReadString(x, "Detail")))
                    .Where(x => !string.IsNullOrWhiteSpace(x.Component))
                    .ToList();
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

    private static DateTime? ReadDate(JsonElement element, string name)
    {
        return DateTime.TryParse(ReadString(element, name), out var date) ? date : null;
    }
}
