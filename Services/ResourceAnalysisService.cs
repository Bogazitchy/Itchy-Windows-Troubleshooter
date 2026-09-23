using System.Text.Json;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class ResourceAnalysisService
{
    private readonly ICommandRunner _runner;
    private readonly Func<string, Task> _log;

    public ResourceAnalysisService(ICommandRunner runner, Func<string, Task> log)
    {
        _runner = runner;
        _log = log;
    }

    public async Task<ResourceScanResult> ScanAsync(CancellationToken cancellationToken)
    {
        await _log("Kaynak Izleyicisi verileri ornekleniyor: CPU, RAM, disk, ag ve en yogun islemler.");
        var script = """
            $samples = @()
            $lastProcesses = @()
            $processSamples = @()
            $logical = [math]::Max(1, [int]$env:NUMBER_OF_PROCESSORS)

            1..5 | ForEach-Object {
              $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Measure-Object LoadPercentage -Average
              $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
              $memory = if ($os.TotalVisibleMemorySize -gt 0) { 100 * (1 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize)) } else { $null }
              $disk = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq '_Total' } | Select-Object -First 1
              $network = Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue |
                Measure-Object BytesTotalPersec -Sum
              $lastProcesses = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue |
                Where-Object { $_.IDProcess -gt 0 -and $_.Name -notin @('_Total','Idle') }
              $processSamples += $lastProcesses | Select-Object Name,@{N='Cpu';E={[double]$_.PercentProcessorTime}}

              $samples += [pscustomobject]@{
                Cpu=$(if ($null -ne $cpu.Average) { [double]$cpu.Average } else { $null })
                Memory=$(if ($null -ne $memory) { [double]$memory } else { $null })
                Disk=$(if ($null -ne $disk.PercentDiskTime) { [double]$disk.PercentDiskTime } else { $null })
                Queue=$(if ($null -ne $disk.CurrentDiskQueueLength) { [double]$disk.CurrentDiskQueueLength } else { $null })
                Network=$(if ($network.Count -gt 0 -and $null -ne $network.Sum) { [double]$network.Sum } else { $null })
              }
              if ($_ -lt 5) { Start-Sleep -Milliseconds 900 }
            }

            function Aggregate($property, $peak = $false, $scale = 1) {
              $values = @($samples | Where-Object { $null -ne $_.$property })
              if ($values.Count -eq 0) { return $null }
              $measure = $values | Measure-Object -Property $property -Average -Maximum
              $number = if ($peak) { $measure.Maximum } else { $measure.Average }
              [math]::Round($number * $scale, 2)
            }
            $counts = @{}
            'Cpu','Memory','Disk','Queue','Network' | ForEach-Object { $key=$_; $counts[$key]=@($samples | Where-Object { $null -ne $_.$key }).Count }
            $topCpu = $processSamples | Group-Object Name | ForEach-Object {
              [pscustomobject]@{
                Name=$_.Name
                Percent=[math]::Round([math]::Min(100,(($_.Group | Measure-Object Cpu -Average).Average / $logical)),1)
              }
            } | Sort-Object Percent -Descending | Select-Object -First 1
            $topMemory = Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 1
            [pscustomobject]@{
              SampleCounts=$counts
              CpuAverage=$(Aggregate 'Cpu')
              CpuPeak=$(Aggregate 'Cpu' $true)
              MemoryAverage=$(Aggregate 'Memory')
              DiskAverage=$(Aggregate 'Disk')
              DiskPeak=$(Aggregate 'Disk' $true)
              DiskQueuePeak=$(Aggregate 'Queue' $true)
              NetworkMbps=$(Aggregate 'Network' $false (8/1MB))
              TopCpuProcess=[string]$topCpu.Name
              TopCpuPercent=[double]$topCpu.Percent
              TopMemoryProcess=[string]$topMemory.ProcessName
              TopMemoryMb=[math]::Round(($topMemory.WorkingSet64 / 1MB),1)
            } | ConvertTo-Json -Depth 3 -Compress
            """;

        var result = await _runner.RunPowerShellAsync(
            script,
            cancellationToken,
            false,
            "Kaynak kullanimi ornekleniyor");

        return result.Success ? Parse(result.Output) : Empty("Kaynak sorgusu tamamlanamadı");
    }

    public static ResourceScanResult Parse(string output)
    {
        var candidate = output
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Reverse()
            .Select(x => x.Trim())
            .FirstOrDefault(x => x.StartsWith('{'));
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return Empty("Kaynak verileri okunamadi");
        }

        try
        {
            using var document = JsonDocument.Parse(candidate);
            var root = document.RootElement;
            var cpuAverage = ReadDouble(root, "CpuAverage");
            var cpuPeak = ReadDouble(root, "CpuPeak");
            var memoryAverage = ReadDouble(root, "MemoryAverage");
            var diskAverage = ReadDouble(root, "DiskAverage");
            var diskPeak = ReadDouble(root, "DiskPeak");
            var diskQueue = ReadDouble(root, "DiskQueuePeak");
            var network = ReadDouble(root, "NetworkMbps");
            var topCpu = ReadString(root, "TopCpuProcess");
            var topCpuPercent = ReadDouble(root, "TopCpuPercent");
            var topMemory = ReadString(root, "TopMemoryProcess");
            var topMemoryMb = ReadDouble(root, "TopMemoryMb");

            var metrics = new List<ResourceMetricItem>
            {
                new("CPU kullanimi", $"Ort. %{cpuAverage:N1} / Tepe %{cpuPeak:N1}", LoadStatus(cpuAverage, 85, 95), "Bes kisa orneklemin ortalamasi ve tepe degeri."),
                new("RAM kullanimi", $"%{memoryAverage:N1}", LoadStatus(memoryAverage, 85, 95), "Fiziksel bellek kullanim orani."),
                new("Disk etkinligi", $"Ort. %{diskAverage:N1} / Tepe %{diskPeak:N1}", LoadStatus(diskAverage, 80, 95), "Fiziksel disk etkinlik orani."),
                new("Disk kuyrugu", $"{diskQueue:N2}", diskQueue >= 4 ? "Kritik" : diskQueue >= 2 ? "Yuksek" : "Normal", "Surekli yuksek kuyruk depolama darbogazina isaret edebilir."),
                new("Ag trafigi", $"{network:N2} Mbit/sn", "Bilgi", "Tarama anindaki toplam ag trafigi."),
                new("En yogun CPU islemi", string.IsNullOrWhiteSpace(topCpu) ? "Okunamadi" : $"{topCpu} (%{topCpuPercent:N1})", "Bilgi", "Tarama sonundaki islem orneklemi."),
                new("En cok RAM kullanan", string.IsNullOrWhiteSpace(topMemory) ? "Okunamadi" : $"{topMemory} ({topMemoryMb:N1} MB)", "Bilgi", "Tarama sonundaki islem orneklemi.")
            };

            var keys = new[] { "Cpu", "Memory", "Disk", "Queue", "Network", "Cpu", "Memory" };
            for (var i = 0; i < metrics.Count; i++)
            {
                var count = root.TryGetProperty("SampleCounts", out var counts) && counts.TryGetProperty(keys[i], out var c) && c.TryGetInt32(out var n) ? n : 0;
                var missing = count == 0 || metrics[i].Value.Contains("NaN") || metrics[i].Value == "Okunamadi";
                metrics[i] = metrics[i] with
                {
                    Value = missing ? "Ölçülemedi" : metrics[i].Value,
                    Status = missing ? "Erişilemedi" : count < 5 ? "Kısmi" : metrics[i].Status,
                    Availability = missing ? DataAvailability.Inaccessible : count < 5 ? DataAvailability.Partial : DataAvailability.Read,
                    Detail = metrics[i].Detail + $" Geçerli örnek: {count}/5."
                };
            }

            return new ResourceScanResult(
                metrics,
                cpuAverage,
                cpuPeak,
                memoryAverage,
                diskAverage,
                diskPeak,
                diskQueue,
                topCpu,
                topCpuPercent,
                topMemory,
                topMemoryMb);
        }
        catch (JsonException)
        {
            return Empty("Kaynak verisi islenemedi");
        }
    }

    private static ResourceScanResult Empty(string reason)
    {
        return new ResourceScanResult(
            [new ResourceMetricItem("Kaynak analizi", "Ölçülemedi", "Erişilemedi", reason) { Availability = DataAvailability.Inaccessible }],
            double.NaN, double.NaN, double.NaN, double.NaN, double.NaN, double.NaN, "", double.NaN, "", double.NaN);
    }

    private static string LoadStatus(double value, double warning, double critical)
    {
        return double.IsNaN(value) ? "Erişilemedi" : value >= critical ? "Kritik" : value >= warning ? "Yuksek" : "Normal";
    }

    private static double ReadDouble(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return double.NaN;
        }

        return value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var number) ? number : double.NaN;
    }

    private static string ReadString(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null
            ? value.ToString()
            : "";
    }
}
