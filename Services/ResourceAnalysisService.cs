using System.Text.Json;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class ResourceAnalysisService
{
    private readonly CommandRunner _runner;
    private readonly Func<string, Task> _log;

    public ResourceAnalysisService(CommandRunner runner, Func<string, Task> log)
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
              $memory = if ($os.TotalVisibleMemorySize -gt 0) { 100 * (1 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize)) } else { 0 }
              $disk = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq '_Total' } | Select-Object -First 1
              $network = Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue |
                Measure-Object BytesTotalPersec -Sum
              $lastProcesses = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue |
                Where-Object { $_.IDProcess -gt 0 -and $_.Name -notin @('_Total','Idle') }
              $processSamples += $lastProcesses | Select-Object Name,@{N='Cpu';E={[double]$_.PercentProcessorTime}}

              $samples += [pscustomobject]@{
                Cpu=[double]$cpu.Average
                Memory=[double]$memory
                Disk=[double]$disk.PercentDiskTime
                Queue=[double]$disk.CurrentDiskQueueLength
                Network=[double]$network.Sum
              }
              if ($_ -lt 5) { Start-Sleep -Milliseconds 900 }
            }

            $topCpu = $processSamples | Group-Object Name | ForEach-Object {
              [pscustomobject]@{
                Name=$_.Name
                Percent=[math]::Round([math]::Min(100,(($_.Group | Measure-Object Cpu -Average).Average / $logical)),1)
              }
            } | Sort-Object Percent -Descending | Select-Object -First 1
            $topMemory = Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 1
            [pscustomobject]@{
              CpuAverage=[math]::Round(($samples | Measure-Object Cpu -Average).Average,1)
              CpuPeak=[math]::Round(($samples | Measure-Object Cpu -Maximum).Maximum,1)
              MemoryAverage=[math]::Round(($samples | Measure-Object Memory -Average).Average,1)
              DiskAverage=[math]::Round([math]::Min(100,($samples | Measure-Object Disk -Average).Average),1)
              DiskPeak=[math]::Round([math]::Min(100,($samples | Measure-Object Disk -Maximum).Maximum),1)
              DiskQueuePeak=[math]::Round(($samples | Measure-Object Queue -Maximum).Maximum,2)
              NetworkMbps=[math]::Round((($samples | Measure-Object Network -Average).Average * 8 / 1MB),2)
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

        return Parse(result.Output);
    }

    private static ResourceScanResult Parse(string output)
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
            [new ResourceMetricItem("Kaynak analizi", "Okunamadi", "Bilgi", reason)],
            0, 0, 0, 0, 0, 0, "", 0, "", 0);
    }

    private static string LoadStatus(double value, double warning, double critical)
    {
        return value >= critical ? "Kritik" : value >= warning ? "Yuksek" : "Normal";
    }

    private static double ReadDouble(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return 0;
        }

        return value.TryGetDouble(out var number) ? number : 0;
    }

    private static string ReadString(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null
            ? value.ToString()
            : "";
    }
}
