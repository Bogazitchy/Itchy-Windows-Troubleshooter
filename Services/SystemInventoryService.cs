using System.Text;
using System.Text.Json;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class SystemInventoryService
{
    private readonly CommandRunner _runner;
    private readonly Func<string, Task> _log;
    private readonly HardwareSensorService _sensors = new();

    public SystemInventoryService(CommandRunner runner, Func<string, Task> log)
    {
        _runner = runner;
        _log = log;
    }

    public async Task<IReadOnlyList<SystemInfoItem>> GetSystemDetailsAsync(CancellationToken cancellationToken)
    {
        await _log("Sistem ozellikleri, BIOS, diskler ve guvenlik bilgileri okunuyor.");
        var script = """
            $inventory = [System.Collections.Generic.List[object]]::new()
            function Add-InventoryRecord($category, $name, $value, $status = '') {
              $inventory.Add([pscustomobject]@{ Category=$category; Name=$name; Value=[string]$value; Status=[string]$status }) | Out-Null
            }

            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
            $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
            $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1
            $board = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object -First 1

            Add-InventoryRecord 'Windows' 'Surum' "$($os.Caption) $($os.Version)"
            Add-InventoryRecord 'Windows' 'Build' $os.BuildNumber
            Add-InventoryRecord 'Windows' 'Kurulum tarihi' $(if ($os.InstallDate) { $os.InstallDate.ToString('dd.MM.yyyy HH:mm') } else { '' })
            Add-InventoryRecord 'Windows' 'Son acilis' $(if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString('dd.MM.yyyy HH:mm') } else { '' })
            Add-InventoryRecord 'Cihaz' 'Uretici / model' "$($cs.Manufacturer) $($cs.Model)"
            Add-InventoryRecord 'Anakart' 'Uretici / model' "$($board.Manufacturer) $($board.Product)"
            Add-InventoryRecord 'Islemci' 'Model' $cpu.Name
            Add-InventoryRecord 'Islemci' 'Cekirdek / mantiksal' "$($cpu.NumberOfCores) / $($cpu.NumberOfLogicalProcessors)"
            Add-InventoryRecord 'Bellek' 'Toplam RAM' "$([math]::Round($cs.TotalPhysicalMemory / 1GB, 2)) GB"
            Add-InventoryRecord 'BIOS' 'Surum' $bios.SMBIOSBIOSVersion 'Uretici destek sayfasiyla karsilastirin'
            Add-InventoryRecord 'BIOS' 'Uretici' $bios.Manufacturer
            Add-InventoryRecord 'BIOS' 'Yayin tarihi' $(if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('dd.MM.yyyy') } else { '' })

            $secureBoot = try { if (Confirm-SecureBootUEFI -ErrorAction Stop) { 'Acik' } else { 'Kapali' } } catch { 'Desteklenmiyor veya okunamadi' }
            Add-InventoryRecord 'Guvenlik' 'Secure Boot' $secureBoot
            $tpm = try { Get-Tpm -ErrorAction Stop } catch { $null }
            if ($tpm -and $null -ne $tpm.TpmPresent) {
              Add-InventoryRecord 'Guvenlik' 'TPM' "Mevcut: $($tpm.TpmPresent), Hazir: $($tpm.TpmReady)"
            } else {
              Add-InventoryRecord 'Guvenlik' 'TPM' 'Okunamadi' 'Yonetici izni veya TPM destegi gerekiyor olabilir'
            }

            Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object {
              Add-InventoryRecord 'Ekran Karti' 'Model' $_.Name
            }

            Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | ForEach-Object {
              $size = if ($_.Size) { "$([math]::Round($_.Size / 1GB, 1)) GB" } else { 'Boyut bilinmiyor' }
              $state = if ($_.Status -eq 'OK') { 'Normal' } else { "Durum: $($_.Status)" }
              Add-InventoryRecord 'Depolama' $_.Model "$size, Arabirim: $($_.InterfaceType)" $state
            }

            $inventory | ConvertTo-Json -Depth 3 -Compress
            """;

        var result = await _runner.RunPowerShellAsync(
            script,
            cancellationToken,
            false,
            "Sistem envanteri okunuyor");

        var items = ParseSystemItems(result.Output).ToList();
        items.AddRange(await _sensors.ReadTemperaturesAsync(cancellationToken));
        return items;
    }

    public Task<IReadOnlyList<SystemInfoItem>> GetTemperaturesAsync(CancellationToken cancellationToken)
    {
        return _sensors.ReadTemperaturesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<DriverInfoItem>> GetDriverDetailsAsync(CancellationToken cancellationToken)
    {
        await _log("BIOS, ekran karti, chipset ve depolama suruculeri listeleniyor.");
        var script = """
            $driverInventory = [System.Collections.Generic.List[object]]::new()
            function Date-Text($value) {
              if ($null -eq $value) { return '' }
              try { return ([datetime]$value).ToString('yyyy-MM-dd') } catch { return [string]$value }
            }
            function Add-Driver($category, $driver) {
              if ($null -eq $driver -or [string]::IsNullOrWhiteSpace($driver.DeviceName)) { return }
              $hardwareId = if ($driver.HardWareID -is [array]) { $driver.HardWareID[0] } else { $driver.HardWareID }
              $driverInventory.Add([pscustomobject]@{
                Category=$category
                DeviceName=$driver.DeviceName
                Manufacturer=$driver.Manufacturer
                DriverVersion=$driver.DriverVersion
                DriverDate=(Date-Text $driver.DriverDate)
                HardwareId=[string]$hardwareId
              }) | Out-Null
            }

            $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($bios) {
              $driverInventory.Add([pscustomobject]@{
                Category='BIOS / Firmware'; DeviceName="$($bios.Manufacturer) BIOS"; Manufacturer=$bios.Manufacturer
                DriverVersion=$bios.SMBIOSBIOSVersion; DriverDate=(Date-Text $bios.ReleaseDate); HardwareId='Anakart uretici/model bilgisiyle kontrol edin'
              }) | Out-Null
            }

            $drivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
              Where-Object { -not [string]::IsNullOrWhiteSpace($_.DeviceName) }

            $drivers | Where-Object { $_.DeviceClass -eq 'DISPLAY' } | ForEach-Object { Add-Driver 'Ekran Karti' $_ }
            $drivers | Where-Object {
              $_.DeviceClass -eq 'SYSTEM' -and
              ($_.DeviceName -match 'chipset|SMBus|PCI Express|PCI standard|Management Engine|Serial IO|GPIO|I2C|AMD PCI|AMD PSP|Intel.*Host|Platform')
            } | Select-Object -First 30 | ForEach-Object { Add-Driver 'Chipset / Sistem' $_ }
            $drivers | Where-Object { $_.DeviceClass -in @('HDC','SCSIADAPTER') } |
              Select-Object -First 15 | ForEach-Object { Add-Driver 'Depolama Denetleyicisi' $_ }

            $driverInventory | Sort-Object Category,DeviceName,DriverVersion -Unique | ConvertTo-Json -Depth 4 -Compress
            """;

        var result = await _runner.RunPowerShellAsync(
            script,
            cancellationToken,
            false,
            "Surucu envanteri okunuyor");
        return ParseDrivers(result.Output);
    }

    public static string BuildTextSummary(IReadOnlyList<SystemInfoItem> items)
    {
        var builder = new StringBuilder();
        foreach (var group in items.GroupBy(x => x.Category))
        {
            builder.AppendLine(group.Key);
            foreach (var item in group)
            {
                builder.AppendLine($"  {item.Name}: {item.Value}{(string.IsNullOrWhiteSpace(item.Status) ? "" : $" ({item.Status})")}");
            }

            builder.AppendLine();
        }

        return builder.ToString().Trim();
    }

    private static IReadOnlyList<SystemInfoItem> ParseSystemItems(string output)
    {
        return ParseElements(output)
            .Select(x => new SystemInfoItem(
                ReadString(x, "Category"),
                ReadString(x, "Name"),
                ReadString(x, "Value"),
                ReadString(x, "Status")))
            .Where(x => !string.IsNullOrWhiteSpace(x.Name))
            .ToList();
    }

    private static IReadOnlyList<DriverInfoItem> ParseDrivers(string output)
    {
        return ParseElements(output)
            .Select(x =>
            {
                var category = ReadString(x, "Category");
                var dateText = ReadString(x, "DriverDate");
                var manufacturer = ReadString(x, "Manufacturer");
                var version = ReadString(x, "DriverVersion");
                return new DriverInfoItem(
                    category,
                    ReadString(x, "DeviceName"),
                    manufacturer,
                    version,
                    dateText,
                    ReadString(x, "HardwareId"),
                    GetDriverStatus(category, manufacturer, version, dateText));
            })
            .Where(x => !string.IsNullOrWhiteSpace(x.DeviceName))
            .ToList();
    }

    private static string GetDriverStatus(string category, string manufacturer, string version, string dateText)
    {
        if (!DateTime.TryParse(dateText, out var date))
        {
            return "Tarih okunamadi; uretici sitesiyle karsilastirin";
        }

        var isWindowsInboxDriver = date.Year == 2006 &&
                                   (manufacturer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                                    manufacturer.Contains("Standard", StringComparison.OrdinalIgnoreCase) ||
                                    version.StartsWith("10.0.", StringComparison.OrdinalIgnoreCase));
        if (isWindowsInboxDriver)
        {
            return "Windows dahili surucusu; surum Windows build'i ile guncellenir";
        }

        var age = DateTime.Today - date.Date;
        var reviewAfter = category.StartsWith("Ekran", StringComparison.OrdinalIgnoreCase)
            ? TimeSpan.FromDays(730)
            : category.StartsWith("BIOS", StringComparison.OrdinalIgnoreCase)
                ? TimeSpan.FromDays(1460)
                : TimeSpan.FromDays(1825);

        return age > reviewAfter
            ? "Tarih eski gorunuyor; uretici sitesiyle karsilastirin"
            : "Surum ve tarihi uretici sitesiyle karsilastirin";
    }

    private static IReadOnlyList<JsonElement> ParseElements(string output)
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
        return element.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null
            ? value.ToString()
            : "";
    }
}
