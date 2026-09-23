using System.Text.Json;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed record EventCollectionResult(IReadOnlyList<EventRecordItem> Events, IReadOnlyList<ScanCoverageItem> Coverage);

public sealed class EventCollectionService(ICommandRunner runner)
{
    public async Task<EventCollectionResult> ReadAsync(int days, CancellationToken token)
    {
        var script = """

            $start = (Get-Date).AddDays(-{DAYS})
            $events = @()
            $coverage = [System.Collections.Generic.List[object]]::new()
            function Read-Events($filter, $limit, $source) {
              try {
                $items = @(Get-WinEvent -FilterHashtable $filter -MaxEvents ($limit+1) -ErrorAction Stop)
                $state = if ($items.Count -gt $limit) { 'Kismi' } else { 'Tamamlandi' }
                $coverage.Add([pscustomobject]@{Source=$source;Status=$state;RecordCount=[math]::Min($items.Count,$limit);Detail="Sorgu limiti: $limit; daha eski kayıtlar sınır dışında olabilir."})
                $items | Select-Object -First $limit
              } catch {
                $empty = $_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'
                $coverage.Add([pscustomobject]@{Source=$source;Status=$(if($empty){'Tamamlandi'}else{'Erisilemedi'});RecordCount=0;Detail=$(if($empty){'Eşleşen olay yok.'}else{$_.Exception.Message})})
              }
            }
            $events += Read-Events (@{LogName='System'; StartTime=$start; Level=1,2}) 350 ([string](@{LogName='System'; StartTime=$start; Level=1,2}).LogName + '/' + [string](@{LogName='System'; StartTime=$start; Level=1,2}).ProviderName)
            @(
              @{Provider='disk'; Id=@(7,11,15,51,129,153,157)},
              @{Provider='Microsoft-Windows-Ntfs'; Id=@(55,98,140)},
              @{Provider='storahci'; Id=@(129,153)},
              @{Provider='stornvme'; Id=@(11,129,153)},
              @{Provider='storport'; Id=@(129,153)},
              @{Provider='iaStorA'; Id=@(129,153)},
              @{Provider='iaStorAC'; Id=@(129,153)},
              @{Provider='volmgr'; Id=@(45,46,49,161,162)},
              @{Provider='partmgr'; Id=@(58)},
              @{Provider='Microsoft-Windows-WHEA-Logger'; Id=@(18,19,20,47)},
              @{Provider='Display'; Id=@(4101)},
              @{Provider='Microsoft-Windows-Kernel-Power'; Id=@(41)},
              @{Provider='Microsoft-Windows-WER-SystemErrorReporting'; Id=@(1001)},
              @{Provider='Microsoft-Windows-Kernel-PnP'; Id=@(219,411,442)},
              @{Provider='Microsoft-Windows-DriverFrameworks-UserMode'; Id=@(10110,10111)},
              @{Provider='Microsoft-Windows-MemoryDiagnostics-Results'; Id=@(1101,1201)},
              @{Provider='Microsoft-Windows-Kernel-Processor-Power'; Id=@(35,37,55)},
              @{Provider='Microsoft-Windows-UserPnp'; Id=@(20001,20003)},
              @{Provider='Service Control Manager'; Id=@(7000,7001,7009,7023,7026,7031,7034,7043)}
            ) | ForEach-Object {
              $events += Read-Events (@{LogName='System'; StartTime=$start; ProviderName=$_.Provider; Id=$_.Id; Level=1,2,3}) 180 ([string](@{LogName='System'; StartTime=$start; ProviderName=$_.Provider; Id=$_.Id; Level=1,2,3}).LogName + '/' + [string](@{LogName='System'; StartTime=$start; ProviderName=$_.Provider; Id=$_.Id; Level=1,2,3}).ProviderName)
            }
            $events += Read-Events (@{LogName='Application'; StartTime=$start; Level=1,2}) 350 ([string](@{LogName='Application'; StartTime=$start; Level=1,2}).LogName + '/' + [string](@{LogName='Application'; StartTime=$start; Level=1,2}).ProviderName)
            $events += Read-Events (@{LogName='Setup'; StartTime=$start; Level=1,2,3}) 180 ([string](@{LogName='Setup'; StartTime=$start; Level=1,2,3}).LogName + '/' + [string](@{LogName='Setup'; StartTime=$start; Level=1,2,3}).ProviderName)
            @(
              'Microsoft-Windows-DeviceSetupManager/Admin',
              'Microsoft-Windows-DriverFrameworks-UserMode/Operational',
              'Microsoft-Windows-WindowsUpdateClient/Operational',
              'Microsoft-Windows-Diagnostics-Performance/Operational',
              'Microsoft-Windows-CodeIntegrity/Operational'
            ) | ForEach-Object {
              $events += Read-Events (@{LogName=$_; StartTime=$start; Level=1,2,3}) 180 ([string](@{LogName=$_; StartTime=$start; Level=1,2,3}).LogName + '/' + [string](@{LogName=$_; StartTime=$start; Level=1,2,3}).ProviderName)
            }
            $events += Read-Events (@{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$start; Id=1116,1117,1118,1119,5001,5007}) 120 ([string](@{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$start; Id=1116,1117,1118,1119,5001,5007}).LogName + '/' + [string](@{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$start; Id=1116,1117,1118,1119,5001,5007}).ProviderName)
            $selected = @($events |
              Where-Object { $_ -ne $null } |
              Group-Object {$_.LogName + '|' + $_.RecordId} |
              ForEach-Object { $_.Group[0] } |
              Sort-Object TimeCreated -Descending |
              Select-Object -First 1200 @{N='TimeCreated';E={$_.TimeCreated.ToString('o')}},LogName,ProviderName,Id,LevelDisplayName,@{N='Message';E={$m=$_.Message; if ([string]::IsNullOrWhiteSpace($m)) { '' } else { $m=$m -replace '\s+',' '; if ($m.Length -gt 1200) { $m.Substring(0,1200) } else { $m } }}})
            if (@($events | Group-Object {$_.LogName + '|' + $_.RecordId}).Count -gt 1200) {
              $coverage.Add([pscustomobject]@{Source='Toplam olaylar';Status='Kismi';RecordCount=1200;Detail='Toplam kayıt sınırı aşıldı.'})
            }
            [pscustomobject]@{Events=@($selected);Coverage=$coverage.ToArray()} | ConvertTo-Json -Depth 5 -Compress
            """.Replace("{DAYS}", Math.Clamp(days, 1, 365).ToString());
        var result = await runner.RunPowerShellAsync(script, token, false, "Olay kayıtları ve sorgu kapsamı okunuyor");
        return Parse(result);
    }

    public static EventCollectionResult Parse(CommandResult result)
    {
        try
        {
            if (!result.Success) throw new JsonException("Olay sorgusu başarısız.");
            var line = result.Output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Last(x => x.TrimStart().StartsWith('{'));
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            var events = root.GetProperty("Events").EnumerateArray().Select(x => new EventRecordItem(
                DateTime.TryParse(x.GetProperty("TimeCreated").GetString(), out var date) ? date : null,
                x.GetProperty("LogName").GetString() ?? "", x.GetProperty("ProviderName").GetString() ?? "",
                x.GetProperty("Id").GetInt32(), x.GetProperty("LevelDisplayName").GetString() ?? "", x.GetProperty("Message").GetString() ?? "")).ToList();
            var coverage = JsonSerializer.Deserialize<List<ScanCoverageItem>>(root.GetProperty("Coverage").GetRawText()) ?? [];
            if (coverage.Count == 0) throw new JsonException("Sorgu kapsamı eksik.");
            return new(events, coverage);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        {
            return new([], [new("Event Viewer", "Erisilemedi", 0, "Olay verisi veya sorgu kapsamı okunamadı: " + ex.Message)]);
        }
    }
}
