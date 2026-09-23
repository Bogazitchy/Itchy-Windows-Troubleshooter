using System.Text;
using System.Text.Json;
using System.IO;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class CaseImportService(ICommandRunner runner)
{
    public async Task<EventCollectionResult> ReadEventsAsync(string path, CancellationToken token)
    {
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(Path.GetFullPath(path)));
        var script = $$$"""
            $path = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{{encoded}}}'))
            $items = @(Get-WinEvent -Path $path -MaxEvents 5001 -ErrorAction Stop)
            $events = @($items | Select-Object -First 5000 @{N='TimeCreated';E={$_.TimeCreated.ToString('o')}},LogName,ProviderName,Id,LevelDisplayName,@{N='Message';E={$_.Message}})
            [pscustomobject]@{
              Events=$events
              Coverage=@([pscustomobject]@{Source=$path;Status=$(if($items.Count -gt 5000){'Kismi'}else{'Tamamlandi'});RecordCount=$events.Count;Detail='Kullanıcının haricî vaka için seçtiği EVTX; en çok 5000 olay.'})
            } | ConvertTo-Json -Depth 5 -Compress
            """;
        return EventCollectionService.Parse(await runner.RunPowerShellAsync(script, token, false, "Haricî vaka EVTX dosyası okunuyor"));
    }

    public static async Task<IReadOnlyList<DriverInfoItem>> ReadInventoryAsync(string path, CancellationToken token)
    {
        await using var stream = File.OpenRead(path);
        if (stream.Length > 10 * 1024 * 1024) throw new InvalidDataException("Envanter 10 MB sınırını aşıyor.");
        var items = await JsonSerializer.DeserializeAsync<List<DriverInfoItem>>(stream, cancellationToken: token)
            ?? throw new InvalidDataException("Sürücü envanteri JSON dizisi olmalı.");
        if (items.Any(x => string.IsNullOrWhiteSpace(x.DeviceName) || x.DriverVersion is null || x.Manufacturer is null))
            throw new InvalidDataException("Envanterde DeviceName, DriverVersion ve Manufacturer gerekli.");
        return items;
    }
}
