using System.Text.Json;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class RestorePointService
{
    private readonly CommandRunner _runner;

    public RestorePointService(CommandRunner runner)
    {
        _runner = runner;
    }

    public async Task<ProtectionStatus> GetProtectionStatusAsync(CancellationToken cancellationToken)
    {
        var points = await GetRestorePointsAsync(cancellationToken);
        var summary = points.Count > 0
            ? $"Sistem Koruma: Geri yukleme noktalari okunabiliyor. Toplam {points.Count} nokta listelendi."
            : "Sistem Koruma: Geri yukleme noktasi okunamadi veya hic nokta yok. Buyuk onarimlardan once Sistem Koruma ayarlarini kontrol edin.";

        return new ProtectionStatus(summary, points);
    }

    public async Task<CommandResult> CreateRestorePointAsync(string description, CancellationToken cancellationToken)
    {
        var safeDescription = description.Replace("'", "''");
        var script = $"Checkpoint-Computer -Description '{safeDescription}' -RestorePointType 'MODIFY_SETTINGS'; Write-Output 'Geri yukleme noktasi istegi gonderildi.'";
        return await _runner.RunPowerShellAsync(script, cancellationToken);
    }

    private async Task<IReadOnlyList<RestorePointItem>> GetRestorePointsAsync(CancellationToken cancellationToken)
    {
        var script = """
            Get-ComputerRestorePoint -ErrorAction SilentlyContinue |
              Sort-Object SequenceNumber -Descending |
              Select-Object -First 30 @{N='CreatedAt';E={$_.ConvertToDateTime($_.CreationTime).ToString('o')}},Description,RestorePointType |
              ConvertTo-Json -Depth 3 -Compress
            """;
        var result = await _runner.RunPowerShellAsync(script, cancellationToken, false, "Geri yukleme noktalari okunuyor");
        var output = result.Output;
        var json = output
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Reverse()
            .Select(x => x.Trim())
            .FirstOrDefault(x => x.StartsWith('[') || x.StartsWith('{'));
        if (string.IsNullOrWhiteSpace(json))
        {
            return Array.Empty<RestorePointItem>();
        }

        var list = new List<RestorePointItem>();
        using var doc = JsonDocument.Parse(json);
        var elements = doc.RootElement.ValueKind == JsonValueKind.Array
            ? doc.RootElement.EnumerateArray().ToArray()
            : [doc.RootElement];

        foreach (var element in elements)
        {
            var dateText = ReadString(element, "CreatedAt");
            list.Add(new RestorePointItem(
                DateTime.TryParse(dateText, out var date) ? date : null,
                ReadString(element, "Description"),
                ReadString(element, "RestorePointType")));
        }

        return list;
    }

    private static string ReadString(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null ? value.ToString() : "";
    }
}
