using System.Text.Json;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class RestorePointService
{
    private readonly ICommandRunner _runner;

    public RestorePointService(ICommandRunner runner)
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
        var script = $$"""
            $before = @(Get-ComputerRestorePoint -ErrorAction Stop | Select-Object -ExpandProperty SequenceNumber)
            Checkpoint-Computer -Description '{{safeDescription}}' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
            $new = @(Get-ComputerRestorePoint -ErrorAction Stop | Where-Object { $_.SequenceNumber -notin $before -and $_.Description -eq '{{safeDescription}}' })
            if ($new.Count -eq 0) { throw 'Yeni geri yükleme noktası doğrulanamadı; sıklık sınırı veya koruma ayarını kontrol edin.' }
            Write-Output ('Doğrulanan yeni geri yükleme kimliği: ' + ($new.SequenceNumber -join ', '))
            """;
        return await _runner.RunPowerShellAsync(script, cancellationToken, policy: CommandCancellationPolicy.WaitForCompletion);
    }

    private async Task<IReadOnlyList<RestorePointItem>> GetRestorePointsAsync(CancellationToken cancellationToken)
    {
        var script = """
            Get-ComputerRestorePoint -ErrorAction Stop |
              Sort-Object SequenceNumber -Descending |
              Select-Object -First 30 @{N='CreatedAt';E={$_.ConvertToDateTime($_.CreationTime).ToString('o')}},Description,RestorePointType |
              ConvertTo-Json -Depth 3 -Compress
            """;
        var result = await _runner.RunPowerShellAsync(
            script,
            cancellationToken,
            false,
            "Geri yukleme noktalari okunuyor",
            TimeSpan.FromSeconds(15));
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
