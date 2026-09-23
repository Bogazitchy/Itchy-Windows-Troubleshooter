using System.Text.Json;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public static class RepairOutcomeParser
{
    public static RepairOutcome Parse(CommandResult result)
    {
        foreach (var line in result.Output.Split('\n').Reverse())
        {
            if (!line.TrimStart().StartsWith('{')) continue;
            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                if (!root.TryGetProperty("ItchyRepair", out var marker) || marker.ValueKind != JsonValueKind.True) continue;
                var status = root.GetProperty("Status").GetString();
                var steps = root.GetProperty("Steps").EnumerateArray().ToList();
                var failures = steps.Any(x => !x.GetProperty("Success").GetBoolean());
                if (status == "Partial") return RepairOutcome.PartiallySucceeded;
                if (!result.Success || failures || steps.Count == 0) return RepairOutcome.Failed;
                return status switch
                {
                    "Succeeded" => RepairOutcome.Succeeded,
                    "RestartRequired" => RepairOutcome.RestartRequired,
                    _ => RepairOutcome.Failed
                };
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException) { }
        }
        if (result.ExitCode == 3010) return RepairOutcome.RestartRequired;
        return result.Success ? RepairOutcome.Unverified : RepairOutcome.Failed;
    }
}
