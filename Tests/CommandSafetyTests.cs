using System.Diagnostics;
using System.Text;
using ItchyWindowsTroubleshooter.Models;
using ItchyWindowsTroubleshooter.Services;
using Xunit;

namespace ItchyWindowsTroubleshooter.Tests;

public sealed class CommandSafetyTests
{
    [Fact]
    public async Task CancellationStopsParentAndChildBeforeReturning()
    {
        var started = new TaskCompletionSource<int[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var runner = new CommandRunner(line =>
        {
            if (line.StartsWith("PIDS:")) started.TrySetResult(line[5..].Split(',').Select(int.Parse).ToArray());
            return Task.CompletedTask;
        });
        using var cts = new CancellationTokenSource();
        var task = runner.RunPowerShellAsync("""
            $child = Start-Process powershell.exe -ArgumentList '-NoProfile -Command Start-Sleep -Seconds 60' -WindowStyle Hidden -PassThru
            Write-Output "PIDS:$PID,$($child.Id)"
            Start-Sleep -Seconds 60
            """, cts.Token, displayCommand: "Benign cancellation fixture", timeout: TimeSpan.FromSeconds(15));
        int[] ids = [];
        try
        {
            ids = await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task.WaitAsync(TimeSpan.FromSeconds(10)));
            Assert.All(ids, id => Assert.False(IsRunning(id), $"Process {id} still running after cancellation."));
        }
        finally
        {
            cts.Cancel();
            foreach (var id in ids)
            {
                try { using var p = Process.GetProcessById(id); if (!p.HasExited) p.Kill(true); }
                catch (ArgumentException) { }
            }
        }
    }

    [Fact]
    public async Task NonInterruptibleCommandWaitsDespiteCancellationAndTimeout()
    {
        using var cts = new CancellationTokenSource();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var runner = new CommandRunner(line =>
        {
            if (line == "STARTED") { cts.Cancel(); started.TrySetResult(); }
            return Task.CompletedTask;
        });
        var task = runner.RunPowerShellAsync("Write-Output 'STARTED'; Start-Sleep -Milliseconds 800; Write-Output 'FINISHED'",
            cts.Token, displayCommand: "Benign non-interruptible fixture", timeout: TimeSpan.FromMilliseconds(50),
            policy: CommandCancellationPolicy.WaitForCompletion);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(task.IsCompleted);
        var result = await task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(result.Success);
        Assert.Contains("FINISHED", result.Output);
    }

    [Fact]
    public async Task ConcurrentStreamsDoNotCorruptOutput()
    {
        var runner = new CommandRunner(_ => Task.CompletedTask);
        var result = await runner.RunPowerShellAsync("""
            1..150 | ForEach-Object {
              [Console]::Out.WriteLine("OUT:$_")
              [Console]::Error.WriteLine("ERR:$_")
            }
            """, CancellationToken.None, displayCommand: "Output fixture");
        Assert.True(result.Success);
        var lines = result.Output.Split(['\r','\n'], StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(150, lines.Count(x => x.StartsWith("OUT:")));
        Assert.Equal(150, lines.Count(x => x.StartsWith("ERR:")));
    }

    [Fact]
    public async Task TimeoutStopsDiagnostic()
    {
        var runner = new CommandRunner(_ => Task.CompletedTask);
        var result = await runner.RunPowerShellAsync("Start-Sleep -Seconds 30", CancellationToken.None,
            displayCommand: "Timeout fixture", timeout: TimeSpan.FromMilliseconds(500));
        Assert.False(result.Success);
        Assert.Equal(-1, result.ExitCode);
    }

    [Fact]
    public async Task RepairScriptsParseWithoutExecutingRepairs()
    {
        var fake = new EvidenceSafetyTests.FakeRunner(new("", 0, "", true));
        await new EventCollectionService(fake).ReadAsync(30, CancellationToken.None);
        await new ResourceAnalysisService(fake, _ => Task.CompletedTask).ScanAsync(CancellationToken.None);
        await new RestorePointService(fake).CreateRestorePointAsync("test", CancellationToken.None);
        var scripts = new[]
        {
            RepairScripts.WindowsUpdateReset, RepairScripts.NetworkReset, RepairScripts.TempPreview,
            RepairScripts.CleanTemp("W10="), RepairScripts.Disk("D:", true, false), RepairScripts.Disk("D:", false, false)
        }.Concat(fake.Scripts);
        var runner = new CommandRunner(_ => Task.CompletedTask);
        foreach (var script in scripts)
        {
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(script));
            var result = await runner.RunPowerShellAsync($$"""
                $text=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{encoded}}'))
                $tokens=$null; $errors=$null
                [System.Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors) | Out-Null
                if ($errors.Count -gt 0) { $errors | ForEach-Object Message; exit 1 }
                """, CancellationToken.None, false, "Script syntax validation");
            Assert.True(result.Success, result.Output);
        }
    }

    [Fact]
    public async Task MockedUpdateFailureReportsFailure_NoRealServicesTouched()
    {
        // These functions shadow every mutating service/file command in the tested script.
        const string mocks = """
            function Get-Service($Name) {
              $item=[pscustomobject]@{Status='Running'}
              $item | Add-Member ScriptMethod WaitForStatus { param($state,$timeout) }
              return $item
            }
            function Stop-Service { throw 'SIMULATED STOP FAILURE' }
            function Start-Service { }
            function Rename-Item { throw 'UNEXPECTED RENAME' }
            """;
        var runner = new CommandRunner(_ => Task.CompletedTask);
        var result = await runner.RunPowerShellAsync(mocks + "\n" + RepairScripts.WindowsUpdateReset,
            CancellationToken.None, false, "Mocked update failure");
        Assert.False(result.Success);
        Assert.Contains("SIMULATED STOP FAILURE", result.Output);
        Assert.NotEqual(RepairOutcome.Succeeded, RepairOutcomeParser.Parse(result));
    }

    [Fact]
    public async Task RestorePointWithoutNewIdentityFails_NoRealCheckpointCreated()
    {
        var fake = new EvidenceSafetyTests.FakeRunner(new("", 0, "", true));
        await new RestorePointService(fake).CreateRestorePointAsync("fixture", CancellationToken.None);
        const string mocks = """
            function Get-ComputerRestorePoint { [pscustomobject]@{SequenceNumber=7;Description='fixture'} }
            function Checkpoint-Computer { }
            """;
        var result = await new CommandRunner(_ => Task.CompletedTask).RunPowerShellAsync(
            mocks + "\n" + Assert.Single(fake.Scripts), CancellationToken.None, false, "Mocked restore point");
        Assert.False(result.Success);
    }

    [Fact]
    public async Task EventCollectorReportsEveryLimitedOrDeniedQuery()
    {
        var fake = new EvidenceSafetyTests.FakeRunner(new("", 0, "", true));
        await new EventCollectionService(fake).ReadAsync(30, CancellationToken.None);
        const string mocks = """
            function Get-WinEvent($FilterHashtable, $MaxEvents, $ErrorAction) {
              if ($FilterHashtable.LogName -eq 'Setup') { throw 'SIMULATED ACCESS DENIED' }
              $count = if ($FilterHashtable.LogName -eq 'System') { $MaxEvents } else { 1 }
              1..$count | ForEach-Object {
                [pscustomobject]@{LogName=$FilterHashtable.LogName; RecordId=$_; TimeCreated=(Get-Date); ProviderName='Fixture'; Id=7; LevelDisplayName='Error'; Message='Synthetic'}
              }
            }
            """;
        var result = await new CommandRunner(_ => Task.CompletedTask).RunPowerShellAsync(mocks + "\n" + Assert.Single(fake.Scripts), CancellationToken.None, false, "Mocked event collection");
        Assert.True(result.Success, result.Output);
        var collection = EventCollectionService.Parse(result);
        Assert.True(collection.Events.Count < 1200);
        Assert.Contains(collection.Coverage, x => x.Status == "Kismi");
        Assert.Contains(collection.Coverage, x => x.Status == "Erisilemedi" && x.Detail.Contains("SIMULATED"));
    }

    [Fact]
    public async Task MissingResourceQueriesStayUnknownThroughPowerShellAndParser()
    {
        var fake = new EvidenceSafetyTests.FakeRunner(new("", 0, "", true));
        await new ResourceAnalysisService(fake, _ => Task.CompletedTask).ScanAsync(CancellationToken.None);
        const string mocks = """
            function Get-CimInstance { }
            function Get-Process { }
            function Start-Sleep { }
            """;
        var result = await new CommandRunner(_ => Task.CompletedTask).RunPowerShellAsync(mocks + "\n" + Assert.Single(fake.Scripts), CancellationToken.None, false, "Mocked missing resource data");
        Assert.True(result.Success, result.Output);
        var resources = ResourceAnalysisService.Parse(result.Output);
        Assert.All(resources.Metrics, x => Assert.Equal(DataAvailability.Inaccessible, x.Availability));
    }

    private static bool IsRunning(int id)
    {
        try { using var p = Process.GetProcessById(id); return !p.HasExited; }
        catch (ArgumentException) { return false; }
    }
}
