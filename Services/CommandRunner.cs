using System.Diagnostics;
using System.Text;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class CommandRunner
{
    private readonly Func<string, Task> _log;

    public CommandRunner(Func<string, Task> log)
    {
        _log = log;
    }

    public Task<CommandResult> RunPowerShellAsync(
        string script,
        CancellationToken cancellationToken,
        bool streamOutput = true,
        string? displayCommand = null,
        TimeSpan? timeout = null)
    {
        var preparedScript = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); " +
                             "$OutputEncoding = [System.Text.UTF8Encoding]::new($false); " +
                             "$ProgressPreference = 'SilentlyContinue'; " +
                             script;
        var encodedScript = Convert.ToBase64String(Encoding.Unicode.GetBytes(preparedScript));
        return RunProcessAsync(
            "powershell.exe",
            $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encodedScript}",
            displayCommand ?? script,
            cancellationToken,
            streamOutput,
            timeout);
    }

    public Task<CommandResult> RunCmdAsync(string command, CancellationToken cancellationToken)
    {
        return RunProcessAsync("cmd.exe", $"/c {command}", command, cancellationToken, true, null);
    }

    public Task<CommandResult> RunExecutableAsync(
        string fileName,
        string arguments,
        string displayCommand,
        CancellationToken cancellationToken,
        TimeSpan timeout,
        bool streamOutput = false)
    {
        return RunProcessAsync(fileName, arguments, displayCommand, cancellationToken, streamOutput, timeout);
    }

    private async Task<CommandResult> RunProcessAsync(
        string fileName,
        string arguments,
        string displayCommand,
        CancellationToken cancellationToken,
        bool streamOutput,
        TimeSpan? timeout)
    {
        var output = new StringBuilder();
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        process.OutputDataReceived += async (_, e) =>
        {
            if (e.Data is null)
            {
                return;
            }

            output.AppendLine(e.Data);
            if (streamOutput)
            {
                await _log(e.Data);
            }
        };

        process.ErrorDataReceived += async (_, e) =>
        {
            if (e.Data is null)
            {
                return;
            }

            output.AppendLine(e.Data);
            if (streamOutput)
            {
                await _log(e.Data);
            }
        };

        await _log($"> {displayCommand}");
        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        using var waitCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout.HasValue)
        {
            waitCancellation.CancelAfter(timeout.Value);
        }

        try
        {
            await process.WaitForExitAsync(waitCancellation.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(true);
                    await process.WaitForExitAsync(CancellationToken.None);
                }
            }
            catch
            {
            }

            var duration = timeout.GetValueOrDefault();
            var durationText = duration.TotalMinutes >= 1
                ? $"{duration.TotalMinutes:N0} dakika"
                : $"{duration.TotalSeconds:N0} saniye";
            var timeoutMessage = $"{displayCommand} zaman asimina ugradi ({durationText}).";
            await _log(timeoutMessage);
            output.AppendLine(timeoutMessage);
            return new CommandResult(displayCommand, -1, output.ToString(), false);
        }

        if (!streamOutput && process.ExitCode != 0 && output.Length > 0)
        {
            var detail = output.ToString()
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim())
                .FirstOrDefault(x => !x.StartsWith("#< CLIXML", StringComparison.OrdinalIgnoreCase) && !x.StartsWith('<'));
            await _log(string.IsNullOrWhiteSpace(detail)
                ? $"{displayCommand} tamamlanamadi (cikis kodu {process.ExitCode})."
                : $"{displayCommand} tamamlanamadi: {(detail.Length > 240 ? detail[..240] + "..." : detail)}");
        }

        return new CommandResult(displayCommand, process.ExitCode, output.ToString(), process.ExitCode == 0);
    }

}
