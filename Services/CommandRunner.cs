using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public enum CommandCancellationPolicy { StopProcessTree, WaitForCompletion }

public interface ICommandRunner
{
    Task<CommandResult> RunPowerShellAsync(string script, CancellationToken cancellationToken,
        bool streamOutput = true, string? displayCommand = null, TimeSpan? timeout = null,
        CommandCancellationPolicy policy = CommandCancellationPolicy.StopProcessTree);
    Task<CommandResult> RunCmdAsync(string command, CancellationToken cancellationToken,
        CommandCancellationPolicy policy = CommandCancellationPolicy.StopProcessTree);
    Task<CommandResult> RunExecutableAsync(string fileName, string arguments, string displayCommand,
        CancellationToken cancellationToken, TimeSpan timeout, bool streamOutput = false,
        CommandCancellationPolicy policy = CommandCancellationPolicy.StopProcessTree);
}

public sealed class CommandRunner(Func<string, Task> log) : ICommandRunner
{
    public Task<CommandResult> RunPowerShellAsync(string script, CancellationToken cancellationToken,
        bool streamOutput = true, string? displayCommand = null, TimeSpan? timeout = null,
        CommandCancellationPolicy policy = CommandCancellationPolicy.StopProcessTree)
    {
        var prepared = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); " +
            "$OutputEncoding = [System.Text.UTF8Encoding]::new($false); $ProgressPreference = 'SilentlyContinue'; " +
            "$ErrorActionPreference = 'Stop'; " + script;
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(prepared));
        return RunProcessAsync("powershell.exe", $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}",
            displayCommand ?? script, cancellationToken, streamOutput, timeout, policy);
    }

    public Task<CommandResult> RunCmdAsync(string command, CancellationToken cancellationToken,
        CommandCancellationPolicy policy = CommandCancellationPolicy.StopProcessTree) =>
        RunProcessAsync("cmd.exe", $"/c {command}", command, cancellationToken, true, null, policy);

    public Task<CommandResult> RunExecutableAsync(string fileName, string arguments, string displayCommand,
        CancellationToken cancellationToken, TimeSpan timeout, bool streamOutput = false,
        CommandCancellationPolicy policy = CommandCancellationPolicy.StopProcessTree) =>
        RunProcessAsync(fileName, arguments, displayCommand, cancellationToken, streamOutput, timeout, policy);

    private async Task<CommandResult> RunProcessAsync(string fileName, string arguments, string displayCommand,
        CancellationToken cancellationToken, bool streamOutput, TimeSpan? timeout, CommandCancellationPolicy policy)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(fileName, arguments)
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
                CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
            }
        };
        await log($"> {displayCommand}");
        if (policy == CommandCancellationPolicy.WaitForCompletion)
            await log("Bu onarım kesilemez; alt süreç tamamlanana kadar beklenecek.");
        cancellationToken.ThrowIfCancellationRequested();
        process.Start();

        // Each stream owns its buffer. Await the readers before exposing completion to the UI.
        using var logLock = new SemaphoreSlim(1, 1);
        async Task<string> ReadAsync(System.IO.StreamReader reader)
        {
            var buffer = new StringBuilder();
            while (await reader.ReadLineAsync() is { } line)
            {
                buffer.AppendLine(line);
                if (streamOutput)
                {
                    await logLock.WaitAsync();
                    try { await log(line); }
                    finally { logLock.Release(); }
                }
            }
            return buffer.ToString();
        }
        var stdout = ReadAsync(process.StandardOutput);
        var stderr = ReadAsync(process.StandardError);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(
            policy == CommandCancellationPolicy.StopProcessTree ? cancellationToken : CancellationToken.None);
        if (timeout.HasValue && policy == CommandCancellationPolicy.StopProcessTree) stop.CancelAfter(timeout.Value);
        var timedOut = false;
        var cancelled = false;
        try
        {
            await process.WaitForExitAsync(stop.Token);
        }
        catch (OperationCanceledException)
        {
            cancelled = cancellationToken.IsCancellationRequested;
            timedOut = !cancelled;
            var descendants = CaptureDescendants(process.Id);
            try
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException) when (process.HasExited) { }
            catch (Exception ex)
            {
                await log($"Süreç durdurulamadı; çıkışı bekleniyor: {ex.Message}");
            }
            await process.WaitForExitAsync(CancellationToken.None);
            foreach (var child in descendants)
            {
                using (child)
                {
                    try
                    {
                        if (!child.HasExited) child.Kill(entireProcessTree: true);
                    }
                    catch (InvalidOperationException) { }
                    catch (System.ComponentModel.Win32Exception ex)
                    {
                        await log($"Alt süreç durdurulamadı; kapanması bekleniyor: {ex.Message}");
                    }
                    await child.WaitForExitAsync(CancellationToken.None);
                }
            }
        }
        var output = (await stdout) + (await stderr);
        if (cancelled) throw new OperationCanceledException(cancellationToken);
        if (timedOut)
        {
            var message = $"{displayCommand} zaman aşımına uğradı. Süreç sonlandırıldı.";
            await log(message);
            return new CommandResult(displayCommand, -1, output + Environment.NewLine + message, false);
        }
        if (process.ExitCode != 0) await log($"{displayCommand}: çıkış kodu {process.ExitCode}.");
        return new CommandResult(displayCommand, process.ExitCode, output, process.ExitCode == 0);
    }

    private static List<Process> CaptureDescendants(int parentId)
    {
        var result = new List<Process>();
        if (!OperatingSystem.IsWindows()) return result;
        using var snapshot = CreateToolhelp32Snapshot(2, 0);
        if (snapshot.IsInvalid) return result;
        var entry = new ProcessEntry { Size = (uint)Marshal.SizeOf<ProcessEntry>() };
        var pairs = new List<(int Id, int Parent)>();
        if (Process32First(snapshot, ref entry))
            do { pairs.Add(((int)entry.Id, (int)entry.ParentId)); } while (Process32Next(snapshot, ref entry));
        var ids = new HashSet<int> { parentId };
        while (true)
        {
            var children = pairs.Where(x => ids.Contains(x.Parent) && !ids.Contains(x.Id)).ToList();
            if (children.Count == 0) break;
            foreach (var child in children)
            {
                ids.Add(child.Id);
                try
                {
                    var process = Process.GetProcessById(child.Id);
                    _ = process.Handle;
                    result.Add(process);
                }
                catch (ArgumentException) { }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception) { }
            }
        }
        return result;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry
    {
        public uint Size, Usage, Id;
        public UIntPtr Heap;
        public uint Module, Threads, ParentId;
        public int Priority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Exe;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", EntryPoint = "Process32FirstW", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(SafeFileHandle snapshot, ref ProcessEntry entry);
    [DllImport("kernel32.dll", EntryPoint = "Process32NextW", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(SafeFileHandle snapshot, ref ProcessEntry entry);
}
