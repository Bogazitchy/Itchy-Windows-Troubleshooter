using System.IO;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class LogService
{
    public string LogDirectory { get; }
    public string LogPath { get; }

    public LogService()
    {
        LogDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ITCHY",
            "WindowsTroubleshooter",
            "Logs");
        Directory.CreateDirectory(LogDirectory);
        LogPath = Path.Combine(LogDirectory, $"itchy-{DateTime.Now:yyyyMMdd}.log");
    }

    public void Write(string line)
    {
        File.AppendAllText(LogPath, line + Environment.NewLine);
    }
}
