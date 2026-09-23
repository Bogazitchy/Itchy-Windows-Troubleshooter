namespace ItchyWindowsTroubleshooter.Services;

public static class RepairScripts
{
    public const string ResultHelpers = """
        $steps = [System.Collections.Generic.List[object]]::new()
        function Add-Step($name, $ok, $detail) { $steps.Add([pscustomobject]@{Name=$name; Success=[bool]$ok; Detail=[string]$detail}) }
        function Finish-Repair($status) {
          [pscustomobject]@{ItchyRepair=$true; Status=$status; Steps=@($steps.ToArray())} | ConvertTo-Json -Depth 6 -Compress
          if ($status -eq 'Failed') { exit 1 }
          if ($status -eq 'Partial') { exit 2 }
          exit 0
        }
        """;

    public static string WindowsUpdateReset => ResultHelpers + "\n" + """
        $before = @{}
        $failed = $false
        try {
          foreach ($name in @('wuauserv','bits','cryptsvc')) {
            $service = Get-Service $name -ErrorAction Stop
            $before[$name] = $service.Status.ToString()
            Stop-Service $name -ErrorAction Stop
            (Get-Service $name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            Add-Step "Stop $name" $true 'Stopped'
          }
          $stamp = [guid]::NewGuid().ToString('N')
          foreach ($path in @("$env:SystemRoot\SoftwareDistribution", "$env:SystemRoot\System32\catroot2")) {
            if (!(Test-Path -LiteralPath $path)) { throw "Cache directory missing: $path" }
            $destination = "$path.itchy-$stamp"
            Rename-Item -LiteralPath $path -NewName ([IO.Path]::GetFileName($destination)) -ErrorAction Stop
            if (!(Test-Path -LiteralPath $destination) -or (Test-Path -LiteralPath $path)) { throw "Rename verification failed: $path" }
            Add-Step "Rename $path" $true $destination
          }
        } catch { $failed = $true; Add-Step 'Update reset' $false $_.Exception.Message }
        finally {
          foreach ($name in $before.Keys) {
            try {
              if ($before[$name] -eq 'Running') { Start-Service $name -ErrorAction Stop }
              (Get-Service $name).WaitForStatus($before[$name], [TimeSpan]::FromSeconds(30))
              Add-Step "Restore $name" $true (Get-Service $name).Status
            } catch { $failed=$true; Add-Step "Restore $name" $false $_.Exception.Message }
          }
        }
        if ($failed) { if (@($steps | Where-Object Success).Count -gt 0) { Finish-Repair 'Partial' }; Finish-Repair 'Failed' }
        Finish-Repair 'Succeeded'
        """;

    public static string Disk(string drive, bool repair, bool surface)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(drive, "^[A-Za-z]:$")) throw new ArgumentException("Geçersiz sürücü.", nameof(drive));
        return ResultHelpers + "\n" + $$"""
            $volume = Get-CimInstance Win32_Volume -Filter "DriveLetter='{{drive}}'" -ErrorAction Stop
            if (!$volume -or $volume.DriveType -ne 3 -or $volume.FileSystem -ne 'NTFS') { throw 'A local NTFS volume is required.' }
            """ + (repair ? $$"""

            $result = Invoke-CimMethod -InputObject $volume -MethodName Chkdsk -Arguments @{
              FixErrors=$true; ForceDismount=$false; RecoverBadSectors=${{surface.ToString().ToLowerInvariant()}}; OkToRunAtBootUp=$true
            } -ErrorAction Stop
            Add-Step 'Win32_Volume.Chkdsk' ($result.ReturnValue -in @(0,1)) "ReturnValue=$($result.ReturnValue)"
            if ($result.ReturnValue -eq 1) { Finish-Repair 'RestartRequired' }
            if ($result.ReturnValue -eq 0) { Finish-Repair 'Succeeded' }
            Finish-Repair 'Failed'
            """ : $$"""

            & chkdsk.exe '{{drive}}' /scan
            $code = $LASTEXITCODE
            Add-Step 'CHKDSK /scan' ($code -eq 0) "ExitCode=$code"
            if ($code -ne 0) { Finish-Repair 'Failed' }
            Finish-Repair 'Succeeded'
            """);
    }

    public static string NetworkReset => ResultHelpers + "\n" + """
        $directory = Join-Path $env:LOCALAPPDATA 'ITCHY\NetworkBackups'
        New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
        $path = Join-Path $directory ((Get-Date -Format yyyyMMdd-HHmmss) + '.json')
        $configuration = @{IP=@(Get-NetIPConfiguration -Detailed -ErrorAction Stop); DNS=@(Get-DnsClientServerAddress -ErrorAction Stop); Addresses=@(Get-NetIPAddress -ErrorAction Stop); Routes=@(Get-NetRoute -ErrorAction Stop)}
        $configuration | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
        Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop | Out-Null
        Add-Step 'Network backup' $true $path
        $failed=$false
        & ipconfig.exe /flushdns
        $code=$LASTEXITCODE; Add-Step 'flushdns' ($code -eq 0) "ExitCode=$code"; if ($code -ne 0) {$failed=$true}
        & netsh.exe winsock reset
        $code=$LASTEXITCODE; Add-Step 'winsock' ($code -eq 0) "ExitCode=$code"; if ($code -ne 0) {$failed=$true}
        & netsh.exe int ip reset
        $code=$LASTEXITCODE; Add-Step 'IP reset' ($code -eq 0) "ExitCode=$code"; if ($code -ne 0) {$failed=$true}
        if ($failed) { Finish-Repair 'Partial' }
        Finish-Repair 'RestartRequired'
        """;

    public const string TempPreview = """
        $cutoff=(Get-Date).AddDays(-7)
        $files=@()
        foreach ($root in @($env:TEMP, "$env:SystemRoot\Temp") | Select-Object -Unique) {
          $directory=Get-Item -LiteralPath $root -ErrorAction Stop
          if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse temp root not supported.' }
          $files += @(Get-ChildItem -LiteralPath $directory.FullName -File -Force -ErrorAction Stop |
            Where-Object { $_.LastWriteTime -lt $cutoff -and !($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
            Select-Object FullName,Length,@{N='WriteTicks';E={$_.LastWriteTimeUtc.Ticks}})
        }
        ConvertTo-Json -InputObject @($files) -Depth 3 -Compress
        """;

    public static string CleanTemp(string manifestBase64) => ResultHelpers + "\n" + $$"""
        $files = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{manifestBase64}}')) | ConvertFrom-Json
        $allowed = @($env:TEMP, "$env:SystemRoot\Temp") | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
        $removed=0; $skipped=0
        foreach ($file in $files) {
          try {
            $target=Get-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            $parent=Get-Item -LiteralPath $target.DirectoryName -Force -ErrorAction Stop
            if ($target.PSIsContainer -or $target.DirectoryName.TrimEnd('\') -notin $allowed -or
                ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                ($target.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                $target.LastWriteTimeUtc.Ticks -ne $file.WriteTicks -or $target.Length -ne $file.Length -or
                $target.LastWriteTime -ge (Get-Date).AddDays(-7)) { throw 'Preview no longer matches.' }
            Remove-Item -LiteralPath $target.FullName -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $target.FullName) { throw 'Deletion not verified.' }
            $removed++
          } catch { $skipped++; Add-Step $file.FullName $false $_.Exception.Message }
        }
        Add-Step 'Temp totals' ($skipped -eq 0) "Deleted=$removed; Skipped=$skipped"
        if ($skipped -gt 0) { Finish-Repair 'Partial' }
        Finish-Repair 'Succeeded'
        """;
}
