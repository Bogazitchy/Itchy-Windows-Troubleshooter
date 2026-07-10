$exe = Join-Path $PSScriptRoot 'bin\Release\net8.0-windows\win-x64\publish\ITCHY Windows Troubleshooter.exe'
if (-not (Test-Path $exe)) {
    $exe = Join-Path $PSScriptRoot 'bin\Debug\net8.0-windows\ITCHY Windows Troubleshooter.exe'
}

if (-not (Test-Path $exe)) {
    Write-Host 'Uygulama exe dosyasi bulunamadi. Once dotnet build veya dotnet publish calistirin.'
    exit 1
}

Start-Process -FilePath $exe -Verb RunAs
