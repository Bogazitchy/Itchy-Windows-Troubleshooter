using System.Diagnostics;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class ShortcutService
{
    public IReadOnlyList<ShortcutItem> GetShortcuts()
    {
        return
        [
            new("Aygit Yoneticisi", "devmgmt.msc", "Surucu ve donanim durumlarini acar."),
            new("Olay Goruntuleyicisi", "eventvwr.msc", "Windows loglarini detayli incelemek icin."),
            new("Guvenilirlik Gecmisi", "perfmon /rel", "Cokme ve hata zaman cizelgesini acar."),
            new("Performans Izleyicisi", "perfmon.msc", "Performans sayaclarini ve veri toplayicilari acar."),
            new("Kaynak Izleyicisi", "resmon.exe", "CPU, disk, ag ve bellek kullanimini gosterir."),
            new("Hizmetler", "services.msc", "Windows servislerini listeler."),
            new("Disk Yonetimi", "diskmgmt.msc", "Disk bolumlerini ve suruculeri yonetir."),
            new("Gorev Yoneticisi", "taskmgr.exe", "Calisan uygulama ve baslangic etkisini gosterir."),
            new("Sistem Yapilandirmasi", "msconfig.exe", "Baslangic ve servis tanilama ayarlarini acar."),
            new("Ag Baglantilari", "ncpa.cpl", "Ag bagdastiricilarini acar."),
            new("Programlar ve Ozellikler", "appwiz.cpl", "Kurulu programlari listeler."),
            new("Sistem Koruma", "SystemPropertiesProtection.exe", "Geri yukleme ayarlarini acar."),
            new("Windows Bellek Tanilama", "mdsched.exe", "RAM tanilama aracini baslatir."),
            new("Windows Update", "ms-settings:windowsupdate", "Windows Update ayarlarini acar."),
            new("Baslangic Uygulamalari", "ms-settings:startupapps", "Baslangic uygulamalarini acar."),
            new("Gelismis Sistem Ozellikleri", "sysdm.cpl", "Sistem ozellikleri ve dump ayarlarini acar.")
        ];
    }

    public void Open(string command)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c start \"\" {command}",
            UseShellExecute = false,
            CreateNoWindow = true
        });
    }
}
