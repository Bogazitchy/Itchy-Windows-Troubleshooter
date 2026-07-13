<div align="center">

# ITCHY Windows Troubleshooter

**Windows 10/11 icin teknik servis teshisi, gelismis mavi ekran analizi ve paylasilabilir sistem raporlama araci.**

[![Release](https://img.shields.io/github/v/release/Bogazitchy/Itchy-Windows-Troubleshooter?display_name=tag&style=for-the-badge&color=3ba6ff)](https://github.com/Bogazitchy/Itchy-Windows-Troubleshooter/releases/latest)
![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?style=for-the-badge&logo=windows11&logoColor=white)
![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
[![Downloads](https://img.shields.io/github/downloads/Bogazitchy/Itchy-Windows-Troubleshooter/total?style=for-the-badge&color=35c58a)](https://github.com/Bogazitchy/Itchy-Windows-Troubleshooter/releases)

[**Son Surumu Indir**](https://github.com/Bogazitchy/Itchy-Windows-Troubleshooter/releases/latest) | [Hata Bildir](https://github.com/Bogazitchy/Itchy-Windows-Troubleshooter/issues) | [Kaynak Kodu Incele](#kaynak-koddan-derleme)

</div>

![ITCHY sistem bilgileri ekrani](docs/images/system-information.png)

## Neden ITCHY?

Windows mavi ekranlari genellikle tek bir kaynaktan anlasilmaz. `ntoskrnl.exe`, Kernel-Power 41 veya bos bir minidump klasoru tek basina kok neden degildir. ITCHY; dump, stack, surucu dosyasi, semboller ve ayni zamandaki Windows olaylarini birlikte degerlendirerek teknisyene kanitli ve guven seviyeli bir sonuc verir.

| Alan | ITCHY ne yapar? |
|---|---|
| Mavi ekran | Minidump ve `MEMORY.DMP` dosyalarini WinDbg sembolleriyle analiz eder |
| Kok neden | Stop code, stack, modul, process, failure bucket ve `.sys` surucusunu ayirir |
| Korelasyon | WHEA, disk, NVMe, NTFS, GPU, Kernel-PnP ve BugCheck olaylarini zamanla eslestirir |
| Sistem | Windows, anakart, CPU, RAM, GPU, disk, BIOS ve surucu envanterini gosterir |
| Sensor | Desteklenen cihazlarda CPU/GPU sicakliklarini her dakika yeniler |
| Rapor | Sekmeli, aranabilir HTML teknisyen raporu ve duz metin raporu uretir |
| Onarim | SFC, DISM, CHKDSK, ag, Update, Defender ve spooler araclarini kontrollu calistirir |

## Gelismis Mavi Ekran Motoru

![ITCHY mavi ekran analiz ekrani](docs/images/blue-screen-analysis.png)

1. `C:\Windows\Minidump`, `C:\Windows\MEMORY.DMP` veya elle secilen dump dosyasi bulunur.
2. Dosya butunlugu ve kernel dump basligi kontrol edilir; okunabilirse BugCheck kodu ve dort parametre cikarilir.
3. Microsoft WinDbg/KD/CDB ile `!analyze -v`, `.bugcheck`, `kv`, modul listesi ve blackbox verileri toplanir.
4. `Probably caused by`, `IMAGE_NAME`, `MODULE_NAME`, `PROCESS_NAME`, `FAILURE_BUCKET_ID`, `SYMBOL_NAME` ve stack adaylari ayristirilir.
5. `ntoskrnl.exe` tek basina asil neden kabul edilmez. Stack'teki anlamli surucu, dosya ureticisi ve tekrar eden dump sonuclari oncelenir.
6. Dump zamaninin +/-20 dakikasindaki WHEA, disk, GPU, NTFS ve guc olaylari eslestirilir.
7. Kullaniciya supheli bilesen, guven seviyesi, kanitlar ve onerilen islem gosterilir.

> Tek bir dump fiziksel donanimi her durumda kesin kanitlamaz. RAM, CPU, PCIe ve guc sorunlarinda guven seviyesi ile olay korelasyonu birlikte degerlendirilmelidir.

## Sekmeli Teknisyen Raporu

HTML rapor artik tek parca uzun bir sayfa degildir. Asagidaki sekmeler arasinda gecis yapilabilir ve aktif sekmede anlik arama yapilabilir:

- Genel Bakis
- Oncelikli Bulgular
- Mavi Ekran ve Dump
- Hata Kayitlari
- Guvenilirlik Gecmisi
- Sistem ve Suruculer
- Koruma ve Onarim
- Ham Uygulama Logu

Tablolar sabit baslikli ve kaydirilabilir yapidadir. Yazdirma veya PDF alma sirasinda butun sekmeler eksiksiz rapora eklenir.

## Sistem ve Surucu Envanteri

- Uygulama acildigi anda sistem bilgileri otomatik yuklenir.
- CPU ve GPU sicakliklari desteklenen cihazlarda 60 saniyede bir yenilenir.
- BIOS, ekran karti, chipset ve depolama denetleyicisi surum/tarih bilgileri listelenir.
- Loglar, analiz metinleri ve tablolar sag tik menusuyle panoya kopyalanabilir.
- Surucu tarihleri kesin guncellik karari olarak sunulmaz; uretici sitesiyle karsilastirma notu verilir.

## Kurulum

1. [Releases](https://github.com/Bogazitchy/Itchy-Windows-Troubleshooter/releases/latest) sayfasini acin.
2. `ITCHY-Windows-Troubleshooter-v1.2.0-win-x64.exe` dosyasini indirin.
3. Uygulamayi calistirin. Korunan dump dosyalari ve sistem onarimlari icin **Yonetici olarak calistir** secenegini kullanin.
4. Tam sembol/stack analizi icin Mavi Ekran sekmesindeki **WinDbg Kur / Guncelle** dugmesini kullanin.

Yayin EXE'si self-contained olarak hazirlanir; ayri bir .NET kurulumu gerektirmez. Uygulama kod imzali degilse Windows SmartScreen ilk acilista ek onay gosterebilir.

## Guvenlik ve Gizlilik

- Analiz verileri bilgisayarda yerel olarak islenir.
- Telemetri veya otomatik log yukleme mekanizmasi yoktur.
- Semboller yalnizca Microsoft public symbol server uzerinden indirilir.
- Registry cleaner, kontrolsuz surucu silme veya tek tik hizlandirma islemi yoktur.
- Kritik onarimlar kullanici onayi olmadan calismaz.

## Kaynak Koddan Derleme

Gereksinimler: Windows 10/11 ve [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```powershell
git clone https://github.com/Bogazitchy/Itchy-Windows-Troubleshooter.git
cd Itchy-Windows-Troubleshooter
dotnet restore
dotnet build -c Release
```

Tek dosyalik self-contained Windows x64 paketi:

```powershell
dotnet publish -p:PublishProfile=ReleaseWinX64
```

Yayin dosyasi `bin\Release\single-file\ITCHY Windows Troubleshooter.exe` yolunda olusur.

## Proje Yapisi

```text
Models/                         Veri modelleri
Services/AdvancedDumpAnalysis  WinDbg, stop code, stack ve korelasyon motoru
Services/SystemAnalysis        Event Viewer ve genel teshis kurallari
Services/SystemInventory       Sistem, BIOS ve surucu envanteri
Services/HardwareSensor        CPU/GPU sensorleri
Services/ReportService         Sekmeli HTML/TXT rapor motoru
MainWindow.xaml                WPF kullanici arayuzu
```

## Katki

Hata kaydi veya gelistirme onerisi icin [Issues](https://github.com/Bogazitchy/Itchy-Windows-Troubleshooter/issues) bolumunu kullanabilirsiniz. Bir hata bildirirken mumkunse HTML teknisyen raporunu, Windows surumunu ve sorunun olustugu saati ekleyin; raporu herkese acik alana yuklemeden once kisisel bilgileri kontrol edin.

---

<div align="center">
  Windows sorunlarini tahminle degil, kanitla daraltmak icin gelistirildi.
</div>
