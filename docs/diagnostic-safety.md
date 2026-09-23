# Teşhis Güvenilirliği ve Doğrulama

## Kanıt Sınırı

- Doğrudan modül eşleşmesi: bugcheck semantiğinden/ExceptionAddress alanından gelen adres dump içindeki `lm` modül aralığına düşer. Bu bir çökme konumudur; belleği daha önce bozan bileşeni her zaman kanıtlamaz.
- `Probably caused by` debugger değerlendirmesidir. IMAGE/MODULE yalnız ilişki; stack görünürlüğü yalnız varlık kanıtıdır.
- Assembly satırı exception adresiyle eşleşmelidir. Register bankındaki RIP de aynı adresi göstermelidir. Desteklenen pointer hesabı tek register ve sabit ofsettir; indeksli/segmentli ifadelerde hesap yapılmaz.
- Sembol eksiği aday gücünü düşürür. Eksik adres/modül aralığı tahmini bir doğrudan fault ile doldurulmaz.
- Skorlar deterministik kural ağırlıklarıdır, yüzde olasılık değildir. Adaylarda kural kimlikleri UI ve raporda saklanır. Aynı kuralın katkısı bir kez uygulanır.
- Pointer canonical aralık denetimi x64 48-bit adresleme varsayımıyla sınırlıdır; tek başına donanım arızası kanıtı değildir.

## Vaka Kaynakları

Haricî dump seçimi varsayılan olarak yerel olay korelasyonunu ve host sürücü metadata'sını kapatır. Olay eşleştirmesi yalnız WinDbg `Debug session time` alanı saat dilimiyle okunabildiğinde yapılır; `LastWriteTime` kullanılmaz.

Vaka araçlarından isteğe bağlı EVTX eklenebilir. Her dosyada en yeni 5000 kayıt sınırı vardır; sınır/erişim durumu işlem ayrıntılarında açıklanır. Dosyaların gerçekten aynı müşteriye ait olması kullanıcının sorumluluğundadır. Yeni dump seçimi önceki ekleri sıfırlar.

JSON sürücü envanteri, aşağıdaki nesnelerden oluşan bir dizi olmalıdır (en fazla 10 MB):

```json
[
  {
    "Category": "Graphics",
    "DeviceName": "nvlddmkm.sys",
    "Manufacturer": "NVIDIA",
    "DriverVersion": "örnek-sürüm",
    "DriverDate": "2026-01-01",
    "HardwareId": "",
    "Status": "Müşteri envanteri"
  }
]
```

Eşleştirme için DeviceName sürücü dosya adını taşımalıdır. Bu veri kullanıcı tarafından eklenen envanterdir; dump içinden doğrulanmış sürüm sayılmaz. Yerel modda okunan FileVersionInfo da çökme anındaki sürüm değil, mevcut dosya sürümüdür. Dump modül sürümleri otomatik olarak her dump türünde ayrıştırılmamaktadır.

## Onarım Güvenliği

- Tanılama iptalinde süreç ağacı sonlandırılır, yakalanan alt süreçler ve çıktı okuyucuları beklenir.
- SFC/RestoreHealth, Update/ağ reseti ve diğer değişiklik yapan işlemler başladıktan sonra kesilmez. UI yeni işlem veya kapanmaya izin vermez. Bu işlemlerde süre doldu diye zorla sonlandırma yapılmaz.
- Update reseti kritik hataları bastırmaz; klasör değişimini kontrol eder, servislerin önceki çalışma durumunu geri getirmeyi dener ve her adımı kaydeder.
- Geri yükleme noktası oluşturma öncesi/sonrası SequenceNumber farkı doğrulanır; sessizce atlanan oluşturma başarı sayılmaz.
- CHKDSK yalnız seçilen yerel NTFS biriminde çalışır. /f ve /r için WMI Chkdsk dönüş kodu 1 yeniden başlatmaya zamanlamayı bildirir. Bu, sonraki açılışta denetimin tamamlandığının kanıtı değildir.
- Ağ sıfırlama öncesi IP/DNS/adres/rota JSON yedeği `%LOCALAPPDATA%\ITCHY\NetworkBackups` altında oluşturulur. Uzak bağlantı kesilebilir. Yedek otomatik geri dönüş mekanizması değildir.
- TEMP temizliği yalnız önizlemede onaylanan, 7 günden eski kök dosyaları kapsar. Alt klasörler/reparse hedefleri silinmez; yaş, boyut ve değiştirilme zamanı tekrar kontrol edilir. Silinemeyen dosyalar ayrı sayılır.
- Postcondition doğrulaması olmayan eski komutlar, exit code 0 olsa bile “Komut tamamlandı; değişiklik doğrulanamadı” gösterir.

## Testler

```powershell
dotnet restore
dotnet build -c Release
dotnet test Tests\ItchyWindowsTroubleshooter.Tests.csproj -c Release
dotnet build Core\Itchy.Diagnostics.Core.csproj -c Release
```

Testler sentetik WinDbg çıktısı, sahte olay/kaynak verisi ve taklit onarım komutları kullanır. Süreç iptali testinde yalnız bekleyen PowerShell süreçleri oluşturulur ve kapatılır. Gerçek Update reseti, disk onarımı, ağ sıfırlama veya geri yükleme noktası oluşturma test sırasında çalıştırılmaz.

WPF testleri arka plan sistem sorgularını başlatmadan 1320×820, 1093×560 ve 910×470 DIP boyutlarında pencere içeriğini render eder. Görüntüler test çıktı klasöründeki `layout-artifacts` altında oluşur. Bu, farklı DPI kullanan fiziksel cihazda kullanıcı etkileşim testi yerine geçmez.

## Kalan Sınırlar

Gerçek müşteri dump'larıyla doğrulama, farklı Windows dillerinde onarımın tam yaşam döngüsü ve gerçek yüksek DPI cihaz testi ayrıca yapılmalıdır. Eski arayüz/teknik mesajların tamamı Türkçe karakter bakımından henüz elden geçirilmemiştir. Hiçbir skor “RAM kesin bozuk” veya “bu sürücü kesin suçlu” anlamına gelmez.

