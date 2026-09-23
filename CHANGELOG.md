# Changelog

## 1.4.0 - 2026-09-23

- Karşılaştırmalı dump analizi; doğrulanmış çökme adresi ve kanıt kaynağı ayrımı.
- Zayıf kanıt tekrarı için puan sınırı ve kanıta bağlı müdahale önerileri.
- Haricî vaka yalıtımı, EVTX ve JSON sürücü envanteri ekleme.
- Süreç ağacı iptali ve kesilemeyen onarımları bekleme politikası.
- Update/geri yükleme doğrulaması, CHKDSK birim seçimi, ağ yedeği ve TEMP önizlemesi.
- Eksik olay/ölçüm/DISM verisinin normal sonuçtan ayrılması.
- WPF bağımsız çekirdek, küçük pencere düzeni, 44 otomatik test.
- Yenilenen README ve teknik güvenlik notları.

Detaylar: [v1.4.0 sürüm notları](docs/releases/v1.4.0.md).

## 1.3.0 - 2026-07-16

### Added

- Bulgular icin 0-100 guven puani ve kanit korelasyonu.
- Disk/SMART, pagefile, dump ayari, Windows Bellek Tanilama, bekleyen yeniden baslatma ve DISM CheckHealth denetimleri.
- Uygulama ve raporlarda Saglik Denetimleri ile Tarama Kapsami bolumleri.
- Code Integrity ve Defender olaylarinda sorunlu modul/tehdit ayristirma.

### Improved

- Event Viewer taramasi WHEA, depolama, GPU, Kernel-PnP, surucu altyapisi, Code Integrity, Defender ve performans kanallariyla genisletildi.
- WHEA duzeltilmis/duzeltilemeyen olaylari, Kernel-Power sonuc kayitlari ve volmgr dump yazma hatalari ayri degerlendiriliyor.
- Kaynak kullanimi uc yerine bes orneklem ve ortalama islem yukuyla hesaplaniyor.
- Tek kaynakli ve eski olaylar daha dusuk guvenle puanlaniyor; yuzde 90 ustu sonuc dogrudan veya cok kaynakli kanit gerektiriyor.
- Kisa sonuc; bilesen, bulgu rolu, guncellik, tekrar, mavi ekran iliskisi ve ilk yapilacak islemi ayri gosteriyor.
- Uygulama, servis ve surucu hatalari bilesen bazinda gruplanarak tekrar eden kayitlar tek bulguda toplaniyor.
- Tarama asamasi arayuzde canli gosteriliyor ve bulgu seviye adlari Turkce sunuluyor.
- HTML raporda ilk uc bulgu acik, ham kayitlar kapali; hata ve Reliability kayitlari gruplanmis olarak gosteriliyor.
- HTML bulgularindan ilgili ham kanitlara tek tikla gecilip otomatik arama yapilabiliyor.
- Sistem Koruma sorgusuna kontrollu zaman asimi uygulaniyor ve bu ikincil sorgu genel taramanin tamamlanma yolundan ayriliyor.

## 1.2.0 - 2026-07-13

### Improved

- Uygulama genelinde daha okunakli, modern graphite tema.
- Ana gezinme, panel hiyerarsisi ve tarama kontrolleri yeniden duzenlendi.
- Buton, sekme, tablo, kaydirma cubugu ve durum renkleri iyilestirildi.
- Windows baslik cubugu karanlik temayla uyumlu hale getirildi.
- Sistem bilgileri tablosunda uzun donanim ve surucu adlarinin gorunurlugu artirildi.
- Sag tik menuleri tamamen karanlik ve yuksek kontrastli hale getirildi.

### Updated

- README ekran goruntuleri yeni arayuzle yenilendi.

## 1.1.0 - 2026-07-10

### Added

- WinDbg/KD/CDB tabanli derin minidump ve `MEMORY.DMP` analizi.
- Stop code, parametre, stack, surucu, process ve failure bucket ayristirma.
- WHEA, disk, NVMe, NTFS, GPU ve Kernel-PnP olay korelasyonu.
- Tekrarlayan dump kaynaklari icin guven seviyesi ve kok neden ozeti.
- Sekmeli, aranabilir ve yazdirilabilir HTML teknisyen raporu.
- Uygulama acilisinda otomatik sistem ve surucu envanteri.
- CPU/GPU sicakliklarini her dakika yenileme.
- Log, analiz metni ve tablolar icin sag tik kopyalama menuleri.

### Improved

- `ntoskrnl.exe` ve `ntkrnlmp.exe` artik tek basina asil neden kabul edilmiyor.
- Dump dosyasi yoksa veya okunamiyorsa Event Viewer stop code bilgisiyle aciklayici sonuc veriliyor.
- Buton, tablo ve metin kontrastlari daha okunabilir hale getirildi.
