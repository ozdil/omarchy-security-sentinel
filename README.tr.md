# Security Sentinel Hub - Omarchy Linux İçin Bütünleşik Siber Savunma ve Gizlilik Merkezi

[![Omarchy Verified Plugin](https://img.shields.io/badge/Omarchy-Verified_Plugin-22c55e?style=for-the-badge&logo=omarchy)](https://github.com/ozdil)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-Support_Development-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/ozdil)

Omarchy Linux için hepsi bir arada yerel siber savunma, donanım bütünlüğü denetçisi ve gizlilik koruma eklentisi.

Geliştirici: Ozan Özdil (ozdil)  
Lisans: MIT  
Eklenti Kimliği: ozdil.security-sentinel  

---

## Genel Bakış

Security Sentinel Hub, 8 temel Linux savunma ve gizlilik alt sistemini tek bir yüksek başarımlı yerel Rust servisinde (`sentinel-engine`) ve temayla uyumlu Quickshell arayüzünde birleştirir.
HANCORE Kurumsal Askeri Güvenlik Standartları, çekirdek seviyesinde sıfır güven politikaları, sınırlandırılmış IPC süreçleri ve gerçek zamanlı donanım bütünlüğü doğrulaması sunar.

---

## Alt Sistemler ve Yetenekler

1. Ağ ve Soket Radarı: Gerçek zamanlı soket izleme (`/proc/net/tcp*`, `/proc/net/udp*`), şüpheli port tespiti ve dinleme yapan servislerin anlık dökümü.
2. BadUSB Koruması & Donanım Zırhı: Donanım HID cihaz izleme (`/sys/bus/usb/devices`), kriptografik güvenli USB taban çizgisi (`trusted_usb.json`) ve Rubber Ducky saldırılarına karşı anlık donanım zırhı kilitlemesi.
3. CVE Zafiyet Radarı: Yerel paket güvenlik denetimi ve Arch Security Tracker ile senkronize güvenlik açığı analizi.
4. Kimlik Doğrulama Nöbetçisi: Systemd journald ve PAM üzerinden son 24 saatteki başarısız giriş ve yetkisiz SSH denemelerini izleme.
5. Tuzak Dosyalar (Tripwire Canaries) & Öz Savunma: Fidye yazılımlarına karşı bal küpü dosyaları, SHA-256 bütünlük kontrolü ve `prctl(PR_SET_DUMPABLE, 0)` ile süreç döküm koruması.
6. DNS Sızıntı Kalkanı (DoT): Şifreli Cloudflare DNS-over-TLS (DoT 1.1.1.1) entegrasyonu ile İSS düzeyinde açık metin gözetlemeyi önleme.
7. Hayalet MAC ve Ağ İzolasyonu: Ağ bağdaştırıcıları için anlık rastgele MAC adresi atama ve acil durum ağ karartması (Panic Blackout).
8. Yapay Zekalı Anomali Analizi: DGA sınıflandırma ve süreç anomali puanlaması ile sıfırıncı gün tehditlerini algılama.

---

## Gereksinimler

- cargo ve rustc (Rust derleme zinciri)
- quickshell (Arayüz kabuğu)

---

## Kurulum ve Derleme

```bash
# Eklenti dizinine gidin
cd ~/.config/omarchy/plugins/ozdil.security-sentinel

# Motoru derleyin
cargo build --release

# İkiliyi kurun
install -m 755 target/release/sentinel-engine ./sentinel-engine
install -m 755 target/release/sentinel-engine ~/.local/bin/sentinel-engine
```

---

## Doğrulama ve Testler

```bash
# Birim ve çekirdek testlerini çalıştırın
cargo test

# Omarchy eklenti doğrulamasını çalıştırın
omarchy plugin validate .
```
