# -*- coding: utf-8 -*-
# ==============================================================================
# SİSTEM VE GÜVENLİK YAPILANDIRMA DOSYASI (config.py)
# ==============================================================================

# 1. Eşik Değerleri (Sistem Kaynakları)
CPU_USAGE_THRESHOLD = 85.0              # İşlemci genel kullanım uyarı eşiği (%)
CPU_USAGE_BY_CORE_THRESHOLD = 95.0      # Çekirdek bazlı aşırı yüklenme eşiği (%)
CPU_IOWAIT_THRESHOLD = 20.0             # CPU Disk bekleme darboğaz eşiği (%)

RAM_USAGE_THRESHOLD = 85.0              # RAM bellek kullanım uyarı eşiği (%)
DISK_USAGE_READ_THRESHOLD = 100         # Disk okuma hızı uyarı eşiği (MB/s)
DISK_USAGE_WRITE_THRESHOLD = 100        # Disk yazma hızı uyarı eşiği (MB/s)
INTERNET_BANDWITH_USAGE_THRESHOLD = 100 # Ağ bant genişliği uyarı eşiği (MB/s)
GPU_USAGE_THRESHOLD = 85.0              # Ekran kartı (GPU) kullanım uyarı eşiği (%)

# 2. Dosya ve Arşivleme Ayarları
FILE_SIZE_THRESHOLD = 5                 # Log dosyası maksimum boyutu (MB)
CHECK_INTERVAL_SECONDS = 2              # Metrik kontrol sıklığı (Saniye)
LINUX_APP_LOG_PATH = "app.log"          # Uygulama log dosyası yolu

# 3. İzlenecek Gerçek Sistem ve Güvenlik Log Dosyaları (Çoklu Dosya İzleme)
SYSTEM_LOG_PATHS = [
    "/var/log/auth.log",      # Debian/Ubuntu SSH ve Kimlik Doğrulama Logları
    "/var/log/syslog",        # Debian/Ubuntu Sistem, Ağ ve Güvenlik Logları
    "/var/log/secure",        # RHEL/CentOS/Rocky Linux Güvenlik Logları
    "/var/log/messages",      # RHEL/CentOS Sistem Logları
    "/var/log/ufw.log",       # UFW Güvenlik Duvarı Paket Blok Logları
    "/var/log/kern.log",      # Çekirdek (Kernel) ve Donanım Logları
    "logs/auth.log",          # Yerel Test Auth Logu
    "logs/syslog"             # Yerel Test Syslog Logu
]

# 4. Oturum ve Eylemsizlik Zaman Aşımı (Auto-Kick)
IDLE_SESSION_TIMEOUT_SECONDS = 900      # 15 Dakika (900 saniye) eylemsiz oturumları otomatik kapatma

# 5. Güvenlik Riski ve Kayan Zaman Penceresi
RISK_SCORE_THRESHOLD = 50               # Banlama için gereken toplam kümülatif risk puanı
TIME_WINDOW = 600                       # Risk puanı hesaplama penceresi (10 Dakika / 600 sn)

# 6. Ağ Yapılandırması (İç Ağ vs. Dış Ağ)
INTERNAL_SUBNETS = [
    "127.0.0.0/8",       # Localhost loopback
    "10.0.0.0/8",        # Sınıf A Özel Ağ
    "172.16.0.0/12",     # Sınıf B Özel Ağ
    "192.168.0.0/16",    # Sınıf C Özel Ağ
    "169.254.0.0/16"     # Link-Local Ağ
]

PROTECTED_IPS = [
    "127.0.0.1", "::1", "localhost", "192.168.1.1", "10.0.0.1" # Kilitlenmeyi önlemek için korunan IP'ler
]

# 7. İnsani Yazım Hatası (Typo) Tolerans Eşikleri
EXTERNAL_MAX_TYPOS = 3                  # Dış ağ için tolere edilen azami yazım hatası (1-3 arası banlanmaz)
INTERNAL_MAX_TYPOS = 5                  # İç ağ çalışanları için tolere edilen azami yazım hatası (1-5 arası banlanmaz)
TYPO_TIME_INTERVAL_SECONDS = 3.0        # İnsani yazım hızı sınırı (3 saniyeden yavaş denemeler insani kabul edilir)

# 8. Kritiklik Düzeyine Göre Kademeli Ban Süreleri (Saniye Cinsinden)
BAN_DURATIONS_EXTERNAL = {
    "CRITICAL": 3600,                   # 60 Dakika (Ters shell, C2, bellek enjeksiyonu, root silme)
    "HIGH": 1800,                       # 30 Dakika (Zero-Day anomali, SQLi, RCE, port tarayıcı)
    "MEDIUM": 600,                      # 10 Dakika (Kasıtlı Brute-force, protokol ihlali)
    "LOW": 0                            # 0 Dakika (İnsani yazım hatası, hafif uyarı - ban yok)
}

BAN_DURATIONS_INTERNAL = {
    "CRITICAL": 900,                    # 15 Dakika (Oturum kapatma ve SSH izolasyonu)
    "HIGH": 300,                        # 5 Dakika (Geçici servis kısıtlaması)
    "MEDIUM": 180,                      # 3 Dakika (Hız sınırlama / geçici kısıtlama)
    "LOW": 0                            # 0 Dakika (İnsani yazım hatası - ban yok)
}

# 9. E-posta Bildirim Ayarları
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your_email@gmail.com"
RECEIVER_EMAIL = "admin@example.com"
EMAIL_PASSWORD = "your_app_password"