# -*- coding: utf-8 -*-
# ==============================================================================
# NETWORK MONİTÖR MODÜLÜ (network_monitor.py)
# Bu modül ağ bant genişliği kullanımını (MB/s) ve ağ donanım hatalarını/paket düşmelerini takip eder.
# ==============================================================================

import psutil  # Ağ I/O sayaçları ve hata sayıları için psutil
import time    # Zaman hesaplamaları ve beklemeler için time
import config  # Ağ eşik değerleri için config modülü

class NetworkMonitor:
    def __init__(self, callback=None):
        # Olay uyarısı tetikleyici callback fonksiyonu
        self.callback = callback

    def get_network_bandwidth(self):
        # Anlık indirme (Download) ve yükleme (Upload) bant genişliğini (MB/s) hesaplar
        try:
            net_first = psutil.net_io_counters() # İlk ağ istatistikleri
            interval = getattr(config, 'CHECK_INTERVAL_SECONDS', 2)
            time.sleep(interval)                 # İki ölçüm arasındaki saniye
            net_last = psutil.net_io_counters()  # İkinci ağ istatistikleri

            if not net_first or not net_last:
                return 0.0, 0.0

            bytes_recv = net_last.bytes_recv - net_first.bytes_recv
            bytes_sent = net_last.bytes_sent - net_first.bytes_sent

            download_speed_mb = (bytes_recv / (1024 * 1024)) / interval
            upload_speed_mb = (bytes_sent / (1024 * 1024)) / interval

            return download_speed_mb, upload_speed_mb
        except Exception:
            return 0.0, 0.0

    def get_network_hardware_errors(self):
        # Ağ kartı seviyesindeki paket hatalarını ve paket düşmelerini (drop) döndürür
        try:
            errors = psutil.net_io_counters()
            return {
                "incoming_errors": errors.errin,   # Gelen paket hataları
                "outgoing_errors": errors.errout,  # Giden paket hataları
                "incoming_drops": errors.dropin,   # Düşen gelen paketler
                "outgoing_drops": errors.dropout   # Düşen giden paketler
            }
        except Exception:
            return {"incoming_errors": 0, "outgoing_errors": 0, "incoming_drops": 0, "outgoing_drops": 0}

    def check_network_usage(self):
        # İndirme ve yükleme hızlarını hesaplar
        download_speed, upload_speed = self.get_network_bandwidth()
        total_bandwidth = download_speed + upload_speed
        
        threshold = getattr(config, 'INTERNET_BANDWITH_USAGE_THRESHOLD', 100)

        # Toplam bant genişliği kullanımı eşik değeri aşarsa uyarı verir
        if total_bandwidth > threshold:
            msg = f"Excessive Network Bandwidth Usage! Total: {total_bandwidth:.2f} MB/s (Download: {download_speed:.2f} MB/s, Upload: {upload_speed:.2f} MB/s)"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("HIGH_NETWORK_BANDWIDTH", "NETWORK", msg)

        # Ağ donanım paket düşmesi/hata uyarısı
        hw_errors = self.get_network_hardware_errors()
        if hw_errors["incoming_drops"] > 100 or hw_errors["incoming_errors"] > 50:
            msg = f"Network Hardware Packet Drops / Errors Detected: {hw_errors}"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("NETWORK_HARDWARE_ERROR", "NETWORK", msg)

    def start(self):
        # Ağ İzleme Servisini Başlatır
        print(f"[+] Network Monitoring Service Started: {time.ctime()}")
        
        # Kesintisiz izleme döngüsü
        while True:
            try:
                self.check_network_usage() # Ağ kullanımını analiz eder
            except Exception as e:
                print(f"[-] Network Monitoring Error: {e}")
