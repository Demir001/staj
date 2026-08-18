# -*- coding: utf-8 -*-
# ==============================================================================
# DISK MONİTÖR MODÜLÜ (disk_monitor.py)
# Bu modül Disk okuma/yazma (I/O) hızlarını (MB/s) ve disk trafiği oluşturan uygulamaları izler.
# ==============================================================================

import psutil  # Disk I/O Sayaçları ve Süreç verileri için psutil
import time    # Zaman ölçümleri ve periyodik gecikme için time
import config  # Konfigürasyon ve eşik değerleri için config

class DiskMonitor:
    def __init__(self, callback=None):
        # Uyarı tetiklendiğinde çağrılacak callback fonksiyonu
        self.callback = callback

    def get_disk_io_speed(self):
        # Disk okuma ve yazma hızını (MB/s cinsinden) hesaplar
        try:
            io_first = psutil.disk_io_counters() # İlk Sayaç Ölçümü
            interval = getattr(config, 'CHECK_INTERVAL_SECONDS', 2)
            time.sleep(interval)                 # İki ölçüm arasındaki zaman aralığı
            io_last = psutil.disk_io_counters()  # İkinci Sayaç Ölçümü

            if not io_first or not io_last:
                return 0.0, 0.0

            read_bytes = io_last.read_bytes - io_first.read_bytes
            write_bytes = io_last.write_bytes - io_first.write_bytes

            read_speed_mb = (read_bytes / (1024 * 1024)) / interval
            write_speed_mb = (write_bytes / (1024 * 1024)) / interval

            return read_speed_mb, write_speed_mb
        except Exception:
            return 0.0, 0.0

    def get_top_disk_process(self):
        # En çok disk I/O (Okuma/Yazma) yapan süreci bulur
        try:
            procs = []
            for p in psutil.process_iter(['name', 'io_counters']):
                try:
                    io = p.info['io_counters']
                    if io:
                        total_bytes = io.read_bytes + io.write_bytes
                        procs.append((p.info['name'], total_bytes))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            procs.sort(key=lambda x: x[1], reverse=True)
            return procs[0][0] if procs else "Unknown"
        except Exception:
            return "Unknown"

    def check_disk_usage(self):
        # Disk okuma ve yazma hızlarını alır
        read_speed, write_speed = self.get_disk_io_speed()
        
        read_threshold = getattr(config, 'DISK_USAGE_READ_THRESHOLD', 100)  # MB/s
        write_threshold = getattr(config, 'DISK_USAGE_WRITE_THRESHOLD', 100) # MB/s

        # Disk Okuma Eşiği Aşımı Kontrolü
        if read_speed > read_threshold:
            top_process = self.get_top_disk_process()
            msg = f"High Disk Read Throughput! Speed: {read_speed:.2f} MB/s | Process: {top_process}"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("HIGH_DISK_READ", "DISK", msg)

        # Disk Yazma Eşiği Aşımı Kontrolü
        if write_speed > write_threshold:
            top_process = self.get_top_disk_process()
            msg = f"High Disk Write Throughput! Speed: {write_speed:.2f} MB/s | Process: {top_process}"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("HIGH_DISK_WRITE", "DISK", msg)

    def start(self):
        # Disk İzleme Servisi Başlatma Bilgisi
        print(f"[+] Disk Monitoring Service Started: {time.ctime()}")
        
        # Kesintisiz izleme döngüsü
        while True:
            try:
                self.check_disk_usage() # Disk kullanımını kontrol eder
            except Exception as e:
                print(f"[-] Disk Monitoring Error: {e}")
