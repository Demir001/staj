# -*- coding: utf-8 -*-
# ==============================================================================
# RAM MONİTÖR MODÜLÜ (ram_monitor.py)
# Bu modül sistemdeki RAM kullanım oranını ve en çok RAM tüketen süreçleri takip eder.
# ==============================================================================

import psutil  # Sistem kaynaklarını ve süreçlerini izlemek için psutil kütüphanesi
import time    # Zaman gecikmeleri ve döngü beklemeleri için time kütüphanesi
import config  # Konfigürasyon ve eşik değerlerini almak için config modülü

class RamMonitor:
    def __init__(self, callback=None):
        # Uyarı durumlarında tetiklenecek geri bildirim (callback) fonksiyonunu saklar
        self.callback = callback

    def get_top_process_ram(self):
        # En yüksek RAM tüketimine sahip olan sürecin (process) adını bulur
        try:
            procs = sorted(
                psutil.process_iter(['name', 'memory_percent']),
                key=lambda p: p.info['memory_percent'] or 0,
                reverse=True
            )
            return procs[0].info['name'] if procs else "Unknown"
        except Exception:
            return "Unknown"

    def check_ram_usage(self):
        # Anlık RAM kullanım yüzdesini alır
        ram_usage = psutil.virtual_memory().percent
        
        # Konfigürasyondaki eşik değerini alır (Varsayılan: %85.0)
        threshold = getattr(config, 'RAM_USAGE_THRESHOLD', 85.0)

        # Eğer RAM kullanımı belirlenen eşik değerini aşarsa uyarı tetikler
        if ram_usage > threshold:
            top_process = self.get_top_process_ram() # En çok RAM harcayan uygulamayı bulur
            msg = f"High RAM Usage Detected! Utilization: {ram_usage:.1f}% | Top Process: {top_process}"
            print(f"[!] {msg}") # Konsola bilgi mesajı basar
            
            # Callback tanımlanmışsa ana sisteme uyarı olayını gönderir
            if self.callback:
                self.callback("HIGH_RAM_USAGE", "RAM", msg)

        return ram_usage

    def start(self):
        # RAM izleme servisini başlatır ve zaman damgalı bilgilendirme basar
        print(f"[+] RAM Monitoring Service Started: {time.ctime()}")
        
        # Arka planda sürekli çalışacak olan izleme döngüsü
        while True:
            try:
                self.check_ram_usage() # RAM kullanımını kontrol eder
            except Exception as e:
                print(f"[-] RAM Monitoring Error: {e}")
            
            # Belirlenen kontrol aralığı kadar bekler (Varsayılan: 2 saniye)
            time.sleep(getattr(config, 'CHECK_INTERVAL_SECONDS', 2))
