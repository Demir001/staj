# -*- coding: utf-8 -*-
# ==============================================================================
# CPU MONİTÖR VE YÖNETİM MODÜLÜ (cpu_info.py)
# Bu modül İşlemci (CPU) toplam kullanımı, çekirdek bazlı yük, frekans ve IOWait darboğazlarını takip eder.
# ==============================================================================

import psutil  # CPU istatistikleri ve süreç takibi için psutil
import time    # Zaman döngüleri ve beklemeler için time
import config  # CPU eşik değerleri için config modülü

class CPU_Manager():
    def __init__(self, callback=None):
        # Uyarı durumunda tetiklenecek geri bildirim fonksiyonu
        self.callback = callback

    def get_top_process_cpu(self):
        # En çok CPU tüketen sürecin (process) adını bulur
        try:
            procs = sorted(
                psutil.process_iter(['name', 'cpu_percent']),
                key=lambda p: p.info['cpu_percent'] or 0,
                reverse=True
            )
            return procs[0].info['name'] if procs else "Unknown"
        except Exception:
            return "Unknown"

    def get_cpu_iowait(self):
        # CPU'nun diski beklerken harcadığı zaman yüzdesini (IOWait) hesaplar
        try:
            cpu_t = psutil.cpu_times_percent(interval=1)
            return getattr(cpu_t, 'iowait', 0.0) # Linux dışındaki sistemlerde iowait 0.0 döner
        except Exception:
            return 0.0

    def Get_CPU_INFO(self):
        # Genel CPU kullanım yüzdesini ölçer
        cpu_usage = psutil.cpu_percent(interval=1)
        
        # CPU frekans bilgilerini alır (current, min, max)
        cpu_frequency = psutil.cpu_freq() 
        current_freq = cpu_frequency.current if cpu_frequency else 0.0

        # Çekirdek bazlı CPU kullanım yüzdelerini alır
        cpu_per_core = psutil.cpu_percent(interval=1.0, percpu=True)
        core_threshold = getattr(config, 'CPU_USAGE_BY_CORE_THRESHOLD', 95.0)

        # 1. Çekirdek Aşırı Yükleme Kontrolü
        for i in range(len(cpu_per_core)):
            if cpu_per_core[i] > core_threshold:
                msg = f"CPU Core {i} Overloaded! Utilization: {cpu_per_core[i]:.1f}%"
                print(f"[!] {msg}")
                if self.callback:
                    self.callback("CPU_CORE_OVERLOAD", f"Core_{i}", msg)

        # 2. Genel CPU Kullanım Eşiği Kontrolü
        cpu_threshold = getattr(config, 'CPU_USAGE_THRESHOLD', 85.0)
        if cpu_usage > cpu_threshold:
            top_process = self.get_top_process_cpu()
            msg = f"High Overall CPU Usage! Utilization: {cpu_usage:.1f}% | Top Process: {top_process}"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("HIGH_CPU_USAGE", "CPU", msg)

        # 3. CPU IOWait Darboğaz Kontrolü
        cpu_iowait = self.get_cpu_iowait()
        iowait_threshold = getattr(config, 'CPU_IOWAIT_THRESHOLD', 20.0)
        if cpu_iowait > iowait_threshold:
            msg = f"CPU IOWait Bottleneck Detected! IOWait: {cpu_iowait:.1f}%"
            print(f"[!] {msg}")
            if self.callback:
                self.callback("CPU_IOWAIT_BOTTLENECK", "CPU", msg)

    def start(self):
        # CPU İzleme Servisini Başlatır
        print(f"[+] CPU Monitoring Service Started: {time.ctime()}")
        
        # Sürekli izleme döngüsü
        while True:
            try:
                self.Get_CPU_INFO() # CPU verilerini analiz eder
            except Exception as e:
                print(f"[-] CPU Monitoring Error: {e}")
            
            # Belirlenen kontrol aralığı kadar bekler
            time.sleep(getattr(config, 'CHECK_INTERVAL_SECONDS', 2))