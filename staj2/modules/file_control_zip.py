# -*- coding: utf-8 -*-
# ==============================================================================
# DOSYA YÖNETİMİ VE ARŞİVLEME MODÜLÜ (file_control_zip.py)
# Bu modül log dosyalarının boyutunu denetler, eşik aşıldığında dosyaları ZIP formatında arşivler
# ve eski arşiv ZIP dosyalarını temizler (Retention Policy).
# ==============================================================================

import config  # Ayarlar için config modülü
import shutil  # Dosya sıkıştırma ve arşivleme için shutil
import time    # Zaman işlemleri için time
import os      # Dosya ve dizin yönetimi için os
import glob    # Dosya arama kalıpları için glob

class FileManager:
    def __init__(self, file_path=None):
        # Arşivlenecek hedef log dosyasının yolunu saklar
        self.file_path = file_path or getattr(config, 'LINUX_APP_LOG_PATH', 'app.log')

    def clean_old_zips(self, days=30):
        # Belirtilen günden (Varsayılan: 30 gün) daha eski olan arşiv `.zip` dosyalarını temizler
        try:
            now = time.time()
            cutoff_seconds = days * 86400 # Gün bilgisini saniyeye çevirir
            
            zip_files = glob.glob("*_firewall.zip")
            for zfile in zip_files:
                file_age = now - os.path.getmtime(zfile)
                if file_age > cutoff_seconds:
                    os.remove(zfile) # Eski zip dosyasını siler
                    print(f"[*] [Old Archive Cleaned] Purged {zfile} (older than {days} days)")
        except Exception as e:
            print(f"[-] Archive Cleanup Error: {e}")

    def zip_file_and_delete_dump(self, file_path):
        # Log dosyasını zaman damgalı ZIP olarak arşivler ve orijinal dosyayı sıfırlar/siler
        if not file_path or not os.path.exists(file_path):
            return

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        file_name = f"{timestamp}_firewall"
        base_dir = os.path.basename(file_path)
        root_dir = os.path.dirname(file_path) or "."
        
        try:
            shutil.make_archive(file_name, "zip", root_dir, base_dir)
            
            with open(file_path, "w") as f:
                f.write("") # Log dosyasının içini boşaltır
                
            print(f"[+] [Log Archived] {file_path} -> compressed into {file_name}.zip and cleared.")
        except Exception as e:
            print(f"[-] Archiving Error: {e}")

    def file_size_control(self, file_path):
        # Dosya boyutunun eşik değerini (MB) aşıp aşmadığını denetler
        if not file_path or not os.path.exists(file_path):
            return
            
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        threshold = getattr(config, 'FILE_SIZE_THRESHOLD', 5) # Varsayılan: 5 MB

        if file_size_mb > threshold:
            print(f"[!] Log File Size Threshold Exceeded ({file_size_mb:.2f} MB > {threshold} MB). Archiving...")
            self.zip_file_and_delete_dump(file_path)

    def start(self):
        # Dosya Yöneticisi Servisini Başlatır
        print(f"[+] File Manager Service Started: {time.ctime()}")
        
        while True:
            try:
                self.file_size_control(self.file_path) # Dosya boyutunu denetler
                self.clean_old_zips(days=30)           # 30 günden eski arşivleri temizler
            except Exception as e:
                print(f"[-] File Manager Error: {e}")
            
            time.sleep(2)