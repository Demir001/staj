# -*- coding: utf-8 -*-
# ==============================================================================
# ANA ÇALIŞTIRMA SİSTEMİ (main.py)
# Bu dosya tüm izleme modüllerini, Çok Katmanlı Yapay Zeka Güvenlik Motorunu (Dual-AI),
# Akıllı Loglayıcıyı, 10 Dakikalık Geçici Ban Yöneticisini ve
# 15 Dakikalık Oturum Eylemsizlik Takip Servisini (Auto-Kick) başlatır.
# ==============================================================================

import threading  # Modülleri eşzamanlı (paralel) arka planda çalıştırır
import time       # Zaman gecikmeleri için time
import config     # Konfigürasyon ayarları için config

# 1. Modül İçe Aktarımları
from modules.smart_logger import SmartLogger                 # Akıllı Anlaşılır Loglama Motoru
from modules.ban_manager import BanManager                   # 10 Dakikalık Geçici Ban & Oto-Unban Yöneticisi
from modules.ai_security_engine import AISecurityEngine     # Çok Katmanlı Yapay Zeka Güvenlik Motoru
from modules.user_session_tracker import UserSessionTracker   # Oturum Eylemsizlik & Komut Takip Yöneticisi
from modules.log_monitor import LogMonitor                  # Güvenlik logları ve tehdit izleme
from modules.cpu_info import CPU_Manager                    # İşlemci (CPU) ve çekirdek izleme
from modules.ram_monitor import RamMonitor                  # RAM ve bellek tüketen süreç izleme
from modules.disk_monitor import DiskMonitor                # Disk okuma/yazma hızı izleme
from modules.network_monitor import NetworkMonitor          # Ağ bant genişliği ve donanım izleme
from modules.gpu_control import Gpu_Controller              # GPU/TPU kaynak izleme
from modules.file_control_zip import FileManager            # Log boyutu ve otomatik zip arşivleme
from modules.db_manager import DataBaseManager              # SQLite Veritabanı yöneticisi
from modules.alert import Alert                             # E-posta bildirim servisi

# Global Nesneler
logger = SmartLogger()                                        # Akıllı Anlaşılır Loglama Yöneticisi
ban_man = BanManager(logger=logger)                          # 10 Dakikalık Ban & Oto-Unban Yöneticisi
ai_engine = AISecurityEngine()                               # Çok Katmanlı Yapay Zeka Motoru
session_tracker = UserSessionTracker(logger=logger, ai_engine=ai_engine) # Oturum & Komut Takibi
db_man = DataBaseManager(database_name="security_events.db") # Veritabanı yöneticisi örneği
alert_service = Alert()                                       # E-posta alarm servisi örneği

def alert_handler(event_type, target, message):
    # Tüm izleme modüllerinden gelen olayların düştüğü MERKEZİ AKILLI ALARM HANDLER
    level = "INFO"
    if "ADVANCED_THREAT" in event_type or "AI_ATTACK" in event_type or "AI_ZERO_DAY" in event_type or "ROOT" in event_type or "SPOOFING" in event_type or "BAN" in event_type or "KICKED" in event_type:
        level = "CRITICAL"
    elif "HIGH_" in event_type or "OVERLOAD" in event_type or "IDLE" in event_type:
        level = "WARNING"
    elif "ATTEMPT" in event_type or "BLOCK" in event_type:
        level = "ALERT"

    # Akıllı Loglayıcı İle Anlaşılır İngilizce Formatında Kaydeder
    logger.log_event(level=level, module="SIEM_MONITOR", event_type=event_type, target=target, details=message)

    # Güvenli vs Zararlı Durumunu Belirle
    status_tag = logger.determine_operation_status(level, event_type)

    # Konsola Temiz Okunabilir İletiyi Basar
    print(f"[{level}] [{status_tag}] [{event_type}] Target: {target} | {message}")

    # E-posta Uyarısı
    if level in ["ALERT", "CRITICAL"]:
        try:
            alert_service.send_alert(f"Subject: SIEM ALERT [{level}] - {event_type}\n\n{message}")
        except Exception:
            pass

if __name__ == "__main__":
    print("=================================================================")
    print("  SECURITY AND SYSTEM MONITORING SERVICE (SIEM) INITIALIZING    ")
    print("=================================================================")

    # A. Veritabanını ve Akıllı Loglayıcıyı Başlat
    db_man.start()
    logger.log_event("INFO", "SYSTEM", "SYSTEM_START", "LOCAL", "SIEM Monitoring Service Initialized.")

    # B. Çok Katmanlı Yapay Zeka Güvenlik Modellerini Hafızaya Yükle
    ai_engine.load_all_models()

    # C. Tüm Modül Nesnelerini Tanımla
    log_mon = LogMonitor(callback=alert_handler, ban_manager=ban_man, session_tracker=session_tracker, ai_engine=ai_engine)
    cpu_mon = CPU_Manager(callback=alert_handler)       # CPU İzleme
    ram_mon = RamMonitor(callback=alert_handler)       # RAM İzleme
    disk_mon = DiskMonitor(callback=alert_handler)     # Disk İzleme
    net_mon = NetworkMonitor(callback=alert_handler)   # Ağ İzleme
    gpu_mon = Gpu_Controller(callback=alert_handler)   # GPU İzleme
    file_man = FileManager(file_path=config.LINUX_APP_LOG_PATH) # Arşivleme

    # D. Modülleri Arka Planda Paralel Thread'ler Olarak Başlat
    threading.Thread(target=session_tracker.start, daemon=True).start() # 15 Dk Eylemsizlik Auto-Kick Thread'i
    threading.Thread(target=ban_man.start, daemon=True).start()          # Ban Süre Denetim & Oto-Unban Thread'i
    threading.Thread(target=log_mon.start, daemon=True).start()          # Log İzleme Thread'i
    threading.Thread(target=cpu_mon.start, daemon=True).start()          # CPU İzleme Thread'i
    threading.Thread(target=ram_mon.start, daemon=True).start()          # RAM İzleme Thread'i
    threading.Thread(target=disk_mon.start, daemon=True).start()         # Disk İzleme Thread'i
    threading.Thread(target=net_mon.start, daemon=True).start()          # Ağ İzleme Thread'i
    threading.Thread(target=gpu_mon.start, daemon=True).start()          # GPU İzleme Thread'i
    threading.Thread(target=file_man.start, daemon=True).start()         # Dosya Arşivleme Thread'i

    print("\n[+] All Monitoring Services, Dual-AI Engine, 10-Min Ban Manager, and 15-Min Auto-Kick Active!")
    print("[+] Human-readable logs are being saved to 'logs/readable_activity.log'.")
    print("[+] Press Ctrl+C to terminate the monitoring engine...\n")

    # E. Ana Programı Açık Tut ve Interrupt (Ctrl+C) Yakala
    try:
        while True:
            time.sleep(1) # Ana thread uykuda tutulur
    except KeyboardInterrupt:
        logger.log_event("INFO", "SYSTEM", "SYSTEM_STOP", "LOCAL", "SIEM Monitoring Service Terminated by User.")
        print("\n[*] Monitoring Service Terminated by User Request.")