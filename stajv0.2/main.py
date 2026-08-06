import threading
import time
from modules.log_monitor import LogMonitor
from modules.system_monitor import SystemMonitoring
from modules.file_control_zip import FileManager

def alert_handler(event_type, target, message):
    # Tüm alarmların basıldığı tek satırlık bildirim
    print(f"[{event_type}] {message}")

if __name__ == "__main__":
    # 1. Modülleri tanımla
    log_mon = LogMonitor(callback=alert_handler)
    sys_mon = SystemMonitoring(callback=alert_handler)
    file_man = FileManager(file_path=config.LINUX_APP_LOG_PATH)

    # 2. Arka planda paralel olarak çalıştır
    threading.Thread(target=log_mon.start, daemon=True).start()
    threading.Thread(target=sys_mon.start, daemon=True).start()
    threading.Thread(target=file_man.start(), daemon=True).start()
    

    print("[+] İzleme başladı. Kapatmak için Ctrl+C...")

    # 3. Programı açık tut
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Program kapatıldı.")