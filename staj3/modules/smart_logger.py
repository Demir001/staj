# -*- coding: utf-8 -*-
# ==============================================================================
# AKILLI LOGLAMA VE ÖZETLEME MOTORU (smart_logger.py)
# Bu modül ham ve karmaşık log ifadelerini, Yapay Zeka (AI) tespitlerini,
# İnsani Yazım Hatası (Typo) Toleransını ve İç/Dış Ağ Kademeli Ban bilgilerini
# anlaşılır İngilizce özetlere dönüştürür.
# Her log kaydına açıkça [SAFE OPERATION] veya [MALICIOUS OPERATION] durumunu ekler.
# ==============================================================================

import os        # Dizin ve dosya işlemleri için os
import time      # Zaman damgaları için time
import json      # Yapılandırılmış JSONL kayıtları için json
import sqlite3   # Veritabanı entegrasyonu için sqlite3

class SmartLogger:
    def __init__(self, log_dir="logs", db_name="security_events.db"):
        # Log dizinini ve veritabanı adını saklar
        self.log_dir = log_dir
        self.db_name = db_name
        
        # 'logs' dizini yoksa otomatik oluşturur
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Log Dosya Yolları
        self.readable_log_path = os.path.join(self.log_dir, "readable_activity.log")
        self.jsonl_log_path = os.path.join(self.log_dir, "activity_records.jsonl")

        # SQLite veritabanında log tablosunu hazırlar
        self.init_db()

    def init_db(self):
        # SQLite veritabanında 'activity_logs' tablosunu oluşturur ve sütunları günceller
        try:
            conn = sqlite3.connect(self.db_name, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("""CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                level TEXT,
                status TEXT,
                module TEXT,
                event_type TEXT,
                target TEXT,
                summary TEXT,
                raw_details TEXT,
                mitre_id TEXT,
                ai_verdict TEXT
            )""")
            # Mevcut eski tablolara 'status' sütununu otomatik ekleme (Migration)
            cursor.execute("PRAGMA table_info(activity_logs)")
            columns = [col[1] for col in cursor.fetchall()]
            if "status" not in columns:
                cursor.execute("ALTER TABLE activity_logs ADD COLUMN status TEXT")
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Log Database Initialization Error: {e}")

    def determine_operation_status(self, level, event_type, ai_info=None) -> str:
        # Logun GÜVENLİ İŞLEM mi yoksa ZARARLI İŞLEM mi olduğunu kesin olarak sınıflandırır
        if ai_info and isinstance(ai_info, dict) and ai_info.get("is_attack"):
            if ai_info.get("verdict") == "ZERO_DAY":
                return "MALICIOUS ZERO-DAY (ZARARLI SIFIR-GÜN İŞLEMİ)"
            return "MALICIOUS ATTACK (ZARARLI SALDIRI İŞLEMİ)"

        malicious_events = [
            "AI_ATTACK_DETECTED", "ADVANCED_THREAT_DETECTED", "DESTRUCTIVE_MUTATION",
            "REVERSE_SHELL_ATTEMPT", "SENSITIVE_FILE_READ", "ARP_SPOOFING_DETECTED",
            "NIC_PROMISCUOUS_ENTER", "SUDO_ROOT_SHELL", "DICTIONARY_PROBE",
            "RAPID_BRUTE_FORCE", "EXTERNAL_IP_BAN", "INTERNAL_IP_BAN", "UNVERIFIED_SCRIPT_PIPE"
        ]
        
        if event_type in malicious_events or level.upper() in ["CRITICAL", "ALERT"]:
            return "MALICIOUS OPERATION (ZARARLI İŞLEM)"
        elif level.upper() == "WARNING" or "TYPO_THRESHOLD_EXCEEDED" in event_type or "IDLE_SESSION" in event_type:
            return "SUSPICIOUS / WARNING (ŞÜPHELİ / UYARI)"
        else:
            return "SAFE OPERATION (GÜVENLİ İŞLEM)"

    def synthesize_summary(self, event_type, target, details, ai_info=None):
        # Karmaşık teknik olayları ve AI tespitlerini anlaşılır İngilizce özetlere dönüştürür
        if ai_info and isinstance(ai_info, dict) and ai_info.get("is_attack"):
            verdict = ai_info.get("verdict", "ATTACK")
            conf = ai_info.get("confidence", 90.0)
            mitre = ai_info.get("mitre_id", "N/A")
            cat = ai_info.get("incident_category", "EXPLOIT")
            title = ai_info.get("incident_title", "Attack Vector")
            return f"AI [{verdict}] ({conf:.1f}% Confidence) | {title} (MITRE {mitre} - {cat}) detected from {target}."

        if event_type == "HUMAN_TYPO_TOLERATED":
            return f"Human password typo tolerated for target {target}. (Safe Operation - No ban applied)."
        elif event_type == "AUTH_RECOVERY_FORGIVEN":
            return f"Legitimate authentication succeeded for {target}. Past typo failures forgiven."
        elif event_type == "DICTIONARY_PROBE":
            return f"Automated dictionary scanning attack targeting privileged accounts from {target}."
        elif event_type == "RAPID_BRUTE_FORCE":
            return f"High-velocity automated brute-force attack burst detected from {target}."
        elif event_type == "EXTERNAL_IP_BAN":
            return f"EXTERNAL WAN IP {target} dropped on firewall due to security violations."
        elif event_type == "INTERNAL_IP_BAN":
            return f"INTERNAL LAN IP {target} quarantined/isolated due to hostile activity."
        elif event_type == "SSH_INVALID_USER_ATTEMPT":
            return f"SSH login attempt with invalid username from IP {target}."
        elif event_type == "SSH_INVALID_PASSWORD_ATTEMPT":
            return f"Failed SSH password attempt from IP {target}."
        elif event_type == "SSH_SUCCESSFUL_LOGIN":
            return f"Successful SSH authentication from IP {target}."
        elif event_type == "SSH_ROOT_LOGIN_ATTEMPT":
            return f"CRITICAL: Direct Root SSH login established from IP {target}."
        elif event_type == "ADVANCED_THREAT_DETECTED":
            return f"CRITICAL THREAT: IP {target} exceeded security risk threshold! Automated firewall ban enforced."
        elif event_type == "AI_ATTACK_DETECTED":
            return f"AI DEEP LEARNING: High-confidence cyber threat detected from IP {target}."
        elif event_type == "AI_ZERO_DAY_ANOMALY":
            return f"AI ZERO-DAY AUTOENCODER: Unseen anomalous payload detected from IP {target}."
        elif event_type == "HIGH_CPU_USAGE":
            return f"System CPU utilization exceeded configured threshold."
        elif event_type == "HIGH_RAM_USAGE":
            return f"System memory (RAM) usage reached critical threshold."
        elif event_type == "HIGH_DISK_READ":
            return f"High disk read throughput detected."
        elif event_type == "HIGH_DISK_WRITE":
            return f"High disk write throughput detected."
        elif event_type == "HIGH_NETWORK_BANDWIDTH":
            return f"Network bandwidth usage exceeded limit."
        elif event_type == "ARP_SPOOFING_DETECTED":
            return f"NETWORK SECURITY VIOLATION: ARP Poisoning / Spoofed MAC detected for IP {target}!"
        elif event_type == "NIC_PROMISCUOUS_ENTER":
            return f"SECURITY WARNING: Network interface entered promiscuous packet capture mode!"
        elif event_type == "SUDO_ROOT_SHELL":
            return f"PRIVILEGE ESCALATION: Root command shell spawned via Sudo!"
        elif event_type == "LOG_ARCHIVED":
            return f"Log file exceeded size threshold and was compressed to ZIP archive."
        elif event_type == "IP_TEMPORARY_BAN":
            return f"IP {target} temporarily banned on firewall due to security violations."
        elif event_type == "IP_AUTOMATIC_UNBAN":
            return f"IP {target} temporary ban expired; unbanned from firewall automatically."
        elif event_type == "IDLE_SESSION_KICKED":
            return f"Session for IP {target} automatically terminated after 15 minutes of inactivity."
        else:
            return f"{event_type} event recorded for target {target}. ({details})"

    def log_event(self, level, module, event_type, target, details="", ai_info=None):
        # Ana Loglama Metodu
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        status_tag = self.determine_operation_status(level, event_type, ai_info=ai_info)
        summary = self.synthesize_summary(event_type, target, details, ai_info=ai_info)
        
        mitre_id = ai_info.get("mitre_id", "N/A") if isinstance(ai_info, dict) else "N/A"
        ai_verdict = ai_info.get("verdict", "N/A") if isinstance(ai_info, dict) else "N/A"
        playbook = ai_info.get("playbook", "") if isinstance(ai_info, dict) else ""

        # 1. OKUNABİLİR METİN LOG DOSYASINA YAZMA (readable_activity.log)
        card_lines = [
            "------------------------------------------------------------------",
            f"TIMESTAMP: {timestamp}",
            f"STATUS   : [{status_tag}]",
            f"LEVEL    : [{level.upper()}]",
            f"MODULE   : {module}",
            f"EVENT    : {event_type}",
            f"TARGET/IP: {target}",
            f"SUMMARY  : {summary}",
            f"DETAILS  : {details}"
        ]
        if ai_info and isinstance(ai_info, dict):
            card_lines.append(f"AI ENGINE: Verdict: {ai_verdict} (Confidence: {ai_info.get('confidence', 0)}%) | Layer: {ai_info.get('layer', 'N/A')}")
            card_lines.append(f"TAXONOMY : MITRE: {mitre_id} | Category: {ai_info.get('incident_category', 'N/A')}")
            if playbook:
                card_lines.append(f"PLAYBOOK : {playbook}")
        card_lines.append("------------------------------------------------------------------\n")
        
        formatted_card = "\n".join(card_lines)

        try:
            with open(self.readable_log_path, "a", encoding="utf-8") as f:
                f.write(formatted_card)
        except Exception as e:
            print(f"[-] Readable Log Write Error: {e}")

        # 2. YAPILANDIRILMIŞ JSONL DOSYASINA YAZMA (activity_records.jsonl)
        json_record = {
            "timestamp": timestamp,
            "status": status_tag,
            "level": level.upper(),
            "module": module,
            "event_type": event_type,
            "target": str(target),
            "summary": summary,
            "raw_details": str(details),
            "mitre_id": mitre_id,
            "ai_verdict": ai_verdict,
            "ai_details": ai_info if isinstance(ai_info, dict) else {}
        }
        try:
            with open(self.jsonl_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(json_record, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[-] JSONL Log Write Error: {e}")

        # 3. SQLITE VERİTABANINA YAZMA (security_events.db -> activity_logs)
        try:
            conn = sqlite3.connect(self.db_name, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("""INSERT INTO activity_logs 
                (timestamp, level, status, module, event_type, target, summary, raw_details, mitre_id, ai_verdict)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (timestamp, level.upper(), status_tag, module, event_type, str(target), summary, str(details), mitre_id, ai_verdict))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Log Database Write Error: {e}")

    def get_recent_readable_logs(self, limit=20):
        try:
            conn = sqlite3.connect(self.db_name, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, level, status, module, summary FROM activity_logs ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            conn.close()
            return rows
        except Exception as e:
            print(f"[-] Log Query Error: {e}")
            return []
