# -*- coding: utf-8 -*-
# ==============================================================================
# ÇOKLU OTURUM, EYLEMSİZLİK TAKİP VE KOMUT ANALİZ MOTORU (user_session_tracker.py)
# Bu modül sisteme bağlanan tüm kullanıcı oturumlarını eşzamanlı takip eder.
# Rutin geliştirici komutlarını gürültü yapmadan tamponlayıp 5 dakikada bir özetler,
# Çok Katmanlı Yapay Zeka Güvenlik Motoru ile obfuskasyonlu ve sıfır-gün komutları tespit eder,
# İç Ağ / Dış Ağ kademeli banlama yapar ve 15 dakika eylemsiz kalanları sistemden atar.
# ==============================================================================

import os        # Oturum kapatma (pkill) komutları için os
import time      # Zaman hesaplamaları ve eylemsizlik takibi için time
import sqlite3   # Oturum ve komut veritabanı yönetimi için sqlite3
import config    # Ayarlar dosyası
from modules.smart_logger import SmartLogger             # Akıllı anlaşılır loglayıcı
from modules.ai_security_engine import AISecurityEngine # Çok Katmanlı Yapay Zeka Motoru
from modules.ban_manager import BanManager               # Kademeli Ban Yöneticisi

class UserSessionTracker:
    def __init__(self, db_name="security_events.db", logger=None, ai_engine=None, ban_manager=None):
        # Veritabanı, Akıllı Loglayıcı, AI Motoru ve Ban Yöneticisi referanslarını saklar
        self.db_name = db_name
        self.logger = logger or SmartLogger()
        self.ai_engine = ai_engine or AISecurityEngine()
        self.ban_manager = ban_manager or BanManager(logger=self.logger)
        
        # Aktif Oturumlar Sözlüğü: (username, ip, tty) -> Oturum Detayları
        self.active_sessions = {}
        
        # Veritabanında oturum tablolarını oluşturur
        self.init_db()

    def init_db(self):
        # SQLite veritabanında 'user_sessions' ve 'session_activity_logs' tablolarını oluşturur
        try:
            conn = sqlite3.connect(self.db_name, check_same_thread=False)
            cursor = conn.cursor()
            
            # 1. Oturum Özet Tablosu
            cursor.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT,
                source_ip TEXT,
                tty_device TEXT,
                login_time REAL,
                logout_time REAL,
                last_activity_time REAL,
                total_commands INTEGER,
                status TEXT
            )""")
            
            # 2. Oturum İçi Komut ve İhlal Tablosu
            cursor.execute("""CREATE TABLE IF NOT EXISTS session_activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                username TEXT,
                source_ip TEXT,
                timestamp TEXT,
                command TEXT,
                category TEXT,
                risk_score INTEGER,
                summary TEXT,
                mitre_id TEXT,
                criticality TEXT
            )""")
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Session Database Initialization Error: {e}")

    def start_session(self, username, source_ip, tty="pts/0"):
        # Yeni Bir Kullanıcı Oturumu Başlatır (Multi-Session Desteği)
        now = time.time()
        session_id = f"SESS_{username}_{source_ip}_{tty.replace('/', '_')}_{int(now)}"
        session_key = (username, source_ip, tty)
        
        # Aktif oturum nesnesi oluşturulur
        session_data = {
            "session_id": session_id,
            "username": username,
            "source_ip": source_ip,
            "tty": tty,
            "login_time": now,
            "last_activity_time": now,
            "routine_buffer": [], # Rutin komutları biriktiren gürültüsüz tampon bellek
            "command_count": 0,
            "cumulative_risk": 0
        }
        
        self.active_sessions[session_key] = session_data

        # Veritabanına yeni aktif oturum ekler
        try:
            conn = sqlite3.connect(self.db_name, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("""INSERT INTO user_sessions 
                (session_id, username, source_ip, tty_device, login_time, logout_time, last_activity_time, total_commands, status)
                VALUES (?, ?, ?, ?, ?, 0, ?, 0, 'ACTIVE')""",
                (session_id, username, source_ip, tty, now, now))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Session Database Write Error: {e}")

        # Akıllı Loglayıcı ile Anlaşılır İngilizce Kayıt Oluşturur
        msg = f"User '{username}' logged in successfully. (IP: {source_ip} | Terminal: {tty})"
        self.logger.log_event("NOTICE", "SESSION_TRACKER", "USER_LOGIN", source_ip, msg)
        print(f"[+] [SESSION STARTED] {msg}")

    def record_command(self, username, source_ip, command, tty="pts/0"):
        # Oturum İçi Komut Çalıştırmasını Analiz Eder ve Kaydeder
        session_key = (username, source_ip, tty)
        now = time.time()
        
        # Oturum bulunamazsa dinamik başlatır
        if session_key not in self.active_sessions:
            self.start_session(username, source_ip, tty)
            
        session = self.active_sessions[session_key]
        session["last_activity_time"] = now # Son hareket zamanını günceller (Idle sıfırlama)
        session["command_count"] += 1

        # 1. Komut Niyet, Kural ve Yapay Zeka Risk Analizi
        category, risk_score, is_anomaly, summary, ai_res, criticality = self.analyze_command_context(username, command)

        # 2. GÜRÜLTÜSÜZ TAMPON MEKANİZMASI: Rutin komutlar gürültü yapmamak için tamponlanır
        if not is_anomaly and risk_score == 0:
            session["routine_buffer"].append(command)
            
            if len(session["routine_buffer"]) >= 10:
                self.flush_routine_buffer(session)
            return

        # 3. ANOMALİ / GERÇEK ŞÜPHELİ EYLEM: Tamponu baypas eder ve anında yüksek öncelikli log oluşturur
        session["cumulative_risk"] += risk_score
        mitre_id = ai_res.get("mitre_id", "N/A")
        
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            conn = sqlite3.connect(self.db_name, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("""INSERT INTO session_activity_logs 
                (session_id, username, source_ip, timestamp, command, category, risk_score, summary, mitre_id, criticality)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session["session_id"], username, source_ip, timestamp, command, category, risk_score, summary, mitre_id, criticality))
            
            cursor.execute("UPDATE user_sessions SET total_commands = ?, last_activity_time = ? WHERE session_id = ?",
                (session["command_count"], now, session["session_id"]))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Command Logging Error: {e}")

        level = "CRITICAL" if criticality == "CRITICAL" else ("WARNING" if criticality == "HIGH" else "NOTICE")
        log_msg = f"Session [{session['session_id']}]: User '{username}' executed '{command}'. (Summary: {summary})"
        self.logger.log_event(level, "USER_ACTIVITY", f"COMMAND_{category}", source_ip, log_msg, ai_info=ai_res)

        # Kritik İhlal veya Risk Eşiği Aşımında Kademeli Ban Tetikleme
        if risk_score >= 70 or session["cumulative_risk"] >= 50:
            ban_reason = f"Session Hostile Activity: '{command}' ({criticality} Level - Risk: {session['cumulative_risk']})"
            self.ban_manager.ban_ip(ip=source_ip, criticality=criticality, reason=ban_reason)

    def analyze_command_context(self, username, command):
        # Komutun Bağlamını, Niyetini, Tahribat Derecesini ve Yapay Zeka Çıkarımını Analiz Eder
        cmd = command.strip()
        cmd_lower = cmd.lower()
        
        # A. Yapay Zeka Güvenlik Motoru Analizi
        ai_res = self.ai_engine.analyze(cmd)
        
        # B. YIKICI SİSTEM TAHRİBATI (Kritik Risk - 90 Puan - CRITICAL)
        if any(w in cmd_lower for w in ["rm -rf /", "shred", "mkfs", "dd if=/dev/zero"]):
            return "DESTRUCTIVE_MUTATION", 90, True, "Dangerous Destructive System Data Wipe Attempt", ai_res, "CRITICAL"

        # C. RAHATSIZ EDİCİ / ZARARLI BORU HATLARI (Piping Redirection - 80 Puan - HIGH)
        if ("curl" in cmd_lower or "wget" in cmd_lower) and ("| bash" in cmd_lower or "| sh" in cmd_lower):
            return "UNVERIFIED_SCRIPT_PIPE", 80, True, "Unverified Remote Web Script Piped Directly into Shell", ai_res, "HIGH"

        # D. HASSAS DOSYA OKUMA VE YETKİ YÜKSELTMESİ (75 Puan - CRITICAL/HIGH)
        if "cat /etc/shadow" in cmd_lower or "cat /etc/sudoers" in cmd_lower:
            return "SENSITIVE_FILE_READ", 75, True, "Unauthorized Sensitive Credential/Privilege File Read", ai_res, "CRITICAL"
            
        if any(w in cmd_lower for w in ["sudo su", "su -", "pkexec", "doas"]):
            return "PRIVILEGE_ESCALATION", 70, True, "Root Interactive Shell Spawned", ai_res, "HIGH"

        # E. TERS BAĞLANTI / AĞ SOKETİ (85 Puan - CRITICAL)
        if any(w in cmd_lower for w in ["nc -e", "ncat -e", "/dev/tcp/", "socat exec"]):
            return "REVERSE_SHELL_ATTEMPT", 85, True, "Outbound Reverse Shell Connection Attempt", ai_res, "CRITICAL"

        # F. DİL YORUMLAYICILARI VE TEK SATIRLIK KOD ENJEKSİYONU (60 Puan - HIGH)
        if ("python" in cmd_lower or "perl" in cmd_lower or "php" in cmd_lower) and "-c " in cmd_lower:
            return "INLINE_INTERPRETER_EXEC", 60, True, "Inline Command-Line Code String Injection Execution", ai_res, "HIGH"

        # G. YAPAY ZEKA SALDIRI TESPİTİ
        if ai_res.get("is_attack"):
            verdict = ai_res.get("verdict", "ATTACK")
            title = ai_res.get("incident_title", "Cyber Threat Detected")
            cat = ai_res.get("incident_category", "AI_ANOMALY")
            urgency = ai_res.get("urgency", "HIGH")
            score = 75 if urgency == "CRITICAL" else 60
            return f"AI_{cat}", score, True, f"AI {verdict}: {title}", ai_res, urgency

        # H. RUTİN KULLANICI / GELİŞTİRİCİ KOMUTLARI (Güvenli - 0 Puan - LOW)
        return "ROUTINE_COMMAND", 0, False, "Routine Normal User / Developer Activity", ai_res, "LOW"

    def flush_routine_buffer(self, session):
        # Biriken Rutin Komutları Gürültü Yapmadan Tek Bir Özet Kartı Olarak Loglar
        if not session["routine_buffer"]:
            return
            
        count = len(session["routine_buffer"])
        sample_cmds = ", ".join(session["routine_buffer"][:3])
        session["routine_buffer"].clear()

        summary_msg = f"Session [{session['session_id']}]: User '{session['username']}' executed {count} routine commands. (Samples: {sample_cmds}...)"
        self.logger.log_event("INFO", "SESSION_SUMMARY", "ROUTINE_ACTIVITY", session["source_ip"], summary_msg)

    def end_session(self, username, source_ip, tty="pts/0"):
        # Kullanıcı Oturumunu Sonlandırır
        session_key = (username, source_ip, tty)
        now = time.time()
        
        if session_key in self.active_sessions:
            session = self.active_sessions[session_key]
            self.flush_routine_buffer(session)
            
            try:
                conn = sqlite3.connect(self.db_name, check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute("UPDATE user_sessions SET logout_time = ?, status = 'ENDED' WHERE session_id = ?",
                    (now, session["session_id"]))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[-] Session Close Error: {e}")

            msg = f"User '{username}' logged out. (IP: {source_ip} | Terminal: {tty})"
            self.logger.log_event("NOTICE", "SESSION_TRACKER", "USER_LOGOUT", source_ip, msg)
            print(f"[*] [SESSION CLOSED] {msg}")
            
            del self.active_sessions[session_key]

    def check_idle_session_timeouts(self):
        # 15 DAKİKA (900 Saniye) EYLEMSİZ KALAN OTURUMLARI OTOMATİK TESPİT EDİP SİSTEMDEN ATAR (Auto-Kick)
        now = time.time()
        timeout_seconds = getattr(config, 'IDLE_SESSION_TIMEOUT_SECONDS', 900)
        
        sessions_to_kick = []

        for session_key, session in list(self.active_sessions.items()):
            idle_time = now - session["last_activity_time"]
            if idle_time >= timeout_seconds:
                sessions_to_kick.append((session_key, session, idle_time))

        for session_key, session, idle_time in sessions_to_kick:
            username = session["username"]
            source_ip = session["source_ip"]
            tty = session["tty"]
            idle_minutes = int(idle_time // 60)

            print(f"\n[!] [KICKED DUE TO INACTIVITY] User: {username} | Terminal: {tty} | Idle Duration: {idle_minutes} Minutes")

            try:
                if os.name != 'nt':
                    clean_tty = tty.replace("/dev/", "")
                    os.system(f"sudo pkill -9 -t {clean_tty}")
                else:
                    print(f"[*] [Windows Simulation] Session for user '{username}' on terminal {tty} terminated.")
            except Exception as e:
                print(f"[-] Session Termination Error ({tty}): {e}")

            try:
                conn = sqlite3.connect(self.db_name, check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute("UPDATE user_sessions SET logout_time = ?, status = 'INACTIVE_TIMEOUT_KICKED' WHERE session_id = ?",
                    (now, session["session_id"]))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[-] Session Timeout Database Update Error: {e}")

            kick_msg = f"User '{username}' automatically kicked out after {idle_minutes} minutes of inactivity (idle session timeout)."
            self.logger.log_event("WARNING", "SESSION_TRACKER", "IDLE_SESSION_KICKED", source_ip, kick_msg)

            del self.active_sessions[session_key]

    def start(self):
        # Oturum Eylemsizlik Zaman Aşımı Takip Servisini Başlatır
        print(f"[+] Session Inactivity Tracking Service Started (15-Min Threshold): {time.ctime()}")
        
        while True:
            try:
                self.check_idle_session_timeouts()
            except Exception as e:
                print(f"[-] Session Tracking Loop Error: {e}")
            time.sleep(10)
