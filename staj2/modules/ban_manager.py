# -*- coding: utf-8 -*-
# ==============================================================================
# AKILLI KADEMELİ BAN VE ENGEL KALDIRMA YÖNETİCİSİ (ban_manager.py)
# Bu modül İç Ağ (LAN) ve Dış Ağ (WAN) ayrımı yaparak, tehdit kritiklik düzeyine
# (CRITICAL / HIGH / MEDIUM / LOW) göre kademeli ban süreleri uygular.
# İnsani yazım hatalarını (Typo) tolere eder, başarılı girişte geçmiş hataları affeder,
# ve süresi dolan engelleri otomatik kaldırır (Auto-Unban).
# ==============================================================================

import os        # Güvenlik duvarı komutları için os
import time      # Zaman hesaplamaları ve ban süreleri için time
import sqlite3   # Veritabanı yönetimi için sqlite3
import ipaddress # IP adresi ve alt ağ ayrımı için ipaddress
from collections import defaultdict # IP bazlı hata takibi için defaultdict

import config    # Konfigürasyon dosyası
from modules.smart_logger import SmartLogger # Akıllı loglayıcı

class BanManager:
    def __init__(self, db_name="security_events.db", logger=None):
        # Veritabanı adı ve Akıllı Loglayıcı referansını saklar
        self.db_name = db_name
        self.logger = logger or SmartLogger()
        
        # İnsani Hata / Typo Takip Belleği: IP -> [timestamp1, timestamp2, ...]
        self.auth_failure_history = defaultdict(list)
        
        # Veritabanında 'banned_ips' tablosunu hazırlar
        self.init_db()

    def init_db(self):
        # SQLite veritabanında 'banned_ips' tablosunu oluşturur ve günceller
        try:
            conn = sqlite3.connect(self.db_name, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("""CREATE TABLE IF NOT EXISTS banned_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                reason TEXT,
                banned_at REAL,
                ban_duration_seconds INTEGER,
                unban_at REAL,
                is_active INTEGER,
                network_type TEXT,
                criticality_level TEXT,
                enforcement_action TEXT
            )""")
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Ban Database Initialization Error: {e}")

    def is_internal_ip(self, ip: str) -> bool:
        # IP adresinin İç Ağ (LAN / Intranet) mi yoksa Dış Ağ (WAN / Internet) mi olduğunu belirler
        if not ip or ip in ["LOCAL_SYSTEM", "localhost", "127.0.0.1", "::1"]:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return True
            
            # config.INTERNAL_SUBNETS listesindeki alt ağları kontrol eder
            internal_subnets = getattr(config, 'INTERNAL_SUBNETS', ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"])
            for subnet in internal_subnets:
                if ip_obj in ipaddress.ip_network(subnet):
                    return True
        except ValueError:
            pass
        return False

    def is_protected_ip(self, ip: str) -> bool:
        # Sistemin kendi kendini kilitlemesini (lockout) önlemek için korunan IP kontrolü
        protected_list = getattr(config, 'PROTECTED_IPS', ["127.0.0.1", "::1", "localhost", "192.168.1.1", "10.0.0.1"])
        if ip in protected_list or ip == "LOCAL_SYSTEM":
            return True
        return False

    def register_auth_failure(self, ip: str, username: str = "unknown") -> tuple[bool, str, int]:
        # İnsani Yazım Hatası (Typo) ile Kasıtlı Brute-Force Arasındaki Ayrımı Yapar
        if self.is_protected_ip(ip):
            return False, "PROTECTED_IP", 0

        now = time.time()
        is_internal = self.is_internal_ip(ip)
        max_typos = getattr(config, 'INTERNAL_MAX_TYPOS', 5) if is_internal else getattr(config, 'EXTERNAL_MAX_TYPOS', 3)
        interval_threshold = getattr(config, 'TYPO_TIME_INTERVAL_SECONDS', 3.0)

        # 1. Bot ve Otomatik Sözlük Taraması Tespiti (root, admin, test, support vb. geçersiz kullanıcılar)
        bot_targets = ["root", "admin", "test", "support", "oracle", "postgres", "ubnt", "guest"]
        if username.lower() in bot_targets and username.lower() != "user":
            self.auth_failure_history[ip].append(now)
            count = len(self.auth_failure_history[ip])
            msg = f"Malicious Dictionary Probe targeting privileged user '{username}' from {ip}."
            self.logger.log_event("WARNING", "AUTH_GUARD", "DICTIONARY_PROBE", ip, msg)
            return True, "MALICIOUS_DICTIONARY_PROBE", count

        # 2. Son 10 dakika içindeki denemeleri filtreler
        recent_failures = [t for t in self.auth_failure_history[ip] if now - t <= 600]
        recent_failures.append(now)
        self.auth_failure_history[ip] = recent_failures
        failure_count = len(recent_failures)

        # 3. Yüksek Hızlı Brute-Force Tespiti (Son 2 deneme arasındaki süre < 3 saniye ise veya 5 sn içinde 3+ deneme)
        if len(recent_failures) >= 2:
            time_diff = recent_failures[-1] - recent_failures[-2]
            burst_in_5s = sum(1 for t in recent_failures if now - t <= 5)
            
            if burst_in_5s >= 3 or time_diff < interval_threshold:
                msg = f"Rapid Automated Brute-Force Burst Detected from {ip} ({burst_in_5s} attempts in 5s)."
                self.logger.log_event("WARNING", "AUTH_GUARD", "RAPID_BRUTE_FORCE", ip, msg)
                return True, "RAPID_BRUTE_FORCE_ATTACK", failure_count

        # 4. İnsani Hata Tolerans Eşiği Kontrolü
        if failure_count <= max_typos:
            msg = f"Tolerated human password typo ({failure_count}/{max_typos}) for user '{username}' from {ip}. No ban applied."
            self.logger.log_event("INFO", "AUTH_GUARD", "HUMAN_TYPO_TOLERATED", ip, msg)
            return False, "HUMAN_TYPO_TOLERATED", failure_count
        else:
            msg = f"Password failure tolerance exceeded ({failure_count}/{max_typos}) for user '{username}' from {ip}."
            self.logger.log_event("WARNING", "AUTH_GUARD", "TYPO_THRESHOLD_EXCEEDED", ip, msg)
            return True, "TYPO_THRESHOLD_EXCEEDED", failure_count

    def register_auth_success(self, ip: str, username: str):
        # Başarılı Girişte Geçmiş Hataları Affetme Mekanizması (Graceful Forgiveness)
        if ip in self.auth_failure_history and len(self.auth_failure_history[ip]) > 0:
            count = len(self.auth_failure_history[ip])
            self.auth_failure_history[ip].clear() # Hata geçmişini temizler
            msg = f"User '{username}' authenticated successfully. Previous {count} password typos forgiven for IP {ip}."
            self.logger.log_event("NOTICE", "AUTH_GUARD", "AUTH_RECOVERY_FORGIVEN", ip, msg)
            print(f"[+] [AUTH FORGIVEN] {msg}")

    def get_repeat_count(self, ip: str) -> int:
        # IP adresinin geçmişte kaç defa banlandığını sorgular (Tekrarlayan Suçlu Kontrolü)
        try:
            conn = sqlite3.connect(self.db_name, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM banned_ips WHERE ip = ?", (ip,))
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception:
            return 0

    def ban_ip(self, ip: str, criticality: str = "CRITICAL", reason: str = "Security Violation",
               source: str = "AUTO", duration_override: int = None):
        # İç/Dış Ağ ve Kritiklik Düzeyine Göre Kademeli Ban Uygular
        if not ip or self.is_protected_ip(ip):
            print(f"[*] [PROTECTION] IP {ip} is in protected core list; lockout avoided.")
            return

        now = time.time()
        is_internal = self.is_internal_ip(ip)
        network_type = "INTERNAL" if is_internal else "EXTERNAL"
        criticality_level = criticality.upper() if criticality.upper() in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "CRITICAL"

        # Ban Süresini Belirleme
        if duration_override is not None:
            base_duration = duration_override
        else:
            if is_internal:
                durations = getattr(config, 'BAN_DURATIONS_INTERNAL', {"CRITICAL": 900, "HIGH": 300, "MEDIUM": 180, "LOW": 0})
            else:
                durations = getattr(config, 'BAN_DURATIONS_EXTERNAL', {"CRITICAL": 3600, "HIGH": 1800, "MEDIUM": 600, "LOW": 0})
            base_duration = durations.get(criticality_level, 600)

        if base_duration == 0:
            print(f"[*] [NO BAN] Threat level '{criticality_level}' does not require ban for IP {ip}.")
            return

        # Tekrarlayan Saldırgan Çarpanı (2x, 4x, maks 8x)
        repeat_count = self.get_repeat_count(ip)
        effective_duration = base_duration * (2 ** min(repeat_count, 3))
        unban_at = now + effective_duration
        unban_at_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unban_at))
        duration_minutes = effective_duration // 60

        enforcement_action = "SESSION_PORT_ISOLATION" if is_internal else "FIREWALL_DROP"

        print(f"\n[!] [{criticality_level} BAN] Network: [{network_type}] | IP: {ip} | Duration: {duration_minutes} Mins | Action: {enforcement_action}")
        print(f"    Reason: {reason}")

        # 1. GÜVENLİK DUVARI VEYA İÇ AĞ KISITLAMA KOMUTU (1. Sıraya Ekleme - Insert 1 Önceliği)
        try:
            if os.name != 'nt':
                if not is_internal: # Dış Ağ İçin UFW Güvenlik Duvarında En Başa (1. Kural) Blok Ekleme
                    os.system(f"sudo ufw insert 1 deny from {ip} to any comment 'Tiered-{criticality_level}-{duration_minutes}m'")
                else: # İç Ağ İçin SSH İzolasyonunu 1. Sıraya Ekleme
                    os.system(f"sudo ufw insert 1 deny proto tcp from {ip} to any port 22 comment 'Internal-SSH-Isolate-{duration_minutes}m'")
            else: # Windows Test Ortamı Simülasyonu
                print(f"[*] [Windows Simulation] {network_type} IP {ip} restricted for {duration_minutes} minutes via {enforcement_action} (sudo ufw insert 1 deny from {ip}).")
        except Exception as e:
            print(f"[-] Enforcement Action Error ({ip}): {e}")

        # 2. SQLITE VERİTABANINA KAYDETME
        try:
            conn = sqlite3.connect(self.db_name, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("UPDATE banned_ips SET is_active = 0 WHERE ip = ? AND is_active = 1", (ip,))
            cursor.execute("""INSERT INTO banned_ips 
                (ip, reason, banned_at, ban_duration_seconds, unban_at, is_active, network_type, criticality_level, enforcement_action)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)""",
                (ip, reason, now, effective_duration, unban_at, network_type, criticality_level, enforcement_action))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Ban Database Write Error: {e}")

        # 3. AKILLI LOGLAYICIYA DETAYLI KART YAZMA
        log_msg = (
            f"[{network_type}] IP {ip} BANNED for {duration_minutes} MINUTES ({criticality_level} Level). "
            f"Enforcement: {enforcement_action}. Reason: {reason}. (Auto-Unban Time: {unban_at_str})"
        )
        self.logger.log_event("CRITICAL" if criticality_level == "CRITICAL" else "WARNING",
                              "BAN_MANAGER", f"{network_type}_IP_BAN", ip, log_msg)

    def unban_ip(self, ip: str, reason: str = "Ban Duration Expired"):
        # IP Adresinin Engeli Süresi Dolduğunda Kaldırır
        is_internal = self.is_internal_ip(ip)
        network_type = "INTERNAL" if is_internal else "EXTERNAL"

        print(f"\n[+] [BAN REMOVED] Network: [{network_type}] | IP: {ip} restriction lifted! Reason: {reason}")
        try:
            if os.name != 'nt':
                if not is_internal:
                    os.system(f"sudo ufw delete deny from {ip}")
                else:
                    os.system(f"sudo ufw delete deny proto tcp from {ip} to any port 22")
            else:
                print(f"[*] [Windows Simulation] {network_type} ban lifted for IP {ip}.")
        except Exception as e:
            print(f"[-] Unban Error ({ip}): {e}")

        try:
            conn = sqlite3.connect(self.db_name, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("UPDATE banned_ips SET is_active = 0 WHERE ip = ? AND is_active = 1", (ip,))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Ban Database Update Error: {e}")

        log_msg = f"Ban duration expired for {network_type} IP {ip}; automatically unbanned."
        self.logger.log_event("INFO", "BAN_MANAGER", "IP_AUTOMATIC_UNBAN", ip, log_msg)

    def check_expired_bans(self):
        # Süresi Dolan Aktif Banları Kontrol Eder ve Otomatik Engellerini Kaldırır
        now = time.time()
        try:
            conn = sqlite3.connect(self.db_name, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("SELECT ip, reason FROM banned_ips WHERE is_active = 1 AND unban_at <= ?", (now,))
            expired_bans = cursor.fetchall()
            conn.close()

            for ip, reason in expired_bans:
                self.unban_ip(ip, reason="Tiered Ban Duration Expired")
        except Exception as e:
            print(f"[-] Ban Expiration Check Error: {e}")

    def start(self):
        # Otomatik Ban Süresi Takip Servisini Başlatır
        print(f"[+] Tiered Ban Manager & Auto-Unban Service Started: {time.ctime()}")
        
        while True:
            try:
                self.check_expired_bans()
            except Exception as e:
                print(f"[-] Ban Service Loop Error: {e}")
            time.sleep(10)
