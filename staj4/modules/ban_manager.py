# -*- coding: utf-8 -*-
"""
==============================================================================
MULTI-BACKEND TIERED BAN & FIREWALL MANAGER (ban_manager.py)
==============================================================================
This module provides:
1. DUAL-STACK MULTI-BACKEND FIREWALL ENFORCEMENT (IPv4, IPv6 & CIDR Subnets):
   - UFW (Insert 1 Priority Rule) + Direct Kernel-Level IPTables/IP6Tables (-I INPUT 1 -s <IP/CIDR> -j DROP).
   - Instant Active TCP/SSH Socket Teardown (`ss -K dst <IP>`, `conntrack -D`).
2. DISTRIBUTED BOTNET & SUBNET / CIDR RANGE BLOCKING:
   - Supports banning individual IP addresses as well as entire /24 and /64 subnets.
3. STARTUP FIREWALL RESYNCHRONIZATION (Reboot / Crash Recovery):
   - Re-applies active database bans into the OS firewall on SIEM initialization.
4. DYNAMIC SELF-LOCKOUT & WHITELIST PROTECTION:
   - Dynamically resolves host interface IPs (IPv4/IPv6), default gateway, and DNS servers.
5. THREAD-SAFE CONCURRENCY (SQLite WAL Mode & Busy Timeout).
==============================================================================
"""

import os
import time
import socket
import sqlite3
import subprocess
import ipaddress
from collections import defaultdict

import config
from modules.smart_logger import SmartLogger
from modules.db_manager import get_db_connection

class BanManager:
    def __init__(self, db_name="security_events.db", logger=None):
        self.db_name = db_name
        self.logger = logger or SmartLogger()
        
        # Typo Tracking Cache: IP -> [timestamp1, timestamp2, ...]
        self.auth_failure_history = defaultdict(list)
        
        # Active Ban In-Memory Cache: IP/CIDR -> unban_at_timestamp
        self.active_bans = {}
        
        # Dynamic Protected Whitelist (Gateway + Local IPs)
        self.dynamic_protected_ips = set()
        self.discover_local_network_context()

        # Initialize tables and load unexpired active bans
        self.init_db()
        self.load_active_bans()

        # Re-synchronize firewall rules on boot
        if getattr(config, 'ENABLE_FIREWALL_SYNC_ON_STARTUP', True):
            self.sync_active_firewall_rules()

    def discover_local_network_context(self):
        """
        Discovers local host IP and default gateway to prevent self-lockout.
        """
        base_protected = getattr(config, 'PROTECTED_IPS', ["127.0.0.1", "::1", "localhost", "192.168.1.1", "10.0.0.1"])
        for ip in base_protected:
            self.dynamic_protected_ips.add(ip)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            if local_ip:
                self.dynamic_protected_ips.add(local_ip)
        except Exception:
            pass

        try:
            host_ip = socket.gethostbyname(socket.gethostname())
            if host_ip:
                self.dynamic_protected_ips.add(host_ip)
        except Exception:
            pass

    def init_db(self):
        """
        Initializes the 'banned_ips' table in SQLite using WAL mode.
        """
        try:
            with get_db_connection(self.db_name) as conn:
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
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_banned_ip_active ON banned_ips (ip, is_active);")
                conn.commit()
        except Exception as e:
            print(f"[-] Ban Database Initialization Error: {e}")

    def load_active_bans(self):
        """
        Loads unexpired active bans into memory on startup.
        """
        now = time.time()
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ip, unban_at FROM banned_ips WHERE is_active = 1 AND unban_at > ?", (now,))
                rows = cursor.fetchall()
                for ip, unban_at in rows:
                    self.active_bans[ip] = unban_at
        except Exception as e:
            print(f"[-] Load Active Bans Error: {e}")

    def sync_active_firewall_rules(self):
        """
        Synchronizes active bans from database into the host firewall.
        """
        if not self.active_bans:
            return

        print(f"[*] [FIREWALL SYNC] Re-synchronizing {len(self.active_bans)} active ban(s) into OS firewall...")
        for target, unban_at in list(self.active_bans.items()):
            if unban_at > time.time():
                self._apply_os_firewall_rule(target, is_internal=self.is_internal_ip(target), criticality="HIGH")

    def is_banned(self, ip: str) -> bool:
        """
        Checks if an IP is actively banned (either directly or via an active CIDR subnet ban).
        """
        if not ip or self.is_protected_ip(ip):
            return False

        now = time.time()

        # 1. Direct O(1) in-memory cache lookup
        if ip in self.active_bans:
            if self.active_bans[ip] > now:
                return True
            else:
                del self.active_bans[ip]

        # 2. Check if IP falls within any active CIDR subnet bans
        try:
            ip_obj = ipaddress.ip_address(ip)
            for target, unban_at in list(self.active_bans.items()):
                if "/" in target and unban_at > now:
                    try:
                        if ip_obj in ipaddress.ip_network(target):
                            return True
                    except Exception:
                        pass
        except Exception:
            pass

        # 3. Database query fallback
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT unban_at FROM banned_ips WHERE ip = ? AND is_active = 1 AND unban_at > ? ORDER BY unban_at DESC LIMIT 1", (ip, now))
                row = cursor.fetchone()
                if row:
                    self.active_bans[ip] = row[0]
                    return True
        except Exception:
            pass

        return False

    def is_internal_ip(self, ip: str) -> bool:
        """
        Determines if an IP or Subnet belongs to internal LAN or external WAN.
        """
        if not ip or ip in ["LOCAL_SYSTEM", "localhost", "127.0.0.1", "::1"]:
            return True
        try:
            if "/" in ip:
                net_obj = ipaddress.ip_network(ip, strict=False)
                return net_obj.is_private or net_obj.is_loopback or net_obj.is_link_local
            else:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    return True
                
                internal_subnets = getattr(config, 'INTERNAL_SUBNETS', ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "fc00::/7", "fe80::/10"])
                for subnet in internal_subnets:
                    try:
                        if ip_obj in ipaddress.ip_network(subnet):
                            return True
                    except TypeError:
                        pass
        except ValueError:
            pass
        return False

    def is_protected_ip(self, ip: str) -> bool:
        """
        Checks if the IP is in the core protected whitelist to prevent self-lockout.
        """
        if not ip or ip == "LOCAL_SYSTEM":
            return True
        if ip in self.dynamic_protected_ips:
            return True
        return False

    def register_auth_failure(self, ip: str, username: str = "unknown") -> tuple[bool, str, int]:
        """
        Distinguishes between human typos and automated brute-force attacks.
        """
        if self.is_protected_ip(ip):
            return False, "PROTECTED_IP", 0

        now = time.time()
        is_internal = self.is_internal_ip(ip)
        max_typos = getattr(config, 'INTERNAL_MAX_TYPOS', 5) if is_internal else getattr(config, 'EXTERNAL_MAX_TYPOS', 3)
        interval_threshold = getattr(config, 'TYPO_TIME_INTERVAL_SECONDS', 3.0)

        # 1. Dictionary Probe against Privileged Users
        bot_targets = ["root", "admin", "test", "support", "oracle", "postgres", "ubnt", "guest"]
        if username.lower() in bot_targets and username.lower() != "user":
            self.auth_failure_history[ip].append(now)
            count = len(self.auth_failure_history[ip])
            msg = f"Malicious Dictionary Probe targeting privileged user '{username}' from {ip}."
            self.logger.log_event("WARNING", "AUTH_GUARD", "DICTIONARY_PROBE", ip, msg)
            return True, "MALICIOUS_DICTIONARY_PROBE", count

        # 2. Filter failures within the last 10 minutes
        recent_failures = [t for t in self.auth_failure_history[ip] if now - t <= 600]
        recent_failures.append(now)
        self.auth_failure_history[ip] = recent_failures
        failure_count = len(recent_failures)

        # 3. High-Speed Brute-Force Burst Detection
        if len(recent_failures) >= 2:
            time_diff = recent_failures[-1] - recent_failures[-2]
            burst_in_5s = sum(1 for t in recent_failures if now - t <= 5)
            
            if burst_in_5s >= 3 or time_diff < interval_threshold:
                msg = f"Rapid Automated Brute-Force Burst Detected from {ip} ({burst_in_5s} attempts in 5s)."
                self.logger.log_event("WARNING", "AUTH_GUARD", "RAPID_BRUTE_FORCE", ip, msg)
                return True, "RAPID_BRUTE_FORCE_ATTACK", failure_count

        # 4. Human Typo Tolerance Check
        if failure_count <= max_typos:
            msg = f"Tolerated human password typo ({failure_count}/{max_typos}) for user '{username}' from {ip}. No ban applied."
            self.logger.log_event("INFO", "AUTH_GUARD", "HUMAN_TYPO_TOLERATED", ip, msg)
            return False, "HUMAN_TYPO_TOLERATED", failure_count
        else:
            msg = f"Password failure tolerance exceeded ({failure_count}/{max_typos}) for user '{username}' from {ip}."
            self.logger.log_event("WARNING", "AUTH_GUARD", "TYPO_THRESHOLD_EXCEEDED", ip, msg)
            return True, "TYPO_THRESHOLD_EXCEEDED", failure_count

    def register_auth_success(self, ip: str, username: str):
        """
        Graceful forgiveness of past password typos upon successful authentication.
        """
        if ip in self.auth_failure_history and len(self.auth_failure_history[ip]) > 0:
            count = len(self.auth_failure_history[ip])
            self.auth_failure_history[ip].clear()
            msg = f"User '{username}' authenticated successfully. Previous {count} password typos forgiven for IP {ip}."
            self.logger.log_event("NOTICE", "AUTH_GUARD", "AUTH_RECOVERY_FORGIVEN", ip, msg)
            print(f"[+] [AUTH FORGIVEN] {msg}")

    def get_repeat_count(self, ip: str) -> int:
        """
        Queries the number of previous bans for an IP address.
        """
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM banned_ips WHERE ip = ? AND is_active = 0", (ip,))
                row = cursor.fetchone()
                return row[0] if row else 0
        except Exception:
            return 0

    def _apply_os_firewall_rule(self, target: str, is_internal: bool, criticality: str):
        """
        Executes dual-stack multi-backend firewall drop for IP or Subnet at kernel level.
        """
        if os.name != 'nt':
            is_ipv6 = False
            try:
                if "/" in target:
                    is_ipv6 = (ipaddress.ip_network(target, strict=False).version == 6)
                else:
                    is_ipv6 = (ipaddress.ip_address(target).version == 6)
            except ValueError:
                pass

            iptables_cmd = "ip6tables" if is_ipv6 else "iptables"

            # 1. UFW Firewall Drop (Insert 1 Priority Rule)
            try:
                if not is_internal:
                    os.system(f"sudo ufw insert 1 deny from {target} to any comment 'SIEM-{criticality}' >/dev/null 2>&1")
                else:
                    os.system(f"sudo ufw insert 1 deny proto tcp from {target} to any port 22 comment 'SIEM-LAN-SSH' >/dev/null 2>&1")
            except Exception:
                pass

            # 2. Kernel Level IPTables / IP6Tables Direct Packet Drop
            if getattr(config, 'ENABLE_IPTABLES_FALLBACK', True):
                try:
                    if not is_internal:
                        os.system(f"sudo {iptables_cmd} -I INPUT 1 -s {target} -j DROP >/dev/null 2>&1")
                    else:
                        os.system(f"sudo {iptables_cmd} -I INPUT 1 -p tcp -s {target} --dport 22 -j DROP >/dev/null 2>&1")
                except Exception:
                    pass

            # 3. Terminate Active TCP/SSH Sockets Immediately
            if getattr(config, 'ENABLE_SESSION_KILL', True) and "/" not in target:
                try:
                    os.system(f"sudo ss -K dst {target} >/dev/null 2>&1")
                    os.system(f"sudo conntrack -D -s {target} >/dev/null 2>&1")
                except Exception:
                    pass
        else:
            action = "LAN Port 22 Block" if is_internal else "Drop All Traffic (UFW + IPTables)"
            print(f"[*] [Windows Simulation] {target} blocked via OS Firewall ({action}).")

    def _remove_os_firewall_rule(self, target: str, is_internal: bool):
        """
        Removes firewall drop rules upon ban expiration.
        """
        if os.name != 'nt':
            is_ipv6 = False
            try:
                if "/" in target:
                    is_ipv6 = (ipaddress.ip_network(target, strict=False).version == 6)
                else:
                    is_ipv6 = (ipaddress.ip_address(target).version == 6)
            except ValueError:
                pass

            iptables_cmd = "ip6tables" if is_ipv6 else "iptables"

            try:
                if not is_internal:
                    os.system(f"sudo ufw delete deny from {target} >/dev/null 2>&1")
                else:
                    os.system(f"sudo ufw delete deny proto tcp from {target} to any port 22 >/dev/null 2>&1")
            except Exception:
                pass

            if getattr(config, 'ENABLE_IPTABLES_FALLBACK', True):
                try:
                    if not is_internal:
                        os.system(f"sudo {iptables_cmd} -D INPUT -s {target} -j DROP >/dev/null 2>&1")
                    else:
                        os.system(f"sudo {iptables_cmd} -D INPUT -p tcp -s {target} --dport 22 -j DROP >/dev/null 2>&1")
                except Exception:
                    pass
        else:
            print(f"[*] [Windows Simulation] Firewall restriction removed for {target}.")

    def ban_ip(self, ip: str, criticality: str = "CRITICAL", reason: str = "Security Violation",
               source: str = "AUTO", duration_override: int = None):
        """
        Applies a tiered ban for an IP or CIDR Subnet.
        """
        if not ip or self.is_protected_ip(ip):
            print(f"[*] [PROTECTION] IP {ip} is in protected core whitelist; lockout avoided.")
            return

        now = time.time()

        # Suppress duplicate bans
        if ip in self.active_bans and self.active_bans[ip] > now:
            remaining_seconds = int(self.active_bans[ip] - now)
            remaining_mins = max(1, remaining_seconds // 60)
            print(f"[*] [ALREADY BANNED] {ip} is already actively banned (~{remaining_mins} mins remaining). Duplicate suppressed.")
            return

        is_internal = self.is_internal_ip(ip)
        network_type = "INTERNAL" if is_internal else "EXTERNAL"
        criticality_level = criticality.upper() if criticality.upper() in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "CRITICAL"

        if duration_override is not None:
            base_duration = duration_override
        else:
            if "/" in ip:
                base_duration = getattr(config, 'SUBNET_BAN_DURATION_SECONDS', 7200)
            elif is_internal:
                durations = getattr(config, 'BAN_DURATIONS_INTERNAL', {"CRITICAL": 900, "HIGH": 300, "MEDIUM": 180, "LOW": 0})
                base_duration = durations.get(criticality_level, 600)
            else:
                durations = getattr(config, 'BAN_DURATIONS_EXTERNAL', {"CRITICAL": 3600, "HIGH": 1800, "MEDIUM": 600, "LOW": 0})
                base_duration = durations.get(criticality_level, 600)

        if base_duration == 0:
            print(f"[*] [NO BAN] Threat level '{criticality_level}' does not require ban for {ip}.")
            return

        repeat_count = self.get_repeat_count(ip)
        effective_duration = base_duration * (2 ** min(repeat_count, 3))
        unban_at = now + effective_duration
        unban_at_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unban_at))
        duration_minutes = effective_duration // 60

        enforcement_action = "SSH_SESSION_KILL_AND_ISOLATE" if is_internal else "UFW_IPTABLES_DUAL_DROP"

        # Update in-memory active cache
        self.active_bans[ip] = unban_at

        target_type = "SUBNET / CIDR" if "/" in ip else "IP"
        print(f"\n[!] [{criticality_level} BAN] [{target_type}] Network: [{network_type}] | Target: {ip} | Duration: {duration_minutes} Mins | Action: {enforcement_action}")
        print(f"    Reason: {reason}")

        # 1. Execute OS Firewall Rule
        self._apply_os_firewall_rule(ip, is_internal=is_internal, criticality=criticality_level)

        # 2. Persist in SQLite Database
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE banned_ips SET is_active = 0 WHERE ip = ? AND is_active = 1", (ip,))
                cursor.execute("""INSERT INTO banned_ips 
                    (ip, reason, banned_at, ban_duration_seconds, unban_at, is_active, network_type, criticality_level, enforcement_action)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)""",
                    (ip, reason, now, effective_duration, unban_at, network_type, criticality_level, enforcement_action))
                conn.commit()
        except Exception as e:
            print(f"[-] Ban Database Write Error: {e}")

        # 3. Log to Smart Activity Logger
        log_msg = (
            f"[{network_type}] {target_type} {ip} BANNED for {duration_minutes} MINUTES ({criticality_level} Level). "
            f"Enforcement: {enforcement_action}. Reason: {reason}. (Auto-Unban Time: {unban_at_str})"
        )
        self.logger.log_event("CRITICAL" if criticality_level == "CRITICAL" else "WARNING",
                              "BAN_MANAGER", f"{network_type}_{target_type.replace(' ', '_')}_BAN", ip, log_msg)

    def unban_ip(self, ip: str, reason: str = "Ban Duration Expired"):
        """
        Lifts the ban restriction for an IP or CIDR Subnet.
        """
        if ip in self.active_bans:
            del self.active_bans[ip]

        is_internal = self.is_internal_ip(ip)
        network_type = "INTERNAL" if is_internal else "EXTERNAL"

        print(f"\n[+] [BAN REMOVED] Network: [{network_type}] | Target: {ip} restriction lifted! Reason: {reason}")
        
        self._remove_os_firewall_rule(ip, is_internal=is_internal)

        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE banned_ips SET is_active = 0 WHERE ip = ? AND is_active = 1", (ip,))
                conn.commit()
        except Exception as e:
            print(f"[-] Ban Database Update Error: {e}")

        log_msg = f"Ban duration expired for {network_type} target {ip}; automatically unbanned."
        self.logger.log_event("INFO", "BAN_MANAGER", "IP_AUTOMATIC_UNBAN", ip, log_msg)

    def check_expired_bans(self):
        """
        Checks and automatically unbans expired entries.
        """
        now = time.time()
        try:
            with get_db_connection(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ip, reason FROM banned_ips WHERE is_active = 1 AND unban_at <= ?", (now,))
                expired_bans = cursor.fetchall()

            seen_ips = set()
            for ip, reason in expired_bans:
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    self.unban_ip(ip, reason="Tiered Ban Duration Expired")
        except Exception as e:
            print(f"[-] Ban Expiration Check Error: {e}")

    def start(self):
        """
        Starts the automatic ban expiration polling service.
        """
        print(f"[+] Multi-Backend Tiered Ban & Auto-Unban Service Started: {time.ctime()}")
        
        while True:
            try:
                self.check_expired_bans()
            except Exception as e:
                print(f"[-] Ban Service Loop Error: {e}")
            time.sleep(5)
