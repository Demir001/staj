# -*- coding: utf-8 -*-
# ==============================================================================
# GÜVENLİK VE LOG İZLEME MODÜLÜ (log_monitor.py)
# ÇOKLU GERÇEK SİSTEM LOGU VE SYSLOG İZLEME MOTORU (/var/log/syslog, /var/log/auth.log vb.)
# 106 ADET AĞ VE SİSTEM GÜVENLİĞİ REGEX KURALLI GELİŞMİŞ TEHDİT TESPİT MOTORU,
# ÇOK KATMANLI YAPAY ZEKA GÜVENLİK MOTORU (Saf NumPy Ensemble + Zero-Day Autoencoder),
# İÇ VE DIŞ AĞ AYRIMLI KADEMELİ BAN YÖNETİMİ, İNSANİ YAZIM HATASI (TYPO) TOLERANSI
# ==============================================================================

import os        # Sistem seviyesi komutlar ve dosya kontrolü için os
import time      # Zaman takibi ve damgalamalar için time
import threading # Çoklu log dosyalarını eşzamanlı izlemek için threading
import config    # Yapılandırma ayarları için config
from collections import defaultdict, deque  # Risk skorları ve zaman penceresi için veri yapıları
import re        # 106 adet Regex kuralını çalıştırmak için re modülü
import json      # Log kayıtlarını JSON formatında saklamak için json
from modules.ban_manager import BanManager                 # Kademeli Ban ve Typo Yöneticisi
from modules.user_session_tracker import UserSessionTracker # Oturum ve Komut Takip Yöneticisi
from modules.ai_security_engine import AISecurityEngine     # Çok Katmanlı Yapay Zeka Güvenlik Motoru

class LogMonitor:
    def __init__(self, callback=None, ban_manager=None, session_tracker=None, ai_engine=None):
        # Callback, Ban Yöneticisi, Oturum Takip Yöneticisi ve Yapay Zeka Motoru Referansları
        self.callback = callback
        self.ban_manager = ban_manager or BanManager()
        self.session_tracker = session_tracker or UserSessionTracker()
        self.ai_engine = ai_engine or AISecurityEngine()
        
        # ----------------------------------------------------------------------
        # 106 ADET KATEGORİZE EDİLMİŞ AĞ VE GÜVENLİK REGEX TEHDİT DESENLERİ
        # ----------------------------------------------------------------------
        self.patterns = {
            # KATEGORİ 1: SSH VE UZAKTAN ERİŞİM GÜVENLİĞİ (12 KURAL)
            "SSH_INVALID_USER": (re.compile(r"Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)"), 25),
            "SSH_FAILED_PASS": (re.compile(r"Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)"), 15),
            "SSH_SUCCESS": (re.compile(r"Accepted (?:password|publickey) for (\w+) from (\d+\.\d+\.\d+\.\d+)"), 0),
            "SSH_LOGOUT": (re.compile(r"Disconnected from (?:user (\w+) )?(\d+\.\d+\.\d+\.\d+)"), 0),
            "SSH_PREAUTH_SCAN": (re.compile(r"Did not receive identification string from (\d+\.\d+\.\d+\.\d+)"), 20),
            "SSH_MAX_AUTH_EXCEEDED": (re.compile(r"error: maximum authentication attempts exceeded for (\w+) from (\d+\.\d+\.\d+\.\d+)"), 35),
            "SSH_ROOT_LOGIN_ATTEMPT": (re.compile(r"Accepted (?:password|publickey) for root from (\d+\.\d+\.\d+\.\d+)"), 50),
            "SSH_TUNNEL_ATTEMPT": (re.compile(r"refused local port forward.*from (\d+\.\d+\.\d+\.\d+)"), 40),
            "SSH_DIRECT_TCPIP": (re.compile(r"connect_to .* port \d+: failed.*from (\d+\.\d+\.\d+\.\d+)"), 30),
            "SSH_SFTP_REQUEST": (re.compile(r"subsystem request for sftp by user (\w+) from (\d+\.\d+\.\d+\.\d+)"), 5),
            "SSH_HOST_KEY_CHANGED": (re.compile(r"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED.*from (\d+\.\d+\.\d+\.\d+)"), 45),
            "SSH_CIPHER_MISMATCH": (re.compile(r"no matching cipher found.*from (\d+\.\d+\.\d+\.\d+)"), 15),

            # KATEGORİ 2: GÜVENLİK DUVARI VE YÖNLENDİRME İHLALLERİ (12 KURAL)
            "UFW_BLOCK_INBOUND": (re.compile(r"\[UFW BLOCK\] IN=(\w+) .* SRC=(\d+\.\d+\.\d+\.\d+) DST=(\d+\.\d+\.\d+\.\d+) .* PROTO=(\w+) DPT=(\d+)"), 10),
            "IPTABLES_DROP": (re.compile(r"\[IPTABLES DROP\] IN=(\w+) .* SRC=(\d+\.\d+\.\d+\.\d+) DST=(\d+\.\d+\.\d+\.\d+) .* PROTO=(\w+) DPT=(\d+)"), 10),
            "PFSENSE_BLOCK": (re.compile(r"filterlog.*block.*src (\d+\.\d+\.\d+\.\d+).*dst (\d+\.\d+\.\d+\.\d+)"), 10),
            "CISCO_ACL_DENY": (re.compile(r"%SEC-6-IPACCESSLOGP: list \w+ denied (\w+) (\d+\.\d+\.\d+\.\d+)"), 15),
            "MIKROTIK_DROP": (re.compile(r"firewall,info forward: in:\w+ out:\w+, src-mac .*, proto \w+, (\d+\.\d+\.\d+\.\d+)->(\d+\.\d+\.\d+\.\d+)"), 10),
            "IP_SPOOFING_MARTIAN": (re.compile(r"IPv4: martian source (\d+\.\d+\.\d+\.\d+) from (\d+\.\d+\.\d+\.\d+)"), 60),
            "BROADCAST_STORM": (re.compile(r"received packet on \w+ with own address as source.*SRC=(\d+\.\d+\.\d+\.\d+)"), 50),
            "UNAUTHORIZED_FORWARD": (re.compile(r"IP forwarding disabled.*SRC=(\d+\.\d+\.\d+\.\d+)"), 30),
            "LAND_ATTACK_DETECTED": (re.compile(r"LAND attack: SRC=(\d+\.\d+\.\d+\.\d+) equals DST"), 70),
            "TEARDROP_ATTACK": (re.compile(r"oversized Ethernet frame / fragmented packet from (\d+\.\d+\.\d+\.\d+)"), 65),
            "SMURF_ATTACK_PROBE": (re.compile(r"ICMP echo request to broadcast address from (\d+\.\d+\.\d+\.\d+)"), 55),
            "BGP_ROUTE_CHANGE": (re.compile(r"BGP-5-ADJCHANGE: neighbor (\d+\.\d+\.\d+\.\d+) Down"), 40),

            # KATEGORİ 3: AĞ PROTOKOL ANOMALİLERİ VE ZEHİRLEME (12 KURAL)
            "ARP_SPOOFING_DETECTED": (re.compile(r"arp: hardware address changed for (\d+\.\d+\.\d+\.\d+) from ([\da-fA-F:]+) to ([\da-fA-F:]+)"), 65),
            "DHCP_ROGUE_SERVER": (re.compile(r"dhcpd: DHCPNAK on (\d+\.\d+\.\d+\.\d+) from ([\da-fA-F:]+)"), 55),
            "DHCP_DISCOVER_FLOOD": (re.compile(r"DHCPDISCOVER from ([\da-fA-F:]+) via \w+: network \w+: no free leases"), 45),
            "DNS_AMPLIFICATION_QUERY": (re.compile(r"named.*query.*ANY.*from (\d+\.\d+\.\d+\.\d+)"), 40),
            "DNS_CACHE_POISONING": (re.compile(r"named.*lame server resolving.*from (\d+\.\d+\.\d+\.\d+)"), 50),
            "ICMP_UNREACHABLE_BURST": (re.compile(r"ICMP (\d+\.\d+\.\d+\.\d+) protocol (\d+) unreachable"), 20),
            "ICMP_REDIRECT_ATTACK": (re.compile(r"ICMP redirect received from (\d+\.\d+\.\d+\.\d+)"), 50),
            "IGMP_MEMBERSHIP_FLOOD": (re.compile(r"IGMP query flood detected from (\d+\.\d+\.\d+\.\d+)"), 40),
            "IPV6_RA_SPOOFING": (re.compile(r"ICMPv6-RA: Router Advertisement from unapproved link-local (\w+)"), 50),
            "NTP_MONLIST_AMPLIFICATION": (re.compile(r"ntpd.*monlist request from (\d+\.\d+\.\d+\.\d+)"), 45),
            "SSDP_AMPLIFICATION_FLOOD": (re.compile(r"SSDP M-SEARCH query flood from (\d+\.\d+\.\d+\.\d+)"), 40),
            "SNMP_BRUTE_FORCE": (re.compile(r"snmpd: Bad community name.*from (\d+\.\d+\.\d+\.\d+)"), 35),

            # KATEGORİ 4: AĞ TARAMA VE KEŞİF ARAÇLARI (10 KURAL)
            "NMAP_NULL_SCAN": (re.compile(r"\[UFW BLOCK\] .* SRC=(\d+\.\d+\.\d+\.\d+) .* PROTO=TCP DPT=\d+ WINDOW=0"), 35),
            "NMAP_XMAS_SCAN": (re.compile(r"\[UFW BLOCK\] .* SRC=(\d+\.\d+\.\d+\.\d+) .* PROTO=TCP.*FLAGS=FIN PSH URG"), 40),
            "NMAP_FIN_SCAN": (re.compile(r"\[UFW BLOCK\] .* SRC=(\d+\.\d+\.\d+\.\d+) .* PROTO=TCP.*FLAGS=FIN"), 30),
            "SYN_FLOOD_PROBE": (re.compile(r"TCP: Possible SYN flooding on port (\d+).*Sending cookies"), 50),
            "MASSCAN_BANNER_GRAB": (re.compile(r"Masscan connection attempt from (\d+\.\d+\.\d+\.\d+)"), 40),
            "ZMAP_SWEEP_DETECTED": (re.compile(r"ZMap network scan probe detected from (\d+\.\d+\.\d+\.\d+)"), 40),
            "HPING3_PACKET_PROBE": (re.compile(r"custom TCP raw packet injection from (\d+\.\d+\.\d+\.\d+)"), 45),
            "TCP_ACK_SCAN": (re.compile(r"\[UFW BLOCK\] .* SRC=(\d+\.\d+\.\d+\.\d+) .* PROTO=TCP.*FLAGS=ACK"), 25),
            "UDP_PORT_SWEEP": (re.compile(r"UDP port sweep from (\d+\.\d+\.\d+\.\d+) across multiple ports"), 35),
            "VULN_SCANNER_USERAGENT": (re.compile(r"(Nikto|sqlmap|Nmap|Gobuster|Dirbuster|Nuclei).*SRC=(\d+\.\d+\.\d+\.\d+)"), 50),

            # KATEGORİ 5: PAKET DİNLEME VE PROMISCUOUS MOD (8 KURAL)
            "NIC_PROMISCUOUS_ENTER": (re.compile(r"device (\w+) entered promiscuous mode"), 70),
            "NIC_PROMISCUOUS_LEAVE": (re.compile(r"device (\w+) left promiscuous mode"), 10),
            "BPF_FILTER_ATTACHED": (re.compile(r"BPF socket filter attached on interface (\w+)"), 50),
            "PCAP_CAPTURE_STARTED": (re.compile(r"pcap packet capture session started by UID (\d+)"), 45),
            "WIRESHARK_TCPDUMP_EXEC": (re.compile(r"process '(tcpdump|tshark|wireshark)' executed by (\w+)"), 40),
            "RAW_SOCKET_CREATED": (re.compile(r"user (\w+) opened raw network socket"), 45),
            "MAC_ADDRESS_CHANGED": (re.compile(r"interface (\w+): link MAC address changed to ([\da-fA-F:]+)"), 50),
            "PACKET_DROP_SPIKE": (re.compile(r"interface (\w+): excessive dropped packets count (\d+)"), 25),

            # KATEGORİ 6: VPN VE TÜNELLEME TEHDİTLERİ (10 KURAL)
            "OPENVPN_AUTH_FAILED": (re.compile(r"openvpn.*TLS Auth Error: Auth Username/Password Failed.*peer (\d+\.\d+\.\d+\.\d+)"), 25),
            "WIREGUARD_HANDSHAKE_FAIL": (re.compile(r"wireguard: Handshake for peer \w+ did not complete after.*from (\d+\.\d+\.\d+\.\d+)"), 20),
            "IPSEC_IKE_AUTH_ERROR": (re.compile(r"pluto.*IKE SA authentication failed with (\d+\.\d+\.\d+\.\d+)"), 30),
            "L2TP_DISCONNECT_BURST": (re.compile(r"xl2tpd.*Connection terminated from (\d+\.\d+\.\d+\.\d+)"), 15),
            "SSH_SOCKS_PROXY_OPEN": (re.compile(r"SSH dynamic SOCKS proxy tunnel requested by (\w+) from (\d+\.\d+\.\d+\.\d+)"), 35),
            "DNS_TUNNELING_QUERY": (re.compile(r"DNS TXT query length > 200 bytes from (\d+\.\d+\.\d+\.\d+)"), 55),
            "ICMP_TUNNELING_PROBE": (re.compile(r"ICMP echo payload size > 1000 bytes from (\d+\.\d+\.\d+\.\d+)"), 55),
            "GRE_TUNNEL_CREATED": (re.compile(r"GRE tunnel interface \w+ created from (\d+\.\d+\.\d+\.\d+)"), 40),
            "VXLAN_ENCAP_WARNING": (re.compile(r"VXLAN invalid VNI received from (\d+\.\d+\.\d+\.\d+)"), 30),
            "TOR_EXIT_NODE_CONN": (re.compile(r"Tor exit node connection established from (\d+\.\d+\.\d+\.\d+)"), 50),

            # KATEGORİ 7: FTP VE MAİL AĞ SERVİSLERİ (10 KURAL)
            "VSFTPD_FAILED_LOGIN": (re.compile(r"vsftpd.*FAIL LOGIN: Client \"(\d+\.\d+\.\d+\.\d+)\""), 20),
            "PROFTPD_ANON_ATTEMPT": (re.compile(r"proftpd.*ANONYMOUS FTP login attempt from (\d+\.\d+\.\d+\.\d+)"), 25),
            "POSTFIX_SASL_FAILED": (re.compile(r"postfix/smtpd.*warning: .*\[(\d+\.\d+\.\d+\.\d+)\]: SASL authentication failed"), 25),
            "DOVECOT_IMAP_BRUTE": (re.compile(r"dovecot: imap-login: Disconnected.*auth failed.*rip=(\d+\.\d+\.\d+\.\d+)"), 25),
            "SMTP_RELAY_ATTEMPT": (re.compile(r"postfix/smtpd.*relay access denied.*from \[(\d+\.\d+\.\d+\.\d+)\]"), 40),
            "FTP_BOUNCE_ATTEMPT": (re.compile(r"FTP PORT command to non-client IP from (\d+\.\d+\.\d+\.\d+)"), 55),
            "POP3_AUTH_ERROR": (re.compile(r"dovecot: pop3-login: Aborted login.*rip=(\d+\.\d+\.\d+\.\d+)"), 20),
            "MAIL_SPAM_FLOOD": (re.compile(r"Postfix rate limit exceeded for client \[(\d+\.\d+\.\d+\.\d+)\]"), 45),
            "RBL_BLACKLISTED_IP": (re.compile(r"blocked using RBL blacklist.*client \[(\d+\.\d+\.\d+\.\d+)\]"), 35),
            "FTP_CMD_INJECTION": (re.compile(r"FTP command injection payload from (\d+\.\d+\.\d+\.\d+)"), 60),

            # KATEGORİ 8: YETKİ YÜKSELTME VE TERS BAĞLANTI (REVERSE SHELL) (12 KURAL)
            "SUDO_EXECUTION": (re.compile(r"(\w+) : TTY=.* ; COMMAND=(.*)"), 5),
            "SUDO_FAILED_PASSWORD": (re.compile(r"(\w+) : (\d+) incorrect password attempts"), 20),
            "SUDO_ROOT_SHELL": (re.compile(r"(\w+) : TTY=.* ; COMMAND=.*(?:/bin/bash|/bin/sh|/bin/zsh|su root|su -)"), 65),
            "SU_TO_ROOT_SUCCESS": (re.compile(r"successful su for root by (\w+)"), 40),
            "NETCAT_REVERSE_SHELL": (re.compile(r"process '(nc|ncat|netcat)' launched with '-e' by (\w+)"), 80),
            "SOCAT_TUNNEL_EXEC": (re.compile(r"socat EXEC:.*TCP:(\d+\.\d+\.\d+\.\d+)"), 75),
            "PYTHON_REVERSE_SHELL": (re.compile(r"python.*socket.*connect\(.*(\d+\.\d+\.\d+\.\d+)"), 80),
            "BASH_DEV_TCP_SHELL": (re.compile(r"bash -i >& /dev/tcp/(\d+\.\d+\.\d+\.\d+)/\d+"), 85),
            "TTY_ALLOCATION_GRANT": (re.compile(r"grantpt: allocated pty slave device for UID (\d+)"), 20),
            "SUID_BINARY_EXECUTION": (re.compile(r"SUID binary '(.*)' executed by non-root UID (\d+)"), 50),
            "SHADOW_FILE_ACCESS": (re.compile(r"unauthorized read attempt on /etc/shadow by (\w+)"), 75),
            "CRON_JOB_ADDED": (re.compile(r"CRON.*\((\w+)\) CMD \(.*(\d+\.\d+\.\d+\.\d+).*\)"), 45),

            # KATEGORİ 9: KERNEL VE DONANIM ANOMALİLERİ (10 KURAL)
            "KERNEL_SEGFAULT": (re.compile(r"kernel: .* segfault at .* error \d+ in"), 40),
            "OOM_KILLER_TRIGGERED": (re.compile(r"kernel: Out of memory: Kill process (\d+) \((.*)\)"), 45),
            "NIC_LINK_DOWN": (re.compile(r"kernel: \w+: link down / carrier lost"), 30),
            "NIC_DRIVER_CRASH": (re.compile(r"kernel: \w+: driver reset failed / hardware error"), 50),
            "DMA_BUFFER_OVERFLOW": (re.compile(r"kernel: DMA buffer overflow on interface (\w+)"), 60),
            "RING_BUFFER_FULL": (re.compile(r"kernel: \w+: rx ring buffer full, dropping packets"), 35),
            "EBPF_PROGRAM_LOAD": (re.compile(r"bpf: loaded program TYPE_\w+ by UID (\d+)"), 40),
            "KERNEL_MODULE_INSERT": (re.compile(r"kernel: module '(\w+)' loaded into kernel by UID (\d+)"), 55),
            "SYSCTL_PARAM_CHANGED": (re.compile(r"sysctl: net\.ipv4\..* changed by (\w+)"), 35),
            "HARDWARE_INTERRUPT_FLOOD": (re.compile(r"kernel: do_IRQ: \d+\.\d+ No irq handler for vector"), 40),

            # KATEGORİ 10: HESAP YÖNETİMİ İHLALLERİ (10 KURAL)
            "USER_CREATED": (re.compile(r"new user: name=(\w+), UID=(\d+)"), 30),
            "USER_DELETED": (re.compile(r"delete user '(\w+)'"), 35),
            "PASSWORD_CHANGED": (re.compile(r"password changed for (\w+)"), 20),
            "GROUP_SUDO_ADD": (re.compile(r"add '(\w+)' to group '(?:sudo|wheel|root)'"), 70),
            "SHADOW_FILE_MODIFIED": (re.compile(r"user management updated /etc/shadow for (\w+)"), 50),
            "PAM_AUTH_FAILURE": (re.compile(r"pam_unix\(.*:auth\): authentication failure; logname=.* rhost=(\d+\.\d+\.\d+\.\d+)"), 20),
            "LOCKED_ACCOUNT_LOGIN": (re.compile(r"User (\w+) account is locked, login refused from (\d+\.\d+\.\d+\.\d+)"), 30),
            "GPASSWD_GROUP_CHANGE": (re.compile(r"gpasswd: user (\w+) added to group (\w+) by (\w+)"), 40),
            "EXPIRED_PASS_LOGIN": (re.compile(r"User (\w+) password has expired, login refused from (\d+\.\d+\.\d+\.\d+)"), 25),
            "MAX_SESSIONS_EXCEEDED": (re.compile(r"Too many active sessions for user (\w+) from (\d+\.\d+\.\d+\.\d+)"), 30)
        }

        # Tehdit Takip Veri Yapıları
        self.failed_attempts = defaultdict(deque)
        self.ip_risk_score = defaultdict(float)

    def tail_file(self, file_path: str):
        # Tek bir log dosyasını canlı ve kesintisiz izleyen iş parçacığı
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as log:
                # Dosyanın sonuna git
                log.seek(0, 2)
                print(f"[+] Live Tailing Active: {file_path}")
                while True:
                    line = log.readline()
                    if not line:
                        time.sleep(0.3)
                        continue
                    self.parse_line(line, source_file=file_path)
        except PermissionError:
            print(f"[-] Permission Denied for {file_path}. Try running with sudo.")
        except Exception as e:
            print(f"[-] Error tailing {file_path}: {e}")

    def start(self):
        # Çoklu Gerçek Sistem Loglarını (/var/log/syslog, /var/log/auth.log vb.) Keşfeder ve Başlatır
        print(f"[+] 106-Rule & Dual-AI Security Log Monitor Initializing: {time.ctime()}")
        
        target_paths = getattr(config, "SYSTEM_LOG_PATHS", ["/var/log/auth.log", "/var/log/syslog", "logs/auth.log"])
        active_files = []

        for p in target_paths:
            if os.path.exists(p) and os.path.isfile(p):
                active_files.append(p)
            elif not os.path.isabs(p):
                # Yerel test dosyası yoksa otomatik oluştur
                os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
                if not os.path.exists(p):
                    with open(p, "w", encoding="utf-8") as f:
                        f.write(f"# Local log file created for {p}\n")
                active_files.append(p)

        if not active_files:
            print("[-] WARNING: No system log files accessible! Please check permissions.")
            return

        print(f"[+] Monitoring {len(active_files)} System Log File(s): {', '.join(active_files)}")

        # Her log dosyası için bağımsız canlı okuyucu thread'i başlatır
        for path in active_files:
            t = threading.Thread(target=self.tail_file, args=(path,), daemon=True)
            t.start()

        # Ana izleme thread'ini canlı tutar
        while True:
            time.sleep(1)

    def parse_line(self, line: str, source_file: str = "syslog"):
        # Gelen ham log satırını hem 106 Regex Kuralı hem de Çok Katmanlı Yapay Zeka ile analiz eder
        cleaned_line = line.strip()
        if not cleaned_line:
            return

        ip = "LOCAL_SYSTEM"
        user = "UNKNOWN"
        matched_rule = None
        base_score = 0

        # 1. 106 Regex Kuralı Taraması
        for event_type, (pattern, score) in self.patterns.items():
            match = pattern.search(cleaned_line)
            if match:
                matched_rule = event_type
                base_score = score
                groups = match.groups()
                
                for g in groups:
                    if g and re.match(r"^\d+\.\d+\.\d+\.\d+$", str(g)):
                        ip = str(g)
                    elif g and not re.match(r"^\d+$", str(g)):
                        user = str(g)

                # A. Başarılı Girişte Hataları Affetme ve Oturum Başlatma
                if event_type == "SSH_SUCCESS":
                    self.ban_manager.register_auth_success(ip=ip, username=user)
                    self.session_tracker.start_session(username=user, source_ip=ip, tty="pts/0")
                    self.ip_risk_score[ip] = 0.0
                    self.failed_attempts[ip].clear()
                    if self.callback:
                        self.callback("SSH_SUCCESS", ip, f"User '{user}' authenticated successfully from {ip}.")

                # B. Oturum Kapatma
                elif event_type == "SSH_LOGOUT":
                    self.session_tracker.end_session(username=user, source_ip=ip, tty="pts/0")

                # C. Komut Çalıştırma Takibi
                elif event_type == "SUDO_EXECUTION" and len(groups) >= 2:
                    cmd = groups[1]
                    self.session_tracker.record_command(username=user, source_ip=ip, command=cmd, tty="pts/0")

                # D. İnsani Parola Hatası (Typo) vs Kasıtlı Brute-Force Ayrımı
                elif event_type in ["SSH_FAILED_PASS", "SSH_INVALID_USER"]:
                    is_malicious, failure_type, count = self.ban_manager.register_auth_failure(ip=ip, username=user)
                    if not is_malicious:
                        # İnsani yazım hatası
                        base_score = 5
                        if self.callback:
                            self.callback("SSH_FAILED_PASS", ip,
                                          f"Password typo for user '{user}' from {ip} (Tolerated attempt {count}).")
                    else:
                        base_score = 25 if failure_type == "MALICIOUS_DICTIONARY_PROBE" else 35
                        if self.callback:
                            self.callback("SSH_FAILED_PASS", ip,
                                          f"Suspicious auth failure ({failure_type}) for user '{user}' from {ip} (Attempt {count}).")
                break

        if ip == "LOCAL_SYSTEM":
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', cleaned_line)
            if ip_match:
                ip = ip_match.group(0)

        # 2. ÇOK KATMANLI YAPAY ZEKA GÜVENLİK ANALİZİ
        ai_res = self.ai_engine.analyze(cleaned_line)
        
        # AI Saldırı veya Sıfır-Gün Tespiti Durumunda Dinamik Risk Puanı Ekleme
        if ai_res.get("is_attack"):
            ai_verdict = ai_res.get("verdict", "ATTACK")
            urgency = ai_res.get("urgency", "HIGH")
            
            ai_score = 40.0
            criticality = "HIGH"
            if urgency == "CRITICAL":
                ai_score = 75.0
                criticality = "CRITICAL"
            elif ai_verdict == "ZERO_DAY":
                ai_score = 65.0
                criticality = "HIGH"
            
            event_name = "AI_ZERO_DAY_ANOMALY" if ai_verdict == "ZERO_DAY" else "AI_ATTACK_DETECTED"
            self.threat_event(ip=ip, user=user, score=ai_score, event=event_name, ai_info=ai_res, criticality=criticality)
        elif matched_rule and base_score > 0:
            crit = "CRITICAL" if base_score >= 60 else ("HIGH" if base_score >= 35 else "MEDIUM")
            self.threat_event(ip=ip, user=user, score=base_score, event=matched_rule, ai_info=ai_res, criticality=crit)

        log_data = {"user": user, "ip": ip, "event": matched_rule or ai_res.get("verdict"), "timestamp": time.ctime(), "source_file": source_file, "ai_analysis": ai_res}
        self.write_log_json(log_data)

    def write_log_json(self, log_dict):
        try:
            with open("log.json", "a") as log_file:
                log_file.write(json.dumps(log_dict) + "\n")
        except Exception as e:
            print(f"[-] JSON Log Write Error: {e}")

    def threat_event(self, ip, user, score, event, ai_info=None, criticality="MEDIUM"):
        # Akıllı Risk Skoru Hesaplama ve BanManager İle Kademeli Banlama
        if not ip or ip == "LOCAL_SYSTEM" or self.ban_manager.is_protected_ip(ip):
            return

        now = time.time()
        window = getattr(config, "TIME_WINDOW", 600)
        
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = deque() 

        while self.failed_attempts[ip] and (now - self.failed_attempts[ip][0]['time'] > window):
            old_event = self.failed_attempts[ip].popleft()
            self.ip_risk_score[ip] -= old_event['score']
            if self.ip_risk_score[ip] < 0:
                self.ip_risk_score[ip] = 0.0

        burst_multiplier = 1.0
        recent_burst = sum(1 for e in self.failed_attempts[ip] if now - e['time'] <= 10)
        if recent_burst >= 5:
            burst_multiplier = 1.5

        final_score = score * burst_multiplier

        self.failed_attempts[ip].append({'time': now, 'score': final_score, 'type': event})
        self.ip_risk_score[ip] += final_score            
        current_score = self.ip_risk_score[ip]
        total_attempts = len(self.failed_attempts[ip])

        if self.callback and score > 0:
            mitre_id = ai_info.get("mitre_id", "N/A") if isinstance(ai_info, dict) else "N/A"
            msg = f"THREAT({event}) | Target: {ip} | Risk: {current_score:.1f}/50 | MITRE: {mitre_id} | Level: {criticality}"
            self.callback(event, ip, msg)

        # Risk Skoru Sınırı (50) Aşıldığında BanManager İle Kademeli Banlama
        risk_threshold = getattr(config, "RISK_SCORE_THRESHOLD", 50)
        if current_score >= risk_threshold:
            reason_msg = f"Cumulative Risk Exceeded ({current_score:.1f}/{risk_threshold} - {total_attempts} Events - Triggered by {event})"
            
            if self.callback:
                self.callback("ADVANCED_THREAT_DETECTED", ip,
                              f"CRITICAL THREAT! IP: {ip} | Risk: {current_score:.1f} | Tiered {criticality} Ban Applied.")
            
            # BanManager İle İç/Dış Ağ ve Kritiklik Düzeyine Göre Kademeli Ban Uygulama
            self.ban_manager.ban_ip(ip=ip, criticality=criticality, reason=reason_msg)

            self.failed_attempts[ip].clear()
            self.ip_risk_score[ip] = 0.0