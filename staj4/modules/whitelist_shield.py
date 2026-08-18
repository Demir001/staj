# -*- coding: utf-8 -*-
"""
==============================================================================
SMART FALSE-POSITIVE WHITELIST SHIELD (whitelist_shield.py)
==============================================================================
This module recognizes authentic system daemon operations, observability sweeps,
and DevOps automation routines (Systemd, Certbot, Logrotate, Prometheus, Dpkg,
PostgreSQL checkpoints, Docker daemon) to eliminate false alarms and prevent
unintended risk accumulation.
==============================================================================
"""

import re

# Pre-compiled high-performance benign signatures
KNOWN_BENIGN_PATTERNS = [
    # Systemd & Kernel Events
    re.compile(r"systemd(?:-logind|-resolved|-timesyncd)?(?:\[\d+\])?: (?:Started Session|Starting Daily Cleanup|Reached target|Clock synchronized|Created slice|Starting Rotate log files)"),
    re.compile(r"kernel: (?:\[\s*\d+\.\d+\] )?(?:usb|EXT4-fs|TCP: cubic|eth0: Link is Up|Memory:|thermal)"),
    re.compile(r"NetworkManager(?:\[\d+\])?: <info>.*dhcp4.*state changed bound"),

    # Package Management & Updates (Apt, Dpkg, Snap, PackageKit)
    re.compile(r"dpkg(?:\[\d+\])?: status installed \S+"),
    re.compile(r"systemd(?:\[\d+\])?: Started Daily apt download activities"),
    re.compile(r"packagekitd(?:\[\d+\])?: (?:Request process transaction completed|Transaction active)"),
    re.compile(r"freshclam(?:\[\d+\])?: daily\.cvd updated"),

    # Certificate Renewal & Scheduled Maintenance (Certbot, Logrotate, Cron Daily)
    re.compile(r"certbot(?:\[\d+\])?: Renewal configuration file.*is valid"),
    re.compile(r"CRON(?:\[\d+\])?: \(root\) CMD \(.*certbot.*renew.*\)"),
    re.compile(r"CRON(?:\[\d+\])?: \(root\) CMD \(.*run-parts --report /etc/cron\.daily.*\)"),
    re.compile(r"logrotate(?:\[\d+\])?: ALERT syslog's size has reached"),

    # Observability, Healthchecks & Metrics (Prometheus, KubeProbe)
    re.compile(r"prometheus(?:\[\d+\])?: level=info.*(?:Scrape loop completed|WAL segment loaded|Head GC completed)"),
    re.compile(r"GET /(?:metrics|healthz|livez|health|favicon\.ico|robots\.txt|sitemap\.xml) HTTP/1\.[01]\" 200"),
    re.compile(r"User-Agent: (?:Prometheus|KubeProbe|OpenTelemetry|Datadog Agent|Googlebot)"),

    # Database Maintenance Checkpoints (PostgreSQL, MySQL, Redis)
    re.compile(r"postgres(?:\[\d+\])?:.*LOG: (?:checkpoint starting|checkpoint complete|autovacuum:|automatic analyze)"),
    re.compile(r"mysqld(?:\[\d+\])?:.*\[Note\] InnoDB: Buffer pool.*load completed"),
    re.compile(r"redis(?:\[\d+\])?:.*DB saved on disk; RDB snapshot created"),

    # Safe Sudo Administration Commands
    re.compile(r"COMMAND=.*(?:/usr/bin/openssl x509 -in|/usr/sbin/nginx -t|/usr/bin/journalctl --vacuum-time|/usr/bin/ufw status|/usr/bin/git pull|/usr/bin/htop|/usr/bin/uptime|/usr/bin/free -h|/usr/bin/dmesg -T)")
]

class WhitelistShield:
    @classmethod
    def is_known_benign(cls, log_line: str) -> bool:
        """
        Fast lookup to check if a log line represents a known legitimate system activity.
        """
        if not log_line:
            return False

        for pattern in KNOWN_BENIGN_PATTERNS:
            if pattern.search(log_line):
                return True

        return False
