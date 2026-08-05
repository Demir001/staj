import os
import time
import config
from collections import defaultdict, deque
import re

class LogMonitor:
    def __init__(self,callback):
        self.callback = callback
        self.ssh_invalid_user = re.compile(r"Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)")
        self.ssh_failed = re.compile(r"Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)")
        self.ssh_success_patern = re.compile(r"Accepted (?:password|publickey) for (\w+) from (\d+\.\d+\.\d+\.\d+)")
        self.ssh_logout = re.compile(r"Disconnected from (?:user (\w+) )?(\d+\.\d+\.\d+\.\d+)")
        self.ssh_preauth = re.compile(r"Did not receive identification string from (\d+\.\d+\.\d+\.\d+)") #Port Scanning
        self.sudo = re.compile(r"(\w+) : TTY=.* ; COMMAND=(.*)")
        self.sudo_failed_pattern = re.compile(r"(\w+) : (\d+) incorrect password attempts")
        self.new_user_created = re.compile(r"new user: name=(\w+), UID=(\d+)")
        self.password_changed_pattern = re.compile(r"password changed for (\w+)")
        self.ufw_block = re.compile(r"\[UFW BLOCK\] IN=(\w+) .* SRC=(\d+\.\d+\.\d+\.\d+) DST=(\d+\.\d+\.\d+\.\d+) .* PROTO=(\w+) DPT=(\d+)") #for port scan detection
        self.failed_attempts = defaultdict(deque)
        self.ip_risk_score = defaultdict(float)
        self.port_scan_tracker = defaultdict(set)
        self.active_ssh_sessions = defaultdict(set)
        self.sudo_failed_attempts = defaultdict(int)
    def start(self):
        print("LOG MONITOR STARTED AT {}".format(time.ctime()))
        log_path = getattr(config, "LINUX_AUTH_LOG_PATH","/var/log/auth.log")
        try:
            with open(log_path,"r") as log:
                log.seek(0, 2) #for live log not the old ones
                while True:
                    line = log.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    self.parse_line(line)
        except PermissionError:
            print("ERROR: Unauthorized. {} can not accessible. ".format(log_path))    
        except Exception:
            print("Error")            
    def parse_line(self,line):
        time_tracker = time.time()
        invalid_user = self.ssh_invalid_user.search(line)
        if invalid_user:
            user, ip = invalid_user.groups()
            self.threat_event(ip,user,score=25,event="SSH_INVALID_USER_ATTEMPT")
            return
        invalid_pass = self.ssh_failed.search(line)
        if invalid_pass:
            user, ip = invalid_pass.groups()
            self.threat_event(ip,user,score=10,event="SSH_INVALID_PASSWORD_ATTEMPT")
            return
        port_scan_attempt = self.ssh_preauth.search(line)
        if port_scan_attempt:
            ip = port_scan_attempt.group(1)
            self.threat_event(ip,user="UNKNOWN",score=15,event="SSH_PORT_SCAN_ATTEMPT")
            return
        ssh_success = self.ssh_success_patern.search(line)
        if ssh_success:
            user, ip = ssh_success.groups()
            self.active_ssh_sessions[ip].add(user)
            self.callback("SSH_SUCCESSFUL_LOGIN", ip, "Successful login | User: {} | IP: {}".format(user,ip))
            return
        ssh_logout1 = self.ssh_logout.search(line)
        if ssh_logout1:
            user, ip = ssh_logout1.groups()
            if ip in self.active_ssh_sessions:
                self.active_ssh_sessions[ip].discard(user)
            self.callback("SSH_DISCONNECTED",ip, "SSH Logout | User: {} | IP: {}".format(user,ip))
            return
        new_user = self.new_user_created.search(line)
        if new_user:
            username, userid = new_user.groups()
            self.callback("USER_CREATED",None,"New user created! Username {} | UID: {}".format(username,userid))
            return
        passwd = self.password_changed_pattern.search(line)
        if passwd:
            user = passwd.groups()
            self.callback("PASSWORD_CHANGED",None,"Password changed! | User: {}".format(user))
        sudo_attempt = self.sudo.search(line)    
        if sudo_attempt:
            user, tty, pwd, target_u, command = sudo_attempt.groups()
            self.callback("SUDO_COMMAND_EXECUTION",None,"Sudo command used! | User: {} | Target: {} | Index: {} | Command {}".format(user,target_u,pwd,command.strip()))
            return   
        sudo_failed = self.sudo_failed_pattern.search(line)
        if sudo_failed:
            user, attempts = sudo_failed.groups()
            self.callback("SUDO_FAILED_PASSWORD",None, "Incorrect sudo password! | User: {} | Attempts: {}".format(user,attempts))
            return
        ufw_det = self.ufw_block.search(line)
        if ufw_det:
            in_iface, src_ip, dst_ip, protocol, dst_port = ufw_det.groups()
            self.port_scan_tracker[src_ip].add(dst_port)
            if len(self.port_scan_tracker[src_ip]) > 3: #if IP try to access more then 3 port 
                self.threat_event(src_ip,user="SCANNER",score=20,event="PORT_SCAN_DETECTED")
                return
    def threat_event(self,ip,user,score,event):
        now = time.time()
        window = getattr(config, "TIME_WINDOW", 60)  #O(1) Time Cleanup: Remove old records outside the time window from the deque.                      
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = deque() 
        while self.failed_attempts[ip] and (now - self.failed_attempts[ip][0]['time'] > window):
            old_event = self.failed_attempts[ip].popleft()
            self.ip_risk_score[ip] -= old_event['score']
        self.failed_attempts[ip].append({'time': now, 'score': score, 'type': event})
        self.ip_risk_score[ip] += score            
        current_score = self.ip_risk_score[ip]
        total_attempts = len(self.failed_attempts[ip])
        self.callback(event, ip,"THREAT({}) | User: {} | IP: {} | Risk Score: {}".format(event,user,ip,current_score))
        if current_score >= config.RISK_SCORE_THRESHOLD:
            msg = (f"GELİŞMİŞ TEHDİT/BRUTE-FORCE TESPİT EDİLDİ! "
                   f"IP: {ip} | Total Risk Score: {current_score}/{config.RISK_SCORE_THRESHOLD} | Total attempts: {total_attempts}")      
            self.callback("ADVANCED_THREAT_DETECTED", ip, msg)
            self.failed_attempts[ip].clear()
            self.ip_risk_score[ip] = 0.0
            if ip in self.port_scan_tracker:
                self.port_scan_tracker[ip].clear()