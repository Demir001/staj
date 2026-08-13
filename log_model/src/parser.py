# File: src/parser.py
import re
import shlex
import urllib.parse
import math

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    for char in set(text):
        p_x = float(text.count(char)) / len(text)
        entropy -= p_x * math.log2(p_x)
    return entropy

def normalize_obfuscation(text):
    if not text:
        return ""
    text = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r"'/|'|\"", "", text)
    text = re.sub(r'IFS=[^\s;]+', ' ', text)
    if '%' in text:
        try:
            text = urllib.parse.unquote(text)
        except Exception:
            pass
    return text

def abstract_tokens(text):
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '<IP>', text)
    text = re.sub(r'\b0x[a-fA-F0-9]+\b|\bidVendor=[a-fA-F0-9]+', '<HEX>', text)
    text = re.sub(r'"[A-Za-z0-9+/=]{20,}"|\'[A-Za-z0-9+/=]{20,}\'', '<B64_BLOB>', text)
    return text

def clean_syslog_header(raw_log):
    # Tarih ve hostname temizleme
    clean = re.sub(r'^[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+', '', str(raw_log)).strip()
    parts = clean.split(' ', 4)
    msg = parts[4] if len(parts) >= 5 else clean
    msg = re.sub(r'^(?:Executed:|CMD\s*\(|msg=.*cmd=)', '', msg).strip()
    return msg

def parse_log_triple_space(raw_log):
    msg_clean = clean_syslog_header(raw_log)
    
    # İstatistiksel / Evrensel Özellik Tespiti
    entropy = calculate_shannon_entropy(msg_clean)
    critical_symbols = len(re.findall(r'[\%\$\;\|\>\<\&\{\}\\\?\*]', msg_clean))

    msg_normalized = normalize_obfuscation(msg_clean)
    msg_abstracted = abstract_tokens(msg_normalized)
    
    exec_tokens = []
    arg_tokens = []
    anomaly_tokens = []
    
    # Anomali Bayraklarını Anomaly Space'e ekle
    if critical_symbols >= 4:
        anomaly_tokens.append("__HIGH_SYMBOL__")
    if entropy >= 4.0:
        anomaly_tokens.append("__HIGH_ENTROPY__")
        
    anomaly_primitives = [
        'checkpoint-action', 'core.pager', 'ld_preload', 'chpasswd', 'shadow',
        'exec=', '-exec', '-execdir', '--arg=', 'io::socket', 'child_process', 'import pty',
        'system(', 'passthru(', 'popen(', 'eval(', '/dev/tcp/', 'socat',
        'touch -r', 'chmod +x', 'chmod 777', 'chmod 4755', 'b64decode', 'base64 -d',
        '/bin/sh', '/bin/bash', '/bin/dash', 'exec /bin/', 'system(/bin/'
    ]
    
    msg_lower = msg_abstracted.lower()
    for prim in anomaly_primitives:
        if prim in msg_lower:
            anomaly_tokens.append(prim)

    if any(http_tag in msg_abstracted for http_tag in ['HTTP/1.', 'GET /', 'POST /']):
        if '?' in msg_abstracted:
            try:
                query_str = msg_abstracted.split('?', 1)[1].split(' HTTP/1.')[0]
                exec_tokens.append(query_str)
            except IndexError:
                pass

    is_service_account = any(svc in msg_lower for svc in ['www-data', 'apache', 'nginx', 'nobody'])
    if is_service_account and 'command=' in msg_lower:
        cmd_part = msg_lower.split('command=')[1]
        exec_tokens.append(cmd_part)

    if any(pipe_sh in msg_lower for pipe_sh in ['| sh', '| bash', '| perl', '| python', '| $shell']):
        exec_tokens.append(msg_abstracted)

    sub_cmds = re.split(r'&&|\|\||;|\|', msg_abstracted)
    
    for sub in sub_cmds:
        sub = sub.strip()
        if not sub:
            continue
        try:
            tokens = shlex.split(sub)
        except Exception:
            tokens = sub.split()
            
        if not tokens:
            continue
            
        cmd_head = tokens[0].lower()
        sub_str = " ".join(tokens).lower()
        
        has_primitive = any(prim in sub_str for prim in anomaly_primitives)
        
        if has_primitive or any(t in ['-c', '-e'] for t in tokens):
            exec_tokens.extend(tokens)
        elif any(cmd_head.endswith(verb) for verb in ['grep', 'find', 'awk', 'sed', 'certbot', 'ls', 'stat', 'psql', 'vacuumdb', 'journalctl', 'docker', 'kubelet']):
            exec_tokens.append(cmd_head)
            arg_tokens.extend(tokens[1:])
        else:
            exec_tokens.append(cmd_head)
            arg_tokens.extend(tokens[1:])
            
    exec_space = " ".join(exec_tokens)
    arg_space = " ".join(arg_tokens)
    anomaly_space = " ".join(anomaly_tokens)
    
    return exec_space, arg_space, anomaly_space