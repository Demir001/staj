# -*- coding: utf-8 -*-
# ==============================================================================
# ÇOK KATMANLI YAPAY ZEKA GÜVENLİK MOTORU (ai_security_engine.py)
# Bu modül 2 güçlü Yapay Zeka model mimarisini birleştirir:
# 1. MODEL: 4'lü Ensemble Sınıflandırıcı + Sıfır-Gün (Zero-Day) Rekonstrüksiyon Autoencoder'ı
# 2. MODEL: PyTorch Derin Olay Sınıflandırıcı (Char-Embedding -> Multi-Kernel 1D-CNN -> BiLSTM -> Self-Attention)
# MITRE ATT&CK ve SOC Playbook haritalandırması ile kesin ve hızlı tespit sağlar.
# ==============================================================================

import os        # Dosya ve dizin yönetimi için os
import sys       # Modül ve sistem yolları için sys
import re        # Metin temizleme ve regex kontrolleri için re
import time      # Zaman ve performans ölçümleri için time
import math      # Matematiksel hesaplamalar için math
from typing import Dict, List, Tuple, Any, Union # Tip ipuçları için typing

import joblib    # Model ağırlıklarını ve Tfidf nesnelerini yüklemek için joblib
import torch     # Derin öğrenme ve tensör işlemleri için PyTorch
import torch.nn as nn
import torch.nn.functional as F

# CPU ve GPU Deserializasyon Güvenliği (CUDA olmayan sistemlerde otomatik CPU eşleme)
if not torch.cuda.is_available():
    import torch.serialization
    torch.serialization.default_restore_location = lambda storage, loc: storage
    torch.serialization._cuda_deserialize = lambda obj, location: obj


# ==============================================================================
# 1. KURAL TABANLI GÜVENLİK MUHAFIZI VE MITRE HARİTALANDIRMASI (Layer 0)
# ==============================================================================
class DeterministicGuardrail:
    """Yapay zekanın kaçırmasını veya yanılmasını önleyen sert güvenlik katmanı."""

    CRITICAL_ATTACK_PATTERNS = [
        r'/dev/(tcp|udp)/\d{1,3}\.',
        r'exec\s+/bin/(bash|sh)',
        r'chmod\s+(\+s|4755|777)',
        r'chpasswd.*root',
        r'NOPASSWD:\s*ALL',
        r'import\s+pty.*spawn',
        r'base64\s+(-d|--decode)\s*\|',
        r'curl\s+.*\|\s*(sh|bash)',
        r'wget\s+.*\|\s*(sh|bash)',
        r'document\.cookie',
        r'union\s+select\s+',
        r'<!doctype\s+.*<!entity'
    ]

    SAFE_SYSTEM_PATTERNS = [
        r'systemd\[\d+\]:\s+(Started|Starting|Reached target|Listening on)',
        r'kernel:\s+\[.*\]\s+(usb|EXT4-fs|TCP|eth0|ACPI):',
        r'GET\s+/(favicon\.ico|static/|assets/|robots\.txt)\s+HTTP/1\.[01]"\s+(200|304)'
    ]

    @classmethod
    def check_hard_rules(cls, raw_log: str) -> dict:
        for pattern in cls.CRITICAL_ATTACK_PATTERNS:
            if re.search(pattern, raw_log, re.IGNORECASE):
                return {
                    "override": True,
                    "verdict": "ATTACK",
                    "confidence": 100.0,
                    "detail": "Deterministic Guardrail: Critical Exploit Pattern Detected"
                }

        for pattern in cls.SAFE_SYSTEM_PATTERNS:
            if re.search(pattern, raw_log, re.IGNORECASE):
                return {
                    "override": True,
                    "verdict": "SAFE",
                    "confidence": 100.0,
                    "detail": "Deterministic Guardrail: Verified Benign System Operation"
                }

        return {"override": False}


def detect_mitre_threat(raw_log: str) -> dict:
    """Log metnini analiz ederek MITRE ATT&CK taktik ve teknik ID'sini belirler."""
    log_lower = raw_log.lower()
    if any(k in log_lower for k in ['union select', 'information_schema', 'select null', 'sleep(']):
        return {"category": "SQL Injection", "mitre_id": "T1190"}
    if any(k in log_lower for k in ['/../', '..\\', 'etc/passwd', 'etc/shadow', 'php://filter']):
        return {"category": "Path Traversal / LFI", "mitre_id": "T1083"}
    if any(k in log_lower for k in ['/bin/sh', '/bin/bash', 'eval-stdin.php', 'shell.php', 'system(']):
        return {"category": "Remote Code Execution (RCE)", "mitre_id": "T1059.004"}
    if any(k in log_lower for k in ['chmod +s', 'chmod 4755', 'nopasswd', 'chpasswd', 'ld_preload']):
        return {"category": "Privilege Escalation", "mitre_id": "T1068"}
    if any(k in log_lower for k in ['<script', 'javascript:', 'document.cookie', 'onerror=']):
        return {"category": "Cross-Site Scripting (XSS)", "mitre_id": "T1189"}
    if any(k in log_lower for k in ['<!entity', '<!doctype', 'system "', '"]>']):
        return {"category": "XML External Entity (XXE)", "mitre_id": "T1190"}
    if any(k in log_lower for k in ['/dev/tcp/', 'socat', 'nc -e', 'import pty', 'mkfifo']):
        return {"category": "Reverse Shell / C2 Tunnel", "mitre_id": "T1090"}
    return {"category": "Known Attack Vector", "mitre_id": "T1210"}


# ==============================================================================
# 2. ÜÇLÜ UZAY LOG PARSER VE ÖZNİTELİK ÇIKARICI (Triple-Space Parser)
# ==============================================================================
def parse_log_triple_space(log_text: str) -> Tuple[str, str, str]:
    """Log satırını Çalıştırılabilir Dosya, Argümanlar ve Anomali İpuçları olarak 3 uzaya ayırır."""
    patterns = [
        re.compile(r'(?P<cmd>\b[a-zA-Z0-9_\-\./]+)(?:\s+(?P<args>.*))?'),
        re.compile(r'"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(?P<path>[^\s]+)\s+HTTP/[0-9\.]+"\s+(?P<status>\d+)'),
        re.compile(r'(?P<service>[a-zA-Z0-9_\-]+)\[\d+\]:\s+(?P<msg>.*)'),
    ]

    for pat in patterns:
        match = pat.search(log_text)
        if match:
            gd = match.groupdict()
            executable = gd.get('cmd') or gd.get('method') or gd.get('service') or "unknown_exec"
            arguments = gd.get('args') or gd.get('path') or gd.get('msg') or "no_args"
            break
    else:
        parts = log_text.strip().split(maxsplit=1)
        executable = parts[0] if parts else "unknown_exec"
        arguments = parts[1] if len(parts) > 1 else "no_args"

    suspicious_chars = ["'", '"', ";", "|", "&", "`", "$", "<", ">", "\\", "%", "..", "(", ")", "{", "}"]
    anomaly_tokens = []

    for char in suspicious_chars:
        count = log_text.count(char)
        if count > 0:
            anomaly_tokens.append(f"SYM_{char}_{count}")

    if any(k in log_text.lower() for k in ["union", "select", "base64", "eval", "exec", "passwd", "shadow", "null", "sleep"]):
        anomaly_tokens.append("KW_SUSPICIOUS")

    anomaly_features = " ".join(anomaly_tokens) if anomaly_tokens else "ANOMALY_CLEAN"
    return executable, arguments, anomaly_features


# ==============================================================================
# 3. 1. MODEL KATMANI: ENSEMBLE CLASSIFIER & AUTOENCODER (log_model)
# ==============================================================================
class GPUClassifierModel(nn.Module):
    """Ensemble bileşeni olan GPU/CPU Lojistik Regresyon / Doğrusal Katman."""
    def __init__(self, input_dim: int):
        super(GPUClassifierModel, self).__init__()
        self.linear = nn.Linear(input_dim, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.linear(x)


class TripleSpaceLogClassifierGPU:
    """Tekil Üçlü-Uzay Sinir Ağı Sınıflandırıcısı."""
    def __init__(self, weights=(2.0, 0.8, 1.8)):
        self.exec_weight, self.arg_weight, self.anomaly_weight = weights
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        self.is_fitted = False

    @classmethod
    def load_model(cls, filepath: str):
        data = joblib.load(filepath)
        instance = cls(weights=data["weights"])
        instance.exec_vec = data["exec_vec"]
        instance.arg_vec = data["arg_vec"]
        instance.anomaly_vec = data["anomaly_vec"]
        instance.input_dim = data["input_dim"]

        instance.model = GPUClassifierModel(instance.input_dim).to(instance.device)
        instance.model.load_state_dict(data["model_state"])
        instance.model.eval()
        instance.is_fitted = True
        return instance

    def predict_proba(self, raw_logs: List[str], batch_size: int = 1024) -> List[float]:
        from scipy.sparse import hstack
        parsed = [parse_log_triple_space(log) for log in raw_logs]
        X_exec = self.exec_vec.transform([p[0] for p in parsed]) * self.exec_weight
        X_arg = self.arg_vec.transform([p[1] for p in parsed]) * self.arg_weight
        X_anom = self.anomaly_vec.transform([p[2] for p in parsed]) * self.anomaly_weight
        X_csr = hstack([X_exec, X_arg, X_anom]).tocsr()

        self.model.eval()
        probabilities = []
        num_samples = X_csr.shape[0]

        with torch.no_grad():
            for i in range(0, num_samples, batch_size):
                batch_x_sparse = X_csr[i:i + batch_size].toarray()
                batch_x = torch.tensor(batch_x_sparse, dtype=torch.float32).to(self.device)
                logits = self.model(batch_x)
                probs = torch.sigmoid(logits).cpu().flatten().tolist()
                probabilities.extend([p * 100.0 for p in probs])

        return probabilities


class AutoencoderNetwork(nn.Module):
    """Zero-Day Tespiti İçin Rekonstrüksiyon Autoencoder Sinir Ağı."""
    def __init__(self, input_dim: int):
        super(AutoencoderNetwork, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 16),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 64),
            nn.ReLU(),
            nn.Linear(64, input_dim),
            nn.Sigmoid()
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


class ZeroDayAutoencoder:
    """Bilinmeyen ve Sıfır-Gün Saldırılarını Rekonstrüksiyon Hatasıyla Bulan Katman."""
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        self.vectorizer = None
        self.threshold = 0.005
        self.is_fitted = False

    @classmethod
    def load_model(cls, filepath: str):
        data = joblib.load(filepath)
        instance = cls()
        instance.vectorizer = data["vectorizer"]
        instance.input_dim = data["input_dim"]
        instance.threshold = data["threshold"]

        instance.model = AutoencoderNetwork(instance.input_dim).to(instance.device)
        instance.model.load_state_dict(data["model_state"])
        instance.model.eval()
        instance.is_fitted = True
        return instance

    def compute_anomaly_score(self, raw_logs: List[str], batch_size: int = 1024) -> List[float]:
        parsed_tuples = [parse_log_triple_space(log) for log in raw_logs]
        cleaned_texts = [f"{p[0]} {p[1]} {p[2]}" for p in parsed_tuples]
        X_sparse = self.vectorizer.transform(cleaned_texts)

        self.model.eval()
        scores = []
        num_samples = X_sparse.shape[0]

        with torch.no_grad():
            for i in range(0, num_samples, batch_size):
                batch_x_dense = X_sparse[i:i + batch_size].toarray()
                batch_tensor = torch.tensor(batch_x_dense, dtype=torch.float32).to(self.device)
                reconstructed = self.model(batch_tensor)
                mse = torch.mean((batch_tensor - reconstructed) ** 2, dim=1).cpu().tolist()
                scores.extend(mse)

        return scores


# ==============================================================================
# 4. 2. MODEL KATMANI: PYTORCH DEEP INCIDENT CLASSIFIER (siem_incident_module)
# ==============================================================================
class CharTokenizer:
    """Log metinlerini sabit uzunluklu tam sayı dizilerine dönüştüren Karakter Seviyesi Tokenizer."""
    def __init__(self, max_len: int = 256):
        self.max_len = max_len
        self.pad_token = "<PAD>"
        self.unk_token = "<UNK>"
        self.chars = [self.pad_token, self.unk_token] + [chr(i) for i in range(32, 127)]
        self.char_to_idx = {char: idx for idx, char in enumerate(self.chars)}
        self.idx_to_char = {idx: char for idx, char in enumerate(self.chars)}
        self.vocab_size = len(self.chars)

    def encode(self, text: str) -> List[int]:
        tokens = [self.char_to_idx.get(ch, self.char_to_idx[self.unk_token]) for ch in text]
        if len(tokens) < self.max_len:
            tokens += [self.char_to_idx[self.pad_token]] * (self.max_len - len(tokens))
        else:
            tokens = tokens[:self.max_len]
        return tokens

    def encode_batch(self, text_list: List[str]) -> torch.Tensor:
        encoded = [self.encode(text) for text in text_list]
        return torch.tensor(encoded, dtype=torch.long)


class LogPreprocessor:
    """Ham logları gürültüden arındırıp temel saldırı kalıplarını normalize eden ön işleyici."""
    SYSLOG_HEADER_PATTERN = re.compile(
        r'^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
        r'(?:[\w\.\-]+(?:\s+))?'
        r'(?:[\w\.\-]+(?:\[\d+\])?:\s+)?'
    )
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    HEX_PATTERN = re.compile(r'\\x[0-9a-fA-F]{2}')
    URL_ENCODED_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')

    @classmethod
    def clean_single_log(cls, raw_log: str) -> str:
        log = raw_log.strip()
        log = cls.SYSLOG_HEADER_PATTERN.sub('', log)
        log = cls.HEX_PATTERN.sub(' <HEX> ', log)
        log = cls.URL_ENCODED_PATTERN.sub(' <URL_ENC> ', log)
        log = cls.IP_PATTERN.sub(' <IP> ', log)
        log = re.sub(r'\s+', ' ', log).strip()
        return log


class SelfAttention(nn.Module):
    """LSTM çıkışındaki en kritik saldırı belirteçlerini yakalayan Öz-Dikkat Katmanı."""
    def __init__(self, hidden_dim: int):
        super(SelfAttention, self).__init__()
        self.projection = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.Tanh(),
            nn.Linear(64, 1)
        )

    def forward(self, lstm_outputs: torch.Tensor) -> torch.Tensor:
        energy = self.projection(lstm_outputs)
        weights = F.softmax(energy, dim=1)
        context = torch.sum(lstm_outputs * weights, dim=1)
        return context


class DeepSIEMClassifierNet(nn.Module):
    """
    GPU/CPU Üzerinde Çalışan Derin Sınıflandırma Mimarisi.
    Karakter Embedding -> Parallel 1D Multi-Kernel Conv -> BiLSTM -> Self-Attention -> Dense Head
    """
    def __init__(self, vocab_size: int, num_classes: int, embed_dim: int = 64, hidden_dim: int = 128):
        super(DeepSIEMClassifierNet, self).__init__()
        
        # Karakter Gömme Katmanı (Character Embedding)
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        
        # Paralel Multi-Kernel 1D-CNN (3'lü, 5'li ve 7'li karakter dizilimlerini yakalar)
        self.conv3 = nn.Conv1d(in_channels=embed_dim, out_channels=64, kernel_size=3, padding=1)
        self.conv5 = nn.Conv1d(in_channels=embed_dim, out_channels=64, kernel_size=5, padding=2)
        self.conv7 = nn.Conv1d(in_channels=embed_dim, out_channels=64, kernel_size=7, padding=3)
        
        self.batch_norm = nn.BatchNorm1d(192)
        self.dropout = nn.Dropout(0.3)
        
        # Çift Yönlü LSTM (Bidirectional LSTM)
        self.bilstm = nn.LSTM(
            input_size=192,
            hidden_size=hidden_dim,
            num_layers=2,
            batch_first=True,
            bidirectional=True,
            dropout=0.2
        )
        
        # Attention & Tam Bağlantılı Sınıflandırma Katmanları
        self.attention = SelfAttention(hidden_dim * 2)
        self.fc1 = nn.Linear(hidden_dim * 2, 128)
        self.relu = nn.ReLU()
        self.out_head = nn.Linear(128, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        embeds = self.embedding(x)
        embeds_permuted = embeds.permute(0, 2, 1)
        
        c3 = F.relu(self.conv3(embeds_permuted))
        c5 = F.relu(self.conv5(embeds_permuted))
        c7 = F.relu(self.conv7(embeds_permuted))
        
        conv_out = torch.cat([c3, c5, c7], dim=1)
        conv_out = self.batch_norm(conv_out)
        conv_out = self.dropout(conv_out)
        
        lstm_input = conv_out.permute(0, 2, 1)
        lstm_out, _ = self.bilstm(lstm_input)
        
        attn_out = self.attention(lstm_out)
        dense = self.dropout(self.relu(self.fc1(attn_out)))
        logits = self.out_head(dense)
        return logits


# Modül Alias Eşlemesi (PyTorch Deserialization için src modüllerini bağlar)
sys.modules['src'] = sys.modules[__name__]
sys.modules['src.deep_classifier'] = sys.modules[__name__]
sys.modules['src.preprocessor'] = sys.modules[__name__]


# SIEM Olay Taksonomisi ve SOC Playbook Bilgileri
TAXONOMY_CATEGORIES = {
    "OBFUSCATION_EVASION": {
        "title": "Evasion & Complex Obfuscation",
        "mitre_id": "T1027",
        "urgency": "HIGH",
        "playbook": "Analyze payload encoding; enforce strict shell restrictions and isolate process."
    },
    "APPLICATION_EXPLOIT": {
        "title": "Web/Application Layer Exploit",
        "mitre_id": "T1190",
        "urgency": "CRITICAL",
        "playbook": "Block source IP on WAF/Firewall; inspect endpoint parameters and sanitize inputs."
    },
    "PROCESS_INJECTION": {
        "title": "Process Injection / Memory Exploit",
        "mitre_id": "T1055",
        "urgency": "CRITICAL",
        "playbook": "Terminate suspicious process immediately; collect memory dump for forensic analysis."
    },
    "SYSTEM_INTEGRITY": {
        "title": "System Integrity & Privilege Escalation",
        "mitre_id": "T1068",
        "urgency": "CRITICAL",
        "playbook": "Revoke unauthorized sudo/root permissions; inspect SUID binaries and environment hooks."
    },
    "NETWORK_C2": {
        "title": "Command & Control / Data Exfiltration",
        "mitre_id": "T1071",
        "urgency": "CRITICAL",
        "playbook": "Sever outbound C2 connection; block C2 IP on firewall and rotate compromised credentials."
    },
    "AUTH_ANOMALY": {
        "title": "Authentication & Brute Force Anomaly",
        "mitre_id": "T1110",
        "urgency": "HIGH",
        "playbook": "Enforce automated temporary IP ban; review failed authentication logs."
    },
    "SAFE_NOISE": {
        "title": "Legitimate System Activity",
        "mitre_id": "N/A",
        "urgency": "INFO",
        "playbook": "No action required. Verified normal system behavior."
    }
}


class GPUDeepSIEMClassifier:
    """Derin Öğrenme Olay Taksonomisi Sınıflandırıcısı."""
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = CharTokenizer()
        self.preprocessor = LogPreprocessor()
        self.model = None
        self.label_to_idx = {}
        self.idx_to_label = {}
        self.is_fitted = False

    @classmethod
    def load(cls, filepath: str):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")

        instance = cls()
        checkpoint = torch.load(filepath, map_location=instance.device, weights_only=False)

        instance.label_to_idx = checkpoint["label_to_idx"]
        instance.idx_to_label = checkpoint["idx_to_label"]
        instance.tokenizer = checkpoint["tokenizer"]
        instance.is_fitted = checkpoint["is_fitted"]

        instance.model = DeepSIEMClassifierNet(
            vocab_size=instance.tokenizer.vocab_size,
            num_classes=len(instance.label_to_idx)
        ).to(instance.device)

        instance.model.load_state_dict(checkpoint["model_state"])
        instance.model.eval()
        return instance

    def predict_single(self, raw_log: str) -> Dict[str, Any]:
        if not self.is_fitted or self.model is None:
            raise RuntimeError("Model is not loaded!")

        self.model.eval()
        cleaned_log = self.preprocessor.clean_single_log(raw_log)
        inputs = self.tokenizer.encode_batch([cleaned_log]).to(self.device)

        with torch.no_grad():
            logits = self.model(inputs)
            probs = F.softmax(logits, dim=1)[0]

        best_idx = torch.argmax(probs).item()
        confidence = probs[best_idx].item() * 100.0
        predicted_label = self.idx_to_label.get(best_idx, "SAFE_NOISE")

        taxonomy_info = TAXONOMY_CATEGORIES.get(predicted_label, {
            "title": "Unclassified Incident", "mitre_id": "T1082", "urgency": "INFO", "playbook": "SOC Investigation Required."
        })

        return {
            "predicted_category": predicted_label,
            "confidence": round(confidence, 2),
            "taxonomy": taxonomy_info,
            "device_used": str(self.device)
        }


# ==============================================================================
# 5. ENTEGRE MERKEZİ YAPAY ZEKA GÜVENLİK MOTORU (Unified AISecurityEngine)
# ==============================================================================
class AISecurityEngine:
    """
    Tüm Yapay Zeka Güvenlik Modellerini Tek Çatı Altında Birleştiren Merkezi Motor.
    Ensemble Modelleri + Zero-Day Autoencoder + PyTorch Derin Olay Sınıflandırıcısı.
    """
    def __init__(self,
                 models_dir="models",
                 ensemble_dir="models/ensemble",
                 autoencoder_path="models/autoencoder/autoencoder.joblib",
                 deep_model_path="models/deep_incident/gpu_deep_incident_model.pt"):
        self.models_dir = models_dir
        self.ensemble_dir = ensemble_dir
        self.autoencoder_path = autoencoder_path
        self.deep_model_path = deep_model_path
        
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.ensemble_models = []
        self.autoencoder = None
        self.deep_classifier = None
        self.is_ready = False

    def load_all_models(self) -> bool:
        """Tüm yapay zeka modellerini hafızaya yükler ve kullanıma hazır hale getirir."""
        try:
            print(f"[+] Loading AI Security Engine on [{self.device}]...")

            # 1. Ensemble Modellerini Yükle (4 Model)
            self.ensemble_models = []
            for i in range(1, 5):
                m_path = os.path.join(self.ensemble_dir, f"model_{i}.joblib")
                if os.path.exists(m_path):
                    clf = TripleSpaceLogClassifierGPU.load_model(m_path)
                    self.ensemble_models.append(clf)
                    print(f"    - Ensemble Model [{i}/4] Loaded: {m_path}")

            # 2. Zero-Day Autoencoder Modelini Yükle
            if os.path.exists(self.autoencoder_path):
                self.autoencoder = ZeroDayAutoencoder.load_model(self.autoencoder_path)
                print(f"    - Zero-Day Autoencoder Loaded: {self.autoencoder_path}")

            # 3. PyTorch Derin Olay Sınıflandırıcı Modelini Yükle
            if os.path.exists(self.deep_model_path):
                self.deep_classifier = GPUDeepSIEMClassifier.load(self.deep_model_path)
                print(f"    - PyTorch Deep Incident Classifier Loaded: {self.deep_model_path}")

            self.is_ready = bool(self.ensemble_models and self.autoencoder and self.deep_classifier)
            if self.is_ready:
                print(f"[+] All AI Security Models Successfully Loaded on Device: {self.device}\n")
            else:
                print("[-] Warning: Some AI model files were missing. Partial AI functionality active.")
            return self.is_ready
        except Exception as e:
            print(f"[-] AI Security Engine Loading Error: {e}")
            self.is_ready = False
            return False

    def analyze(self, raw_log: str) -> Dict[str, Any]:
        """
        Log satırını veya kullanıcı komutunu tüm yapay zeka katmanlarından geçirerek tam analiz üretir.
        """
        if not self.is_ready:
            guard_res = DeterministicGuardrail.check_hard_rules(raw_log)
            threat_info = detect_mitre_threat(raw_log)
            return {
                "is_attack": guard_res.get("verdict") == "ATTACK",
                "verdict": guard_res.get("verdict", "SAFE"),
                "confidence": guard_res.get("confidence", 50.0),
                "layer": "Rule Guardrail Fallback",
                "mitre_id": threat_info["mitre_id"],
                "mitre_category": threat_info["category"],
                "incident_category": "UNCLASSIFIED",
                "incident_title": "AI Engine Offline",
                "urgency": "INFO",
                "playbook": "Inspect rule match.",
                "details": guard_res.get("detail", "Rule Evaluation")
            }

        # 0. KATMAN: Sert Kural Tabanlı Guardrail Kontrolü
        guard_res = DeterministicGuardrail.check_hard_rules(raw_log)
        if guard_res["override"]:
            threat_info = detect_mitre_threat(raw_log) if guard_res["verdict"] == "ATTACK" else {"category": "Benign", "mitre_id": "N/A"}
            deep_res = self.deep_classifier.predict_single(raw_log) if self.deep_classifier else {}
            taxonomy = deep_res.get("taxonomy", {})

            return {
                "is_attack": guard_res["verdict"] == "ATTACK",
                "verdict": guard_res["verdict"],
                "confidence": guard_res["confidence"],
                "layer": "0. Layer (Guardrail)",
                "mitre_id": threat_info["mitre_id"],
                "mitre_category": threat_info["category"],
                "incident_category": deep_res.get("predicted_category", "SYSTEM_INTEGRITY"),
                "incident_title": taxonomy.get("title", "Critical Guardrail Violation"),
                "urgency": taxonomy.get("urgency", "CRITICAL" if guard_res["verdict"] == "ATTACK" else "INFO"),
                "playbook": taxonomy.get("playbook", "Immediate SOC Action"),
                "details": f"[{threat_info['category']}] (MITRE {threat_info['mitre_id']}) - {guard_res['detail']}"
            }

        # 1. KATMAN: 4'lü Ensemble Modeli Saldırı Olasılığı Hesabı
        ensemble_probs = []
        for model in self.ensemble_models:
            p = model.predict_proba([raw_log])[0]
            ensemble_probs.append(p)
        avg_attack_prob = sum(ensemble_probs) / len(ensemble_probs) if ensemble_probs else 0.0

        # Derin Olay Sınıflandırıcı Tahmini
        deep_res = self.deep_classifier.predict_single(raw_log) if self.deep_classifier else {}
        taxonomy = deep_res.get("taxonomy", {})
        predicted_cat = deep_res.get("predicted_category", "SAFE_NOISE")
        deep_conf = deep_res.get("confidence", 50.0)

        # Karar Mantığı
        if avg_attack_prob >= 50.0 or (predicted_cat != "SAFE_NOISE" and deep_conf >= 80.0):
            threat_info = detect_mitre_threat(raw_log)
            return {
                "is_attack": True,
                "verdict": "ATTACK",
                "confidence": max(avg_attack_prob, deep_conf),
                "layer": "1. Layer (Ensemble & Deep Classifier)",
                "mitre_id": taxonomy.get("mitre_id") or threat_info["mitre_id"],
                "mitre_category": taxonomy.get("title") or threat_info["category"],
                "incident_category": predicted_cat,
                "incident_title": taxonomy.get("title", "Detected Attack Vector"),
                "urgency": taxonomy.get("urgency", "HIGH"),
                "playbook": taxonomy.get("playbook", "Automated Mitigation Initiated"),
                "details": f"[{predicted_cat}] {taxonomy.get('title')} (Confidence: {max(avg_attack_prob, deep_conf):.1f}%)"
            }

        # 2. KATMAN: Zero-Day Rekonstrüksiyon Autoencoder'ı
        mse_scores = self.autoencoder.compute_anomaly_score([raw_log]) if self.autoencoder else [0.0]
        mse_score = mse_scores[0]
        effective_threshold = (self.autoencoder.threshold * 1.05) if self.autoencoder else 0.005

        if (mse_score > effective_threshold or avg_attack_prob >= 30.0) and predicted_cat != "SAFE_NOISE":
            conf_val = min(99.9, 65.0 + ((mse_score / effective_threshold) - 1.0) * 15.0) if effective_threshold > 0 else 75.0
            return {
                "is_attack": True,
                "verdict": "ZERO_DAY",
                "confidence": max(60.0, conf_val),
                "layer": "2. Layer (Zero-Day Autoencoder)",
                "mitre_id": "T1059",
                "mitre_category": "Zero-Day Behavioral Anomaly",
                "incident_category": predicted_cat if predicted_cat != "SAFE_NOISE" else "OBFUSCATION_EVASION",
                "incident_title": "Unforeseen Zero-Day Vulnerability Anomaly",
                "urgency": "HIGH",
                "playbook": "Isolate process; quarantine IP; collect full memory payload for reverse engineering.",
                "details": f"[Zero-Day Anomaly] Reconstruction MSE: {mse_score:.5f} > Threshold: {effective_threshold:.5f}"
            }

        # Güvenli / Meşru Sistem Hareketi
        return {
            "is_attack": False,
            "verdict": "SAFE",
            "confidence": round(100.0 - avg_attack_prob, 2),
            "layer": "Multi-Layer Cleared",
            "mitre_id": "N/A",
            "mitre_category": "Benign System Activity",
            "incident_category": "SAFE_NOISE",
            "incident_title": "Normal Operation",
            "urgency": "INFO",
            "playbook": "Normal monitoring.",
            "details": "Verified benign system behavior."
        }
