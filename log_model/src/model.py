# File: src/model.py
# Description: GPU-Accelerated (PyTorch CUDA/MPS) Triple-Space Log Anomaly Classifier

import joblib
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer

from src.parser import parse_log_triple_space

# 1. GPU Cihaz Tespiti (NVIDIA CUDA -> Apple MPS -> CPU)
def get_device():
    if torch.cuda.is_available():
        return torch.device("cuda")
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    else:
        return torch.device("cpu")

# 2. PyTorch GPU Lojistik Regresyon / Neural Model
class GPUClassifierModel(nn.Module):
    def __init__(self, input_dim):
        super(GPUClassifierModel, self).__init__()
        self.linear = nn.Linear(input_dim, 1)

    def forward(self, x):
        return self.linear(x)

class TripleSpaceLogClassifierGPU:
    """
    Üçlü Vektör Uzayını PyTorch GPU Tektörleri Üzerinde Eğiten Hızlı Sınıflandırıcı.
    """
    def __init__(self, weights=(2.0, 0.8, 1.8)):
        self.exec_weight, self.arg_weight, self.anomaly_weight = weights
        self.device = get_device()
        print(f"⚡ GPU Hızlandırma Aktif: [{self.device.type.upper()}] Cihazı Kullanılıyor.")

        self.exec_vec = TfidfVectorizer(
            analyzer='char_wb', 
            ngram_range=(2, 5), 
            sublinear_tf=True, 
            max_features=30000
        )
        self.arg_vec = TfidfVectorizer(
            analyzer='char_wb', 
            ngram_range=(3, 5), 
            sublinear_tf=True, 
            max_features=20000
        )
        self.anomaly_vec = TfidfVectorizer(
            analyzer='char_wb', 
            ngram_range=(2, 5), 
            sublinear_tf=True, 
            max_features=10000
        )

        self.model = None
        self.input_dim = None
        self.is_fitted = False

    def _transform_pipeline(self, parsed_tuples, is_training=False):
        exec_texts = [p[0] for p in parsed_tuples]
        arg_texts = [p[1] for p in parsed_tuples]
        anomaly_texts = [p[2] for p in parsed_tuples]

        if is_training:
            Xe = self.exec_vec.fit_transform(exec_texts)
            Xa = self.arg_vec.fit_transform(arg_texts)
            Xx = self.anomaly_vec.fit_transform(anomaly_texts)
        else:
            Xe = self.exec_vec.transform(exec_texts)
            Xa = self.arg_vec.transform(arg_texts)
            Xx = self.anomaly_vec.transform(anomaly_texts)

        X_combined = hstack([
            Xe * self.exec_weight, 
            Xa * self.arg_weight, 
            Xx * self.anomaly_weight
        ])
        return X_combined.tocsr()

    def fit(self, df_logs, epochs=5, batch_size=4096, lr=0.01):
        """1 Milyon veriyi GPU Mini-Batch kullanarak paralel eğitir."""
        print("1. Loglar Üçlü Uzayda Ayrıştırılıyor...")
        parsed_tuples = [parse_log_triple_space(log) for log in df_logs['log']]
        
        print("2. TF-IDF Vektörleştirme Yapılıyor...")
        X_csr = self._transform_pipeline(parsed_tuples, is_training=True)
        y_arr = df_logs['label'].values.astype(np.float32)

        self.input_dim = X_csr.shape[1]
        self.model = GPUClassifierModel(self.input_dim).to(self.device)

        criterion = nn.BCEWithLogitsLoss()
        optimizer = optim.Adam(self.model.parameters(), lr=lr)

        print(f"3. PyTorch GPU Eğitimi Başlatılıyor (Epochs: {epochs}, Batch Size: {batch_size})...")
        self.model.train()

        num_samples = X_csr.shape[0]
        
        for epoch in range(epochs):
            running_loss = 0.0
            permutation = np.random.permutation(num_samples)
            
            for i in range(0, num_samples, batch_size):
                indices = permutation[i:i + batch_size]
                
                # CSR Matrisi Pytorch GPU Tensorüne Dönüştürme
                batch_x_sparse = X_csr[indices].toarray()
                batch_x = torch.tensor(batch_x_sparse, dtype=torch.float32).to(self.device)
                batch_y = torch.tensor(y_arr[indices], dtype=torch.float32).unsqueeze(1).to(self.device)

                optimizer.zero_grad()
                outputs = self.model(batch_x)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()

                running_loss += loss.item() * len(indices)

            epoch_loss = running_loss / num_samples
            print(f"   [Epoch {epoch+1}/{epochs}] Loss: {epoch_loss:.6f}")

        self.is_fitted = True
        print("✅ GPU Üzerinde Eğitim Tamamlandı!\n")
        return self

    def predict_proba(self, raw_logs, batch_size=2048):
        """GPU Üzerinde Hızlı İnferans / Tahmin Yürütme."""
        if not self.is_fitted:
            raise ValueError("Model eğitilmedi. Önce fit() çağırın.")

        parsed_tuples = [parse_log_triple_space(log) for log in raw_logs]
        X_csr = self._transform_pipeline(parsed_tuples, is_training=False)
        
        self.model.eval()
        probabilities = []
        num_samples = X_csr.shape[0]

        with torch.no_grad():
            for i in range(0, num_samples, batch_size):
                batch_x_sparse = X_csr[i:i + batch_size].toarray()
                batch_x = torch.tensor(batch_x_sparse, dtype=torch.float32).to(self.device)
                
                logits = self.model(batch_x)
                probs = torch.sigmoid(logits).cpu().numpy().flatten()
                probabilities.extend(probs * 100.0)

        return np.array(probabilities)

    def save_model(self, filepath="model.joblib"):
        """Model ağırlıklarını ve Tfidf yapılarını kaydeder."""
        data = {
            "exec_vec": self.exec_vec,
            "arg_vec": self.arg_vec,
            "anomaly_vec": self.anomaly_vec,
            "model_state": self.model.state_dict(),
            "input_dim": self.input_dim,
            "weights": (self.exec_weight, self.arg_weight, self.anomaly_weight)
        }
        joblib.dump(data, filepath)

    @classmethod
    def load_model(cls, filepath="model.joblib"):
        data = joblib.load(filepath)
        instance = cls(weights=data["weights"])
        instance.exec_vec = data["exec_vec"]
        instance.arg_vec = data["arg_vec"]
        instance.anomaly_vec = data["anomaly_vec"]
        instance.input_dim = data["input_dim"]
        
        instance.model = GPUClassifierModel(instance.input_dim).to(instance.device)
        instance.model.load_state_dict(data["model_state"])
        instance.is_fitted = True
        return instance
# Model ismi geriye dönük uyumluluk takma adı
TripleSpaceLogClassifier = TripleSpaceLogClassifierGPU
