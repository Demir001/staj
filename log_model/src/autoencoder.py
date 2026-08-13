# File: src/autoencoder.py
import joblib
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from src.parser import parse_log_triple_space

def get_device():
    if torch.cuda.is_available():
        return torch.device("cuda")
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")

class AutoencoderNetwork(nn.Module):
    def __init__(self, input_dim):
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

    def forward(self, x):
        return self.decoder(self.encoder(x))

class ZeroDayAutoencoder:
    def __init__(self, max_features=6000):
        self.device = get_device()
        self.vectorizer = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(2, 4),
            sublinear_tf=True,
            max_features=max_features
        )
        self.model = None
        self.threshold = 0.0
        self.input_dim = None
        self.is_fitted = False

    def fit(self, safe_logs, epochs=8, batch_size=2048, lr=0.005):
        print(f"⚙️ [Zero-Day Katmanı] {len(safe_logs):,} Meşru log ayrıştırılıyor ({self.device.type.upper()})...")
        parsed_tuples = [parse_log_triple_space(log) for log in safe_logs]
        cleaned_texts = [f"{p[0]} {p[1]} {p[2]}" for p in parsed_tuples]

        X_sparse = self.vectorizer.fit_transform(cleaned_texts)
        self.input_dim = X_sparse.shape[1]
        
        self.model = AutoencoderNetwork(self.input_dim).to(self.device)
        criterion = nn.MSELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=lr)

        num_samples = X_sparse.shape[0]

        self.model.train()
        for epoch in range(epochs):
            running_loss = 0.0
            permutation = np.random.permutation(num_samples)
            
            for i in range(0, num_samples, batch_size):
                indices = permutation[i:i + batch_size]
                batch_x_dense = X_sparse[indices].toarray()
                batch_tensor = torch.tensor(batch_x_dense, dtype=torch.float32).to(self.device)

                optimizer.zero_grad()
                outputs = self.model(batch_tensor)
                loss = criterion(outputs, batch_tensor)
                loss.backward()
                optimizer.step()

                running_loss += loss.item() * len(indices)

            epoch_loss = running_loss / num_samples
            print(f"   [Autoencoder Epoch {epoch+1}/{epochs}] Reconstruct Loss (MSE): {epoch_loss:.6f}")

        # Dinamik Eşik Belirleme (Bellek Dostu Batch Hesaplama)
        self.model.eval()
        mse_errors = []
        with torch.no_grad():
            for i in range(0, num_samples, batch_size):
                batch_dense = X_sparse[i:i + batch_size].toarray()
                batch_tensor = torch.tensor(batch_dense, dtype=torch.float32).to(self.device)
                reconstructed = self.model(batch_tensor)
                mse = torch.mean((batch_tensor - reconstructed) ** 2, dim=1).cpu().numpy()
                mse_errors.extend(mse)

        mse_errors = np.array(mse_errors)
        self.threshold = float(np.mean(mse_errors) + 3.5 * np.std(mse_errors))
        print(f"🎯 [Zero-Day Katmanı] Dinamik Anomali Eşiği Belirlendi: {self.threshold:.6f}\n")

        self.is_fitted = True

    def compute_anomaly_score(self, raw_logs, batch_size=1024):
        if not self.is_fitted:
            raise ValueError("Autoencoder henüz eğitilmedi.")

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
                mse = torch.mean((batch_tensor - reconstructed) ** 2, dim=1).cpu().numpy()
                scores.extend(mse)

        return np.array(scores)

    def save_model(self, filepath="autoencoder.joblib"):
        data = {
            "vectorizer": self.vectorizer,
            "model_state": self.model.state_dict(),
            "input_dim": self.input_dim,
            "threshold": self.threshold
        }
        joblib.dump(data, filepath)

    @classmethod
    def load_model(cls, filepath="autoencoder.joblib"):
        data = joblib.load(filepath)
        instance = cls()
        instance.vectorizer = data["vectorizer"]
        instance.input_dim = data["input_dim"]
        instance.threshold = data["threshold"]
        
        instance.model = AutoencoderNetwork(instance.input_dim).to(instance.device)
        instance.model.load_state_dict(data["model_state"])
        instance.is_fitted = True
        return instance