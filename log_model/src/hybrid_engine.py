# File: src/hybrid_engine.py
import os
import numpy as np
from src.ensemble import EnsembleLogClassifierGPU
from src.autoencoder import ZeroDayAutoencoder

class EnterpriseHybridEngine:
    def __init__(self, ensemble_dir="ensemble_models", autoencoder_path="autoencoder.joblib"):
        self.ensemble = EnsembleLogClassifierGPU(num_models=4)
        self.autoencoder = ZeroDayAutoencoder()
        self.ensemble_dir = ensemble_dir
        self.autoencoder_path = autoencoder_path
        self.is_ready = False

    def load_engine(self):
        self.ensemble.load_all(self.ensemble_dir)
        self.autoencoder = ZeroDayAutoencoder.load_model(self.autoencoder_path)
        self.is_ready = True

    def analyze_log(self, raw_log: str) -> dict:
        if not self.is_ready:
            raise ValueError("Engine henüz başlatılmadı veya yüklenmedi.")

        if raw_log.startswith("#"):
            return {
                "verdict": "HEADER",
                "layer": "Comment/Header",
                "confidence": 100.0,
                "detail": "Seviye Başlığı"
            }

        # 1. KATMAN: Bilinen Saldırı Sınıflandırma (Ensemble)
        prob_attack = self.ensemble.predict_proba([raw_log])[0]

        if prob_attack >= 55.0:
            return {
                "verdict": "ATTACK",
                "layer": "1. Katman (Ensemble)",
                "confidence": prob_attack,
                "detail": "Bilinen Saldırı Vektörü / Obfuskasyon"
            }

        # 2. KATMAN: Zero-Day Anomali Tespiti (Autoencoder)
        mse_score = self.autoencoder.compute_anomaly_score([raw_log])[0]

        if mse_score > self.autoencoder.threshold or prob_attack >= 35.0:
            confidence_val = max(prob_attack, min(99.9, (mse_score / (self.autoencoder.threshold + 1e-8)) * 60.0))
            return {
                "verdict": "ZERO_DAY",
                "layer": "2. Katman (Autoencoder)",
                "confidence": confidence_val,
                "detail": f"Zero-Day Anomali (MSE: {mse_score:.5f} > Threshold: {self.autoencoder.threshold:.5f})"
            }

        return {
            "verdict": "SAFE",
            "layer": "Her İki Katman Temiz",
            "confidence": 100.0 - prob_attack,
            "detail": "Meşru Sistem İşlemi"
        }