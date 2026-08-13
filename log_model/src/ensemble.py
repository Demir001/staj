# File: src/ensemble.py
# Description: 4-Model Ensemble (Soft Voting) Classifier for Log Anomaly Detection

import os
import joblib
import numpy as np
from src.dataset import get_training_data
from src.model import TripleSpaceLogClassifierGPU

class EnsembleLogClassifierGPU:
    """
    4 Adet 500.000'lik bağımsız eğitilmiş GPU modelini paralel çalıştıran 
    ve Soft Voting (Olasılık Ortalaması) ile nihai karar veren Topluluk Mimarisi.
    """
    def __init__(self, num_models=4, samples_per_model=250000):
        self.num_models = num_models
        self.samples_per_model = samples_per_model
        self.models = []

    def fit_all(self, model_dir="ensemble_models"):
        """4 farklı 500.000'lik veri kümesiyle 4 ayrı modeli eğitir ve diske kaydeder."""
        os.makedirs(model_dir, exist_ok=True)
        
        for i in range(1, self.num_models + 1):
            model_path = os.path.join(model_dir, f"model_{i}.joblib")
            print(f"\n==================================================")
            print(f"🚀 ENSEMBLE MODEL [{i}/{self.num_models}] EĞİTİLİYOR...")
            print(f"==================================================")
            
            # Her model için bağımsız 500.000 sentetik veri üretilir
            df_train = get_training_data(n_samples=self.samples_per_model)
            
            clf = TripleSpaceLogClassifierGPU(weights=(2.0, 0.8, 1.8))
            clf.fit(df_train, epochs=3, batch_size=4096)
            
            clf.save_model(model_path)
            self.models.append(clf)
            print(f"💾 Model {i} diske kaydedildi: '{model_path}'")

    def load_all(self, model_dir="ensemble_models"):
        """Diskteki 4 modeli belleğe/GPU'ya yükler."""
        self.models = []
        for i in range(1, self.num_models + 1):
            model_path = os.path.join(model_dir, f"model_{i}.joblib")
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model dosyası bulunamadı: {model_path}")
            
            print(f"📦 Ensemble Model [{i}/{self.num_models}] yükleniyor: '{model_path}'...")
            clf = TripleSpaceLogClassifierGPU.load_model(model_path)
            self.models.append(clf)
        print("✅ 4 Modelli Ensemble Yapısı GPU Belleğinde Hazır!\n")

    def predict_proba(self, raw_logs):
        """
        Gelen logları 4 modele aynı anda sorar ve Soft Voting (Ortalama Olasılık) hesaplar.
        """
        if not self.models:
            raise ValueError("Yüklü model bulunamadı. Önce fit_all() veya load_all() çağırın.")

        all_probs = []
        for idx, model in enumerate(self.models, 1):
            probs = model.predict_proba(raw_logs)
            all_probs.append(probs)

        # 4 modelin tahmin matrisinin ortalamasını alma (Soft Voting)
        ensemble_probs = np.mean(all_probs, axis=0)
        return ensemble_probs