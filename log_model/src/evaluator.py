# File: src/evaluator.py
# Description: Model Evaluation, Performance Metrics & Batch Reporting Module

import time
import numpy as np

class ModelEvaluator:
    """
    Eğitilmiş TripleSpaceLogClassifier modelini toplu log verileri üzerinde test eden,
    performans metriklerini (Accuracy, Precision, Recall, F1, Hız) hesaplayan modül.
    """
    
    def __init__(self, classifier, threshold=50.0):
        self.classifier = classifier
        self.threshold = threshold

    def evaluate_file(self, file_path="test_logs.txt", expected_labels=None):
        """
        Belirtilen .txt dosyasındaki tüm log satırlarını okur, olasılıksal tahmin 
        yürütür ve ayrıntılı batch analiz raporu üretir.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            print(f"❌ HATA: '{file_path}' dosyası bulunamadı.")
            return None

        if not lines:
            print(f"⚠️ UYARI: '{file_path}' dosyası boş.")
            return None

        print(f"📄 '{file_path}' içerisinden {len(lines)} adet log okunuyor ve analiz ediliyor...\n")
        
        results = []
        safe_count = 0
        malicious_count = 0
        
        start_time = time.time()
        
        # Batch Tahmin Yürütme
        probabilities = self.classifier.predict_proba(lines)
        total_time = time.time() - start_time

        for idx, (raw_log, mal_prob) in enumerate(zip(lines, probabilities), 1):
            is_malicious = mal_prob >= self.threshold
            
            if is_malicious:
                malicious_count += 1
                status_str = f"🚨 ZARARLI (%{mal_prob:.2f})"
            else:
                safe_count += 1
                status_str = f"✅ GÜVENLİ (%{(100 - mal_prob):.2f})"

            results.append({
                "index": idx,
                "log": raw_log,
                "mal_prob": mal_prob,
                "is_malicious": is_malicious
            })

            print(f"[{idx:03d}/{len(lines):03d}] {status_str} | LOG: {raw_log[:85]}...")

        avg_ms = (total_time / len(lines)) * 1000.0

        print("\n" + "=" * 75)
        print("📊 BATCH TEST TAHMİN BİLDİRİM RAPORU")
        print("=" * 75)
        print(f"• Toplam İşlenen Log  : {len(lines)}")
        print(f"• Güvenli Tespit      : {safe_count}")
        print(f"• Zararlı Tespit      : {malicious_count}")
        print(f"• Toplam İşlem Süresi : {total_time:.2f} saniye")
        print(f"• Log Başına Ortalama : {avg_ms:.2f} ms")
        print("=" * 75)

        # Beklenen etiketler sağlandıysa Doğrulama Metriklerini hesapla
        if expected_labels is not None and len(expected_labels) == len(lines):
            self.calculate_metrics(expected_labels, [r["is_malicious"] for r in results])

        return results

    @staticmethod
    def calculate_metrics(y_true, y_pred):
        """
        True Positive, False Positive, True Negative, False Negative matrisini 
        ve metrik oranlarını (Accuracy, Precision, Recall, F1) hesaplar.
        """
        y_true = np.array(y_true, dtype=int)
        y_pred = np.array(y_pred, dtype=int)

        tp = np.sum((y_true == 1) & (y_pred == 1))
        fp = np.sum((y_true == 0) & (y_pred == 1))
        tn = np.sum((y_true == 0) & (y_pred == 0))
        fn = np.sum((y_true == 1) & (y_pred == 0))

        accuracy = (tp + tn) / len(y_true) if len(y_true) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        print("\n" + "=" * 75)
        print("📈 METRİK VE DOĞRULAMA DETAYLARI")
        print("=" * 75)
        print(f"• Doğruluk (Accuracy)  : %{accuracy * 100:.2f}")
        print(f"• Kesinlik (Precision) : %{precision * 100:.2f}")
        print(f"• Duyarlılık (Recall)  : %{recall * 100:.2f}")
        print(f"• F1-Skoru (F1-Score)  : %{f1 * 100:.2f}")
        print("-" * 75)
        print(f"• Doğru Pozitif (TP)   : {tp:<5} | Yanlış Pozitif (FP)  : {fp}")
        print(f"• Doğru Negatif (TN)   : {tn:<5} | Yanlış Negatif (FN)  : {fn}")
        print("=" * 75)