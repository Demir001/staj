# File: run_advanced_analysis.py
import os
import time
from src.hybrid_engine import EnterpriseHybridEngine, extract_universal_features
from src.autoencoder import ZeroDayAutoencoder
from src.dataset import get_training_data

TEST_FILE = "advanced_test_logs.txt"

def main():
    engine = EnterpriseHybridEngine()
    
    # 1. Her iki katmanın varlığını ayrı ayrı kontrol et
    ensemble_exists = all(os.path.exists(f"ensemble_models/model_{i}.joblib") for i in range(1, 5))
    autoencoder_exists = os.path.exists("autoencoder.joblib")

    # -------------------------------------------------------------------------
    # 1. KATMAN: ENSEMBLE MODELLERİ KONTROLÜ
    # -------------------------------------------------------------------------
    if ensemble_exists:
        print("📦 Mevcut Ensemble modelleri (4 adet) diski taranıp yükleniyor...")
        engine.ensemble.load_all("ensemble_models")
    else:
        print("⚙️ Ensemble modelleri bulunamadı. 4x 250.000 veri ile 1. Katman eğitimi başlatılıyor...")
        engine.ensemble.fit_all("ensemble_models")

    # -------------------------------------------------------------------------
    # 2. KATMAN: AUTOENCODER (ZERO-DAY) KONTROLÜ
    # -------------------------------------------------------------------------
    if autoencoder_exists:
        print("📦 Mevcut Autoencoder (Zero-Day) modeli yükleniyor...")
        engine.autoencoder = ZeroDayAutoencoder.load_model("autoencoder.joblib")
    else:
        print("\n⚙️ 'autoencoder.joblib' bulunamadı. Sadece Autoencoder için eğitim başlatılıyor...")
        df_dataset = get_training_data(n_samples=150000)
        safe_logs = df_dataset[df_dataset['label'] == 0]['log'].tolist()
        
        # Sadece Autoencoder katmanını eğit ve kaydet
        processed_safe = [extract_universal_features(log) for log in safe_logs]
        engine.autoencoder.fit(processed_safe, epochs=8)
        engine.autoencoder.save_model("autoencoder.joblib")

    engine.is_ready = True
    print("\n✅ HİBRİT MOTOR HAZIR! (Tüm katmanlar başarıyla senkronize edildi)\n")

    # -------------------------------------------------------------------------
    # TEST VE ANALİZ DÖNGÜSÜ
    # -------------------------------------------------------------------------
    if not os.path.exists(TEST_FILE):
        print(f"❌ Test dosyası bulunamadı: '{TEST_FILE}'")
        return

    print(f"📄 '{TEST_FILE}' Analiz Ediliyor...\n")
    print("=" * 85)

    with open(TEST_FILE, "r", encoding="utf-8") as f:
        logs = [line.strip() for line in f if line.strip()]

    attack_count = 0
    zero_day_count = 0
    safe_count = 0

    start_time = time.time()
    for idx, raw_log in enumerate(logs, 1):
        res = engine.analyze_log(raw_log)
        verdict = res["verdict"]

        if verdict == "ATTACK":
            attack_count += 1
            print(f"[{idx:03d}] 🚨 BİLİNEN SALDIRI (%{res['confidence']:.2f}) | {res['detail']} | LOG: {raw_log[:55]}...")
        elif verdict == "ZERO_DAY":
            zero_day_count += 1
            print(f"[{idx:03d}] ⚠️ ZERO-DAY ANOMALİ (%{res['confidence']:.2f}) | {res['detail']} | LOG: {raw_log[:55]}...")
        else:
            safe_count += 1
            print(f"[{idx:03d}] ✅ GÜVENLİ (%{res['confidence']:.2f}) | LOG: {raw_log[:55]}...")

    elapsed = time.time() - start_time

    print("=" * 85)
    print("📊 ENTEGRE HİBRİT TESPİT RAPORU")
    print("=" * 85)
    print(f"• Toplam Log         : {len(logs)}")
    print(f"• Bilinen Saldırılar : {attack_count} (1. Katman Ensemble)")
    print(f"• Zero-Day Anomali   : {zero_day_count} (2. Katman Autoencoder)")
    print(f"• Meşru / Güvenli    : {safe_count}")
    print(f"• İşlem Süresi       : {elapsed:.2f} saniye (Log başı: {(elapsed/len(logs))*1000:.2f} ms)")
    print("=" * 85)

if __name__ == "__main__":
    main()