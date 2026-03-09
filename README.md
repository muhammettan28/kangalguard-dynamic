# KangalGuard Dynamic Analyzer

Android uygulamalarını Frida ile dinamik analiz ederek davranışsal özellikler çıkarır ve etiketli bir ML dataset'i oluşturur.

## Kurulum

### Gereksinimler
- Genymotion Android 8.0 emülatörü (Genymotion-ARM-Translation_for_8.0 ile ARM desteği)
- `frida-server` binary: `/data/local/tmp/frida-server`
- Python paketleri: `frida`, `androguard`
- Android SDK araçları: `adb`, `aapt`

### İlk Kurulum
```bash
# frida-server'ı başlat ve temiz snapshot kaydet
python batch_analyzer.py --setup
```

## Kullanım

```bash
# Benign APK koleksiyonu
python batch_analyzer.py --dir ./data/benign --label benign

# Malware APK koleksiyonu
python batch_analyzer.py --dir ./data/malware --label malware

# Test çalıştırması (5 APK, 30s timeout)
python batch_analyzer.py --dir ./data/benign --label benign --limit 5 --timeout 30

# Özel CSV çıktısı
python batch_analyzer.py --dir ./data/benign --label benign --csv custom_output.csv
```

## Zamanlama (APK başına)

| Aşama | Süre |
|-------|------|
| Dialog temizleme + Kurulum | ~17s |
| adb monkey + PID bulma | ~5-8s |
| Frida attach | ~2s |
| Analiz penceresi (DEFAULT_TIMEOUT) | 75s |
| Final RPC + force-stop | ~3s |
| Uninstall | ~5s |
| Snapshot restore | ~30-60s |
| **Toplam** | **~140-170s (~2.5-3 dk)** |

## ANR / Diyalog Yönetimi

Analiz sırasında "App Not Responding" veya "App Has Stopped" diyalogları otomatik olarak yönetilir:

- **`dismiss_dialogs()`**: Her APK başında ve polling loop içinde her 15 saniyede bir BACK + ENTER tuşu göndererek sistem diyaloglarını kapatır.
- **`_rpc_safe(timeout_s=8)`**: Frida RPC çağrılarını daemon thread ile sarar. 8 saniyede cevap gelmezse freeze sayar; 3 ardışık freeze sonrası döngü sonlandırılır ve toplanan verilerle CSV satırı yazılır.

## Mimari

```
agent.ts              — Frida TS agent, ~50 Java API hook, emülatöre inject edilir
kangal_collector.py   — Feature engineering, 97 CSV kolonu
batch_analyzer.py     — Orchestration: install → attach → poll → CSV → uninstall
```

## Dataset

- `kangal_dataset.csv` — Çıktı dataset (97 kolon)
- `data/benign/` — Benign APK'lar (KronoDroid, AndroZoo)
- `data/malware/` — Malware APK'lar
- `logs/failed_apks.csv` — Hatalı/atlanan APK logu
- `logs/run_<timestamp>_<label>.log` — Çalıştırma logları
