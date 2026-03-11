# Malware Detection — Feature Engineering TODO

## Proje Bağlamı
- Dinamik analiz ile Android APK'lardan feature extraction yapılıyor
- İlk test: ~2293 APK (1218 malware, 1075 benign), 94 feature
- Model: XGBoost, AUC ~0.94, F1-macro ~0.87
- Hedef: Feature setini iyileştir → veri artır → model karşılaştır

---

## 1. Mevcut Featurelardaki Sorunlar (Düzeltilmesi Gereken)

### 1.1 Score Kolonları Ters Çalışıyor
Aşağıdaki skorlar "şüpheli davranış" ölçmesi gerekirken benign uygulamalar daha yüksek çıkıyor.
Sebep: Mutlak API çağrı sayısı kullanılıyor, büyük benign uygulamalar doğal olarak daha aktif.

```
network_score:       malware=1.77,  benign=5.64
anti_analysis_score: malware=1.00,  benign=3.04
stealth_score:       malware=27,    benign=381
dynamic_exec_score:  malware=23,    benign=370
```

**Çözüm:** Tüm score kolonlarını session süresine normalize et:
```python
score_normalized = raw_score / (session_duration_ms / 1000)
```

### 1.2 Extreme Outlier Kolonlar
Aşağıdaki kolonlarda p99 ile max arasında 10x-600x fark var.
Log1p normalizasyonu tek başına yeterli değil, p99 ile cap uygulanmalı.

| Kolon | p99 | max | Oran |
|-------|-----|-----|------|
| reflection_invoke_count | 1658 | 132108 | 80x |
| cipher_des_count | 1.1 | 676 | 626x |
| dns_lookup_count | 12 | 4037 | 336x |
| file_read_sensitive_count | 1 | 335 | 335x |
| shared_prefs_write_count | 62 | 8912 | 144x |
| stack_trace_inspect_count | 5 | 586 | 117x |
| file_write_count | 3 | 335 | 112x |

**Çözüm:** `df[col] = df[col].clip(upper=df[col].quantile(0.99))`

### 1.3 Session Duration Anomalisi
- Normal session ~75 saniye (sandbox timeout)
- max=7,995,429 ms (~133 dakika) → anormal
- Malware mean=48s, benign mean=88s → benign oturumlar çok daha uzun

**Yapılacak:** max > 300,000 ms olan örnekleri incele. Sandbox'tan kaçma mı, timeout sorunu mu?

### 1.4 Sıfır Variance Kolonlar (Hiç Tetiklenmemiş)
Aşağıdaki 8 kolon tüm dataset boyunca 0, yani hook'lar ya çalışmamış ya da bu davranışlar hiç gözlemlenmemiş. Araştırılmalı.

```
verify_attempt_count
string_decrypt_count
setRequestProperty_count
job_scheduler_count
memory_alloc_large_count
native_method_register_count
has_full_spy_pattern
seq_contact_then_sms
```

### 1.5 reflection_invoke_count Ham Sayı Olarak Yanıltıcı
- malware mean=23, benign mean=369 → benign çok daha fazla reflection kullanıyor
- Büyük benign uygulamalar ORM/DI framework kullandığı için normal
- Ham count modeli yanıltıyor

**Çözüm:** `reflection_rate = reflection_invoke_count / session_seconds` kullan

---

## 2. Mevcut Veriden Türetilebilecek Yeni Featurelar
> Yeniden dinamik analiz gerektirmez, mevcut CSV'den hesaplanabilir.

### 2.1 Session-Normalized Rate Featurelar
Tüm count featureları session süresine böl:

```python
session_sec = session_duration_ms / 1000

reflection_rate         = reflection_invoke_count / session_sec
network_events_rate     = (socket_create_count + url_connection_count + dns_lookup_count) / session_sec
file_write_rate         = file_write_count / session_sec
crypto_rate             = cipher_init_count / session_sec
anti_analysis_rate      = (debugger_check_count + emulator_check_count + root_check_count) / session_sec
dynamic_load_rate       = dynamic_class_load_count / session_sec
```

### 2.2 Inter-Event Delta Featurelar
`first_*_ms` kolonlarından event'ler arası geçen süreyi hesapla.
(-1 olan değerleri (event hiç olmadı) dikkate alma.)

```python
# Reflection başladıktan kaç ms sonra exec çalıştı
delta_exec_after_reflection = first_exec_ms - first_reflection_ms
    # koşul: her ikisi de > 0

# Dosya yazımından kaç ms sonra network bağlantısı kuruldu
delta_network_after_file    = first_network_ms - first_file_write_ms

# Crypto işleminden kaç ms sonra network bağlantısı kuruldu
delta_network_after_crypto  = first_network_ms - first_crypto_ms

# DexClassLoader'dan kaç ms sonra reflection başladı
delta_reflection_after_dex  = first_reflection_ms - first_dynamic_load_ms
```

### 2.3 Erken Davranış Flag'leri (İlk 5 Saniye)
```python
early_exec_flag       = (first_exec_ms > 0) & (first_exec_ms < 5000)
early_file_write_flag = (first_file_write_ms > 0) & (first_file_write_ms < 5000)
early_crypto_flag     = (first_crypto_ms > 0) & (first_crypto_ms < 5000)
early_anti_flag       = (first_anti_analysis_ms > 0) & (first_anti_analysis_ms < 5000)
```

Veriyle doğrulanmış: `first_exec_ms` malware=243ms, benign=23ms — erken exec malware sinyali.

---

## 3. Yeniden Dinamik Analiz Gerektiren Yeni Featurelar
> Bir sonraki veri toplama turunda eklenmeli.

### 3.1 Sequence Count Featurelar (Binary Yerine Sayısal)
Şu an `seq_*` kolonları 0/1 (pattern gerçekleşti mi). Kaç kez gerçekleştiği daha anlamlı.

```
seq_reflect_before_exec_count    # kaç kez reflection → exec zinciri kuruldu
seq_dex_then_reflect_count       # kaç kez dex load → reflection izledi
seq_file_then_network_count      # kaç kez dosya yaz → network gönder oldu  ← EN GÜÇLÜ SİNYAL
seq_crypto_before_network_count  # kaç kez şifrele → gönder oldu
seq_root_check_before_exec_count
```

Mevcut veriden doğrulanmış güç:
- `seq_file_then_network`: malware=%9.4, benign=%0.1
- `seq_reflect_before_exec`: malware=%13.5, benign=%0.6
- `seq_dex_then_reflect`: malware=%10.9, benign=%0.9

### 3.2 Time-Windowed Activity Featurelar
Session'ı zaman dilimlerine böl, her dilimde kaç event olduğunu say:

```
events_first_10s     # ilk 10 saniyedeki toplam event sayısı
events_first_30s
events_10s_to_30s    # 10-30s arası
events_last_30s      # son 30 saniye
early_activity_ratio = events_first_10s / total_events
```

Hipotez: Malware erken hareket eder (ilk 10s yoğun), benign zamanla aktif olur.

### 3.3 Eksik Davranış Featureları

```
unique_process_spawned_count     # kaç farklı process başlattı
binder_transaction_count         # IPC yoğunluğu
foreground_service_start_count   # arka planda çalışma girişimi
wake_lock_acquire_count          # ekran kapalıyken uyanık kalma
intent_with_data_count           # data payload taşıyan intent sayısı
content_provider_unique_count    # kaç farklı content provider'a erişti
permission_used_vs_declared_ratio # talep edilen vs gerçekten kullanılan izin oranı
```

---

## 4. Güçlü Sinyaller (Mevcut Veriden Doğrulandı)

Aşağıdaki featurelar zaten iyi çalışıyor, korunmalı:

| Feature | Malware | Benign | Not |
|---------|---------|--------|-----|
| `write_to_read_ratio` | 0.47 | 0.007 | Çok güçlü |
| `seq_file_then_network` | %9.4 | %0.1 | Çok güçlü |
| `first_sms_ms > 0` | Var | Hiç yok | Kesin sinyal |
| `seq_reflect_before_exec` | %13.5 | %0.6 | Güçlü |
| `seq_dex_then_reflect` | %10.9 | %0.9 | Güçlü |
| `anti_to_total_ratio` | 0.27 | 0.12 | Orta |

---

## 5. Aksiyon Sırası

| Adım | Aksiyon | Yeniden Analiz? |
|------|---------|-----------------|
| 1 | Score kolonlarını `/ session_seconds` ile normalize et | Hayır |
| 2 | Rate featureları hesapla (2.1) | Hayır |
| 3 | Inter-event delta featureları hesapla (2.2) | Hayır |
| 4 | Outlier cap uygula (p99) | Hayır |
| 5 | Session duration anomalilerini araştır | Hayır |
| 6 | Sıfır-variance hook'larını doğrula | Hayır |
| 7 | Sequence count featureları ekle (3.1) | **Evet** |
| 8 | Time-window featureları ekle (3.2) | **Evet** |
| 9 | Eksik davranış featureları ekle (3.3) | **Evet** |
| 10 | Veri artır (hedef: 10k+ APK, çeşitli family) | **Evet** |
| 11 | LightGBM, MLP, stacking karşılaştırması | Hayır |
