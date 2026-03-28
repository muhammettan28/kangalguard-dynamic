# Kangal Feature Reference — Temiz Feature Uzayı & LLM Taxonomisi

Kaynak: `kangal_collector.py` + `20k_improved.ipynb` + `20k_feature_reduction.ipynb`
Hedef: Kolektör değişikliği + temiz feature uzayı + LLM girdi yapısı

---

## 1. Kolektör Değişikliği (2 satır)

`kangal_collector.py` dosyasında iki yer:

**`CSV_FILE` satırının hemen altına:**
```python
SEQ_LOG_FILE = CSV_FILE.replace('.csv', '_seqlogs.jsonl')
```

**`write_row()` içinde `csv.writer(f).writerow(row)` satırının hemen altına:**
```python
if latest_seq_log:
    with open(SEQ_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps({
            "package_name": PACKAGE_NAME,
            "label": LABEL,
            "session_duration_ms": latest_session_duration_ms,
            "seq_log": latest_seq_log
        }) + '\n')
```

`json` zaten import edilmiş. Başka değişiklik yok.

**Çıktı formatı** (`kangal_seqlogs.jsonl`, her satır bir APK):
```json
{"package_name": "com.example", "label": "malware", "session_duration_ms": 45000,
 "seq_log": [{"tag": "REFLECT", "ms": 142}, {"tag": "DEX_LOAD", "ms": 890}, {"tag": "EXEC", "ms": 3421}, {"tag": "NETWORK", "ms": 5100}]}
```

---

## 2. Event Vocabulary — 18 Tag (seq_log içeriği)

Frida agent'ın gönderdiği sabit tag seti. Her tag bir API kategorisini temsil eder:

```
Tag             CSV karşılığı                    Anlam
─────────────── ──────────────────────────────── ──────────────────────────────────
REFLECT         reflection_invoke_count          Java Reflection API kullanımı
DEX_LOAD        dex_class_loader_count           Harici DEX dosyası yükleme
DYNAMIC_CLS     dynamic_class_load_count         Dinamik sınıf yükleme
EXEC            runtime_exec_count               Kabuk komutu çalıştırma
NATIVE_LOAD     native_lib_load_count            Native kütüphane yükleme
CRYPTO          cipher_init/aes/des/keygen       Şifreleme işlemi
NETWORK         socket/url_connection/dns        Ağ bağlantısı
ANTI            debugger/emulator/root_check     Anti-analiz kontrolü
ROOT_CHECK      root_check_count                 Root tespiti
FILE_WRITE      file_write_count                 Dosyaya yazma
SMS             sendTextMessage_count            SMS gönderme
CONTACT_READ    content_resolver_query           Rehber/içerik okuma
SURVEIL         getDeviceId/getSubscriberId      Cihaz kimliği sorgulama
PERSIST         alarm_manager/register_receiver  Kalıcılık mekanizması
IPC             bindService/sendBroadcast        Süreçler arası iletişim
CLIPBOARD       clipboard_read/write             Pano okuma/yazma
OVERLAY         overlay_window_count             Ekran bindirme (20k'da sıfır varyans)
ACCESSIBILITY   accessibility_query_count        Erişilebilirlik servisi kullanımı
```

---

## 3. Kolektör CSV — 143 Kolon (ham çıktı)

### Raw Features — 54 kolon
```
reflection_invoke_count       dex_class_loader_count        runtime_exec_count
dynamic_class_load_count      getPackageInfo_count           sendTextMessage_count
getDeviceId_count             getSubscriberId_count          cipher_init_count
cipher_aes_count              cipher_des_count               secret_key_gen_count
base64_encode_count           system_exit_attempt            debugger_check_count
emulator_check_count          root_check_count               sleep_call_count
stack_trace_inspect_count     secure_random_count            verify_attempt_count
string_decrypt_count          native_lib_load_count          implicit_intent_count
startActivity_count           sendBroadcast_count            bindService_count
content_resolver_query_count  content_resolver_insert_count  file_write_count
file_read_sensitive_count     shared_prefs_write_count       openFileOutput_count
deleteFile_count              getExternalStorageDirectory_count socket_create_count
url_connection_count          ssl_bypass_attempt             dns_lookup_count
setRequestProperty_count      alarm_manager_set_count        job_scheduler_count
register_receiver_count       requestPermission_count        setComponentEnabled_count
thread_create_count           process_list_query_count       memory_alloc_large_count
class_loader_parent_count     native_method_register_count   accessibility_query_count
overlay_window_count          clipboard_read_count           clipboard_write_count
```

### Derived Features — 36 kolon
```
network_score                 anti_analysis_score            persistence_score
stealth_score                 exfil_score                    privilege_score
surveillance_score            dynamic_exec_score
crypto_to_network_ratio       write_to_read_ratio            anti_to_total_ratio
reflection_to_exec_ratio      network_to_activity_ratio
has_crypto_and_network        has_exfil_pattern              has_evasion_pattern
has_persistence_pattern       has_privilege_escalation       has_sms_exfil
has_full_spy_pattern
network_score_per_sec         anti_analysis_score_per_sec    stealth_score_per_sec
dynamic_exec_score_per_sec
reflection_rate               network_events_rate            file_write_rate
crypto_rate                   anti_analysis_rate             dynamic_load_rate
log1p_reflection_invoke       log1p_dns_lookup               log1p_shared_prefs_write
log1p_file_read_sensitive     log1p_stack_trace_inspect      log1p_file_write
```

### Temporal Features — 22 kolon
```
first_network_ms    first_crypto_ms     first_anti_analysis_ms  first_file_write_ms
first_reflection_ms first_exec_ms       first_sms_ms            first_dynamic_load_ms
burst_peak_count    session_duration_ms
early_network_flag  early_anti_analysis_flag  crypto_before_network  rapid_burst_flag
early_exec_flag     early_file_write_flag     early_crypto_flag
delta_exec_after_reflection  delta_network_after_file
delta_network_after_crypto   delta_reflection_after_dex
session_anomaly_flag
```

### Sequence Features — 28 kolon (seq_log'dan aggregate)
```
seq_reflect_before_exec       seq_crypto_before_network      seq_root_check_before_exit
seq_dex_then_reflect          seq_anti_before_payload        seq_file_then_network
seq_contact_then_sms          seq_surveil_before_network     seq_persist_before_exec
seq_clipboard_before_network  seq_overlay_before_network
seq_reflect_exec_count        seq_dex_reflect_count          seq_file_network_count
seq_crypto_network_count      seq_anti_exec_count            seq_surveil_network_count
seq_clipboard_network_count
seq_first_reflect_exec_ms     seq_first_dex_reflect_ms       seq_first_file_network_ms
seq_first_crypto_network_ms   seq_first_anti_exec_ms         seq_first_surveil_network_ms
seq_first_clipboard_network_ms
seq_triple_chain_count        seq_max_chain_length           seq_alternating_crypto_net
```

---

## 4. Kaldırılacak Kolonlar

### 4a. Sıfır Varyanslı — 8 kolon (20k dataset'te hiç tetiklenmedi)
```python
ZERO_VAR_COLS = [
    'verify_attempt_count',
    'string_decrypt_count',
    'setRequestProperty_count',
    'job_scheduler_count',
    'memory_alloc_large_count',
    'native_method_register_count',
    'overlay_window_count',           # raw
    'seq_overlay_before_network',     # sequence
]
```

### 4b. Double-Transform Yaratan — 6 kolon
Kolektörde log1p alınmış, eğitimde tekrar log1p uygulanırsa çift dönüşüm:
```python
LOG1P_PRECALC_COLS = [
    'log1p_reflection_invoke',     # reflection_invoke_count zaten var
    'log1p_dns_lookup',            # dns_lookup_count zaten var
    'log1p_shared_prefs_write',    # shared_prefs_write_count zaten var
    'log1p_file_read_sensitive',   # file_read_sensitive_count zaten var
    'log1p_stack_trace_inspect',   # stack_trace_inspect_count zaten var
    'log1p_file_write',            # file_write_count zaten var
]
```

### 4c. Mükemmel Korelasyonlu (r=1.000) — 6 kolon
Birebir kopya — hiçbir bilgi katkısı yok:
```python
REDUNDANT_COLS = [
    'network_events_rate',        # == network_score_per_sec
    'network_to_activity_ratio',  # == network_score
    'dynamic_exec_score',         # == reflection_invoke_count
    'persistence_score',          # == register_receiver_count
    'privilege_score',            # == process_list_query_count
    'reflection_rate',            # == dynamic_exec_score_per_sec
]
```

**Toplam kaldırılan: 20 kolon**

---

## 5. Notebook'ta Üretilen Ek Features (143 CSV'de yok, eğitimde hesaplanır)

### 5a. Sentinel Mühendisliği — 15 yeni binary flag
`first_*_ms = -1` → "olay hiç gerçekleşmedi". Her timing kolonu için flag + clip(-1→0):
```
occurred_network          ← first_network_ms
occurred_crypto           ← first_crypto_ms
occurred_anti_analysis    ← first_anti_analysis_ms
occurred_file_write       ← first_file_write_ms
occurred_reflection       ← first_reflection_ms
occurred_exec             ← first_exec_ms
occurred_sms              ← first_sms_ms
occurred_dynamic_load     ← first_dynamic_load_ms
occurred_reflect_exec     ← seq_first_reflect_exec_ms
occurred_dex_reflect      ← seq_first_dex_reflect_ms
occurred_file_network     ← seq_first_file_network_ms
occurred_crypto_network   ← seq_first_crypto_network_ms
occurred_anti_exec        ← seq_first_anti_exec_ms
occurred_surveil_network  ← seq_first_surveil_network_ms
occurred_clipboard_network← seq_first_clipboard_network_ms
```

### 5b. Timing Ratio — 15 yeni kolon  (`*_ms / session_duration_ms`)
Geciktirmeli aktivasyon sinyali: 0.0=erken, 1.0=session sonunda tetiklendi
```
first_network_ratio            first_crypto_ratio
first_anti_analysis_ratio      first_file_write_ratio
first_reflection_ratio         first_exec_ratio
first_sms_ratio                first_dynamic_load_ratio
seq_first_reflect_exec_ratio   seq_first_dex_reflect_ratio
seq_first_file_network_ratio   seq_first_crypto_network_ratio
seq_first_anti_exec_ratio      seq_first_surveil_network_ratio
seq_first_clipboard_network_ratio
```

### 5c. Event Density — 9 yeni kolon (`count / session_duration_ms`)
```
reflect_density     ← reflection_invoke_count
network_density     ← url_connection_count
crypto_density      ← cipher_aes_count
exec_density        ← runtime_exec_count
dex_density         ← dex_class_loader_count
file_write_density  ← file_write_count
dns_density         ← dns_lookup_count
subscriber_density  ← getSubscriberId_count
sms_density         ← sendTextMessage_count
```

**Preprocessing sonrası toplam: 159 feature** (GBDT için), **seq_log ayrı** (Transformer için)

---

## 6. Temiz Feature Uzayı — Öncelik Sıralı (Top-50 Konsensüs)

`CSV` = kolektörden doğrudan | `ENG` = notebook'ta hesaplanan

```
#   Feature                          Kaynak        Kategori
──  ───────────────────────────────  ────────────  ─────────────────────
1   session_duration_ms              CSV/temporal  Zaman
2   accessibility_query_count        CSV/raw       Davranış
3   getDeviceId_count                CSV/raw       Gözetleme
4   seq_max_chain_length             CSV/sequence  Zincir
5   anti_analysis_score_per_sec      CSV/derived   Anti-analiz yoğunluğu
6   first_reflection_ratio           ENG/ratio     Zamanlama
7   system_exit_attempt              CSV/raw       Kaçış
8   implicit_intent_count            CSV/raw       Davranış
9   first_reflection_ms              CSV/temporal  Zamanlama
10  register_receiver_count          CSV/raw       Kalıcılık
11  dynamic_load_rate                CSV/derived   Yükleme hızı
12  anti_analysis_score              CSV/derived   Anti-analiz toplam
13  network_density                  ENG/density   Ağ yoğunluğu
14  startActivity_count              CSV/raw       Davranış
15  getSubscriberId_count            CSV/raw       Gözetleme
16  subscriber_density               ENG/density   Gözetleme yoğunluğu
17  first_network_ms                 CSV/temporal  Zamanlama
18  dynamic_class_load_count         CSV/raw       Yükleme
19  sleep_call_count                 CSV/raw       Anti-analiz
20  anti_to_total_ratio              CSV/derived   Gizlilik oranı
21  first_anti_analysis_ms           CSV/temporal  Zamanlama
22  dynamic_exec_score_per_sec       CSV/derived   Çalıştırma yoğunluğu
23  stealth_score_per_sec            CSV/derived   Gizlilik yoğunluğu
24  dex_class_loader_count           CSV/raw       Yükleme
25  surveillance_score               CSV/derived   Gözetleme toplam
26  burst_peak_count                 CSV/temporal  Ani aktivite
27  reflection_to_exec_ratio         CSV/derived   Yansıma/çalıştırma oranı
28  reflection_invoke_count          CSV/raw       Yansıma
29  secure_random_count              CSV/raw       Kripto
30  thread_create_count              CSV/raw       Davranış
31  first_dynamic_load_ms            CSV/temporal  Zamanlama
32  first_crypto_ms                  CSV/temporal  Zamanlama
33  dex_density                      ENG/density   DEX yoğunluğu
34  network_score_per_sec            CSV/derived   Ağ yoğunluğu
35  first_network_ratio              ENG/ratio     Zamanlama
36  first_dynamic_load_ratio         ENG/ratio     Zamanlama
37  stealth_score                    CSV/derived   Gizlilik toplam
38  bindService_count                CSV/raw       IPC
39  native_lib_load_count            CSV/raw       Native
40  deleteFile_count                 CSV/raw       Dosya
41  alarm_manager_set_count          CSV/raw       Kalıcılık
42  reflect_density                  ENG/density   Yansıma yoğunluğu
43  getExternalStorageDirectory_count CSV/raw       Dosya
44  seq_first_surveil_network_ratio  ENG/ratio     Gözetleme→Ağ zamanlaması
45  url_connection_count             CSV/raw       Ağ
46  delta_reflection_after_dex       CSV/temporal  Sıralama delta
47  seq_first_dex_reflect_ms         CSV/sequence  Zincir zamanlaması
48  openFileOutput_count             CSV/raw       Dosya
49  early_anti_analysis_flag         CSV/temporal  Erken tetiklenme
50  seq_first_surveil_network_ms     CSV/sequence  Zincir zamanlaması
```

---

## 7. LLM Girdi Notu

Bölüm 6'daki temiz feature uzayı (seq_log dahil) KangalGuard'da LLM'e girdi olarak kullanılacaktır.
seq_log'un olay sırası ve zamanlama bilgisi, tabular feature'larla birlikte LLM'e verildiğinde
doğal dil açıklaması üretmek için yeterli ve kapsamlı bir feature uzayı sağlar.

---

## 8. Özet

| | Transformer | GBDT Baseline | LLM Explainer |
|---|---|---|---|
| **Girdi** | seq_log (ham sıra) | 159 tabular feature | Kategori A-F prompt |
| **Kaynak** | kangal_seqlogs.jsonl | kangal_dataset.csv + preprocessing | Transformer + CSV |
| **Novel katkı** | ✅ Temporal shift | ✅ Baseline | KangalGuard uygulaması |

**Kolektörde yapılacak tek değişiklik:** Bölüm 1 — 2 satır.
**GBDT pipeline:** Bölüm 4 drop listesi + Bölüm 5 engineering → mevcut notebook kodu.
**Transformer:** seq_log → ham event sırası, Bölüm 2 vocabulary.
**LLM:** Bölüm 7 kategori şablonları.
