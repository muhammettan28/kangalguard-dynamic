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

## Mimari

```
agent.ts              — Frida TypeScript agent, 54 Java API hook, emülatöre inject edilir
kangal_collector.py   — Feature engineering, 143 CSV kolonu tanımlar ve hesaplar
batch_analyzer.py     — Orchestration: install → attach → poll → CSV → uninstall
```

### `agent.ts` — Hook Kategorileri (54 hook)

| Kategori | Hook'lar | seqLog Tag |
|----------|----------|------------|
| Java API | reflection, DexClassLoader, Runtime.exec, Class.forName, getPackageInfo, SMS, getDeviceId, getSubscriberId | REFLECT, DEX_LOAD, EXEC, DYNAMIC_CLS, SMS, SURVEIL |
| Crypto | Cipher.init (AES/DES), KeyGenerator, Base64, SecureRandom | CRYPTO |
| Anti-Analysis | System.exit, Process.kill, Runtime.halt, isDebuggerConnected, SystemProperties, File.exists (root path), Thread.sleep, getStackTrace, loadLibrary | ANTI, ROOT_CHECK, NATIVE_LOAD |
| Intent & IPC | Intent.setAction, startActivity, sendBroadcast, bindService, ContentResolver.query/insert | IPC, CONTACT_READ |
| File System | FileOutputStream, SharedPreferences, openFileOutput, File.delete, getExternalStorageDirectory | FILE_WRITE |
| Network | Socket, URL.openConnection, SSLContext, InetAddress (DNS), setRequestProperty | NETWORK |
| Persistence | AlarmManager.set, JobScheduler, registerReceiver, requestPermissions, setComponentEnabled | PERSIST |
| Process & Memory | Thread.$init, getRunningAppProcesses, ByteBuffer.allocate (>5MB), ClassLoader.getParent | — |
| **Clipboard** | ClipboardManager.getPrimaryClip / setPrimaryClip | CLIPBOARD |
| **Accessibility** | AccessibilityManager.isEnabled / getEnabledServiceList | ACCESSIBILITY |
| **Overlay** | WindowManagerImpl.addView (TYPE_APPLICATION_OVERLAY ve türleri) | OVERLAY |

#### seqLog Per-Tag Throttle
Global `MAX_SEQ_EVENTS` yerine her tag için ayrı limit uygulanır (REFLECT/DYNAMIC_CLS: 15, NETWORK: 30, CLIPBOARD/OVERLAY: 10-20). Bu sayede yüksek frekanslı benign davranışlar (reflection) seqLog'u doldurup kritik malware event'lerini ezemiyor.

---

## Feature Schema (143 sütun)

### 3 Meta Kolonu
`package_name`, `label`, `timestamp`

### 54 Ham Sayaç (Raw)
Agent.ts'ten doğrudan gelen event sayıları.

| Kategori | Kolonlar |
|----------|----------|
| Java API | reflection_invoke_count, dex_class_loader_count, runtime_exec_count, dynamic_class_load_count, getPackageInfo_count, sendTextMessage_count, getDeviceId_count, getSubscriberId_count |
| Crypto | cipher_init_count, cipher_aes_count, cipher_des_count, secret_key_gen_count, base64_encode_count |
| Anti-Analysis | system_exit_attempt, debugger_check_count, emulator_check_count, root_check_count, sleep_call_count, stack_trace_inspect_count, secure_random_count |
| Genel | verify_attempt_count, string_decrypt_count, native_lib_load_count |
| IPC | implicit_intent_count, startActivity_count, sendBroadcast_count, bindService_count, content_resolver_query_count, content_resolver_insert_count |
| Dosya | file_write_count, file_read_sensitive_count, shared_prefs_write_count, openFileOutput_count, deleteFile_count, getExternalStorageDirectory_count |
| Network | socket_create_count, url_connection_count, ssl_bypass_attempt, dns_lookup_count, setRequestProperty_count |
| Persistence | alarm_manager_set_count, job_scheduler_count, register_receiver_count, requestPermission_count, setComponentEnabled_count |
| Process | thread_create_count, process_list_query_count, memory_alloc_large_count, class_loader_parent_count, native_method_register_count |
| **Yeni** | **accessibility_query_count, overlay_window_count, clipboard_read_count, clipboard_write_count** |

### 36 Türetilmiş Feature (Derived)

**8 Kompozit Skor** (ham sayaçların toplamı):
`network_score`, `anti_analysis_score`, `persistence_score`, `stealth_score`, `exfil_score`, `privilege_score`, `surveillance_score`, `dynamic_exec_score`

**5 Oran Feature**:
`crypto_to_network_ratio`, `write_to_read_ratio`, `anti_to_total_ratio`, `reflection_to_exec_ratio`, `network_to_activity_ratio`

**7 Boolean Pattern**:
`has_crypto_and_network`, `has_exfil_pattern`, `has_evasion_pattern`, `has_persistence_pattern`, `has_privilege_escalation`, `has_sms_exfil`, `has_full_spy_pattern`

**4 Session-Normalized Skor** — *ham skorların session süresine bölünmüş hali; benign uygulamaların daha uzun oturum süresi nedeniyle oluşan yanıltıcı büyük değerleri düzeltir:*
`network_score_per_sec`, `anti_analysis_score_per_sec`, `stealth_score_per_sec`, `dynamic_exec_score_per_sec`

**6 Rate Feature** (count / session_sec):
`reflection_rate`, `network_events_rate`, `file_write_rate`, `crypto_rate`, `anti_analysis_rate`, `dynamic_load_rate`

**6 Log1p Outlier Feature** — *p99/max farkı 80x-336x olan kolonlar için ML stabilitesi sağlar:*
`log1p_reflection_invoke` (80x), `log1p_dns_lookup` (336x), `log1p_shared_prefs_write` (144x), `log1p_file_read_sensitive` (335x), `log1p_stack_trace_inspect` (117x), `log1p_file_write` (112x)

### 22 Temporal Feature

**8 İlk Tetiklenme Zamanı** (ms, -1 = tetiklenmedi):
`first_network_ms`, `first_crypto_ms`, `first_anti_analysis_ms`, `first_file_write_ms`, `first_reflection_ms`, `first_exec_ms`, `first_sms_ms`, `first_dynamic_load_ms`

**Burst & Oturum**:
`burst_peak_count`, `session_duration_ms`

**Türetilmiş Temporal**:
- `early_network_flag`, `early_anti_analysis_flag`, `crypto_before_network`, `rapid_burst_flag` — mevcut
- `early_exec_flag`, `early_file_write_flag`, `early_crypto_flag` — ilk 5s içinde event var mı?
- `delta_exec_after_reflection`, `delta_network_after_file`, `delta_network_after_crypto`, `delta_reflection_after_dex` — iki event arası delta (ms)
- `session_anomaly_flag` — oturum > 300s ise 1 (sandbox anomalisi)

### 28 Sequence Feature

**10 Binary Zincir Flag** (0/1 — zincir gerçekleşti mi?):
`seq_reflect_before_exec`, `seq_crypto_before_network`, `seq_root_check_before_exit`, `seq_dex_then_reflect`, `seq_anti_before_payload`, `seq_file_then_network`, `seq_contact_then_sms`, `seq_triple_chain_count`, `seq_max_chain_length`, `seq_alternating_crypto_net`

**5 Zincir Sayısı** (kaç kez gerçekleşti?):
`seq_reflect_exec_count`, `seq_dex_reflect_count`, `seq_file_network_count`, `seq_crypto_network_count`, `seq_anti_exec_count`

**5 İlk Zincir Zamanı** (ms, -1 = hiç olmadı):
`seq_first_reflect_exec_ms`, `seq_first_dex_reflect_ms`, `seq_first_file_network_ms`, `seq_first_crypto_network_ms`, `seq_first_anti_exec_ms`

**8 Yeni Saldırı Vektörü Zinciri** (modern malware için):
- Binary: `seq_surveil_before_network`, `seq_persist_before_exec`, `seq_clipboard_before_network`, `seq_overlay_before_network`
- Count: `seq_surveil_network_count`, `seq_clipboard_network_count`
- Timing: `seq_first_surveil_network_ms`, `seq_first_clipboard_network_ms`

---

## Dataset

- `kangal_dataset.csv` — Çıktı dataset (143 kolon)
- `data/benign/` — Benign APK'lar (KronoDroid, AndroZoo)
- `data/malware/` — Malware APK'lar
- `logs/failed_apks.csv` — Hatalı/atlanan APK logu
- `logs/run_<timestamp>_<label>.log` — Çalıştırma logları

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

## Teknik Notlar

- **PID attach, spawn değil**: `device.spawn()` jailed Android'de "need Gadget" verir. Çözüm: `adb shell monkey` ile başlat, `adb shell pidof` ile PID bul, o PID'e attach et.
- **RPC polling**: `exports_sync.get_counters()` her 5s'de bir çağrılır. `on_message` yerine polling tercih edilir — batch analizde daha güvenilir.
- **Snapshot restore**: Her APK öncesi `kangal_clean` snapshot'ı yüklenir — frida-server dahil temiz durum garantisi.
- **Agent tek derleme**: `frida.Compiler()` startup'ta `agent.ts`'i derler, bundle tüm APK'lar için yeniden kullanılır.
- **`_rpc_safe(timeout_s=8)`**: Donmuş process (ANR) RPC'yi sonsuza kadar bloklayabilir. Daemon thread ile sarılmıştır; 8s içinde cevap gelmezse `RuntimeError("rpc_timeout")` fırlatır. 3 ardışık freeze döngüyü sonlandırır.
- **`dismiss_dialogs()`**: KEYCODE_BACK + KEYCODE_ENTER ile ANR/"App Has Stopped" diyaloglarını kapatır. Her APK başında ve polling içinde her 15s'de bir çağrılır.
