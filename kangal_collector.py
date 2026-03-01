import frida
import csv
import sys
import time
import os
import json
from datetime import datetime

# ─── Ayarlar ─────────────────────────────────────────────────────────────────

PACKAGE_NAME  = "owasp.mstg.uncrackable1"
LABEL         = "benign"          # "benign" veya "malware" — elle değiştir
ANALYSIS_TIME = 75                # Kaç saniye analiz yapılsın (0 = sonsuz)
CSV_FILE      = "kangal_dataset.csv"
AGENT_TS      = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.ts")

# ─── Ham Feature Sütunları (agent.ts'ten gelen 50 sayaç) ─────────────────────

RAW_FEATURE_COLUMNS = [
    # Java API Calls
    "reflection_invoke_count", "dex_class_loader_count", "runtime_exec_count",
    "dynamic_class_load_count", "getPackageInfo_count", "sendTextMessage_count",
    "getDeviceId_count", "getSubscriberId_count",
    # Crypto
    "cipher_init_count", "cipher_aes_count", "cipher_des_count",
    "secret_key_gen_count", "base64_encode_count",
    # Anti-Analysis
    "system_exit_attempt", "debugger_check_count", "emulator_check_count",
    "root_check_count", "sleep_call_count", "stack_trace_inspect_count",
    "secure_random_count",
    # Genel Davranış
    "verify_attempt_count", "string_decrypt_count", "native_lib_load_count",
    # Intent & IPC
    "implicit_intent_count", "startActivity_count", "sendBroadcast_count",
    "bindService_count", "content_resolver_query_count", "content_resolver_insert_count",
    # File System
    "file_write_count", "file_read_sensitive_count", "shared_prefs_write_count",
    "openFileOutput_count", "deleteFile_count", "getExternalStorageDirectory_count",
    # Network & Socket
    "socket_create_count", "url_connection_count", "ssl_bypass_attempt",
    "dns_lookup_count", "setRequestProperty_count",
    # Persistence & Privilege
    "alarm_manager_set_count", "job_scheduler_count", "register_receiver_count",
    "requestPermission_count", "setComponentEnabled_count",
    # Process & Memory
    "thread_create_count", "process_list_query_count", "memory_alloc_large_count",
    "class_loader_parent_count", "native_method_register_count",
]

# ─── Türetilmiş Feature Sütunları (Python'da hesaplanan 20 yeni feature) ─────

DERIVED_FEATURE_COLUMNS = [

    # ── Skor Feature'ları (8 adet) ───────────────────────────────────────────
    "network_score",        # socket + url + dns + setRequestProp
    "anti_analysis_score",  # exit + debugger + emulator + root + sleep + stacktrace
    "persistence_score",    # alarm + jobscheduler + registerReceiver + setComponent
    "stealth_score",        # reflection + dexloader + dynamicClass + nativeLib
    "exfil_score",          # network + base64 + cipher + file_write
    "privilege_score",      # requestPermission + setComponent + processQuery + contentInsert
    "surveillance_score",   # getDeviceId + getSubscriberId + getPackageInfo + contentQuery
    "dynamic_exec_score",   # runtime_exec + dexloader + reflection + nativeLib

    # ── Oran Feature'ları (5 adet) ───────────────────────────────────────────
    "crypto_to_network_ratio",    # Şifreleme / Ağ → yüksekse exfiltration sinyali
    "write_to_read_ratio",        # Dosya yazma / Dosya okuma → veri toplama sinyali
    "anti_to_total_ratio",        # Anti-analiz / Toplam event → kaçınma yoğunluğu
    "reflection_to_exec_ratio",   # Reflection / Exec → dinamik payload pattern
    "network_to_activity_ratio",  # Ağ / startActivity → arka plan network yoğunluğu

    # ── Boolean Kombinasyon Feature'ları (7 adet) ────────────────────────────
    "has_crypto_and_network",     # Hem şifreleme hem ağ (1/0)
    "has_exfil_pattern",          # base64 + network birlikte (1/0)
    "has_evasion_pattern",        # anti-analysis + dynamic load birlikte (1/0)
    "has_persistence_pattern",    # En az 2 persistence mekanizması (1/0)
    "has_privilege_escalation",   # root check + native lib + dynamic load üçlüsü (1/0)
    "has_sms_exfil",              # SMS + network birlikte (1/0)
    "has_full_spy_pattern",       # DeviceId + SMS + network + crypto hepsi (1/0)
]

# ─── Temporal Feature Sütunları (agent.ts'ten gelen zamanlama verisi) ─────────

TEMPORAL_FEATURE_COLUMNS = [
    # İlk tetiklenme zamanları (ms) — -1 = hiç tetiklenmedi
    "first_network_ms",
    "first_crypto_ms",
    "first_anti_analysis_ms",
    "first_file_write_ms",
    "first_reflection_ms",
    "first_exec_ms",
    "first_sms_ms",
    "first_dynamic_load_ms",
    # Burst ve oturum
    "burst_peak_count",
    "session_duration_ms",
    # Türetilmiş temporal
    "early_network_flag",
    "early_anti_analysis_flag",
    "crypto_before_network",
    "rapid_burst_flag",
]

# ─── Sequence Feature Sütunları (10 adet) ────────────────────────────────────

SEQUENCE_FEATURE_COLUMNS = [
    "seq_reflect_before_exec",      # REFLECT → EXEC zinciri var mı?
    "seq_crypto_before_network",    # CRYPTO → NETWORK zinciri var mı?
    "seq_root_check_before_exit",   # ROOT_CHECK → ANTI(exit) zinciri var mı?
    "seq_dex_then_reflect",         # DEX_LOAD → REFLECT zinciri var mı?
    "seq_anti_before_payload",      # ANTI → (EXEC|DEX_LOAD) zinciri var mı?
    "seq_file_then_network",        # FILE_WRITE → NETWORK zinciri var mı?
    "seq_contact_then_sms",         # CONTACT_READ → SMS zinciri var mı?
    "seq_triple_chain_count",       # 3'lü malware zinciri kaç kez oluştu?
    "seq_max_chain_length",         # En uzun ardışık malware zinciri kaç event?
    "seq_alternating_crypto_net",   # CRYPTO-NET-CRYPTO-NET dönüşümlü pattern var mı?
]

# ─── Tüm CSV sütunları: 3 meta + 50 ham + 20 türetilmiş + 14 temporal + 10 sequence = 97 sütun

ALL_COLUMNS = (
    ["package_name", "label", "timestamp"]
    + RAW_FEATURE_COLUMNS
    + DERIVED_FEATURE_COLUMNS
    + TEMPORAL_FEATURE_COLUMNS
    + SEQUENCE_FEATURE_COLUMNS
)

# ─── Global State ─────────────────────────────────────────────────────────────

latest_timings: dict = {}
latest_burst_peak: int = 0
latest_session_duration_ms: int = 0
latest_seq_log: list = []
latest_counters: dict = {}
password_attempts: list = []
session_ref = None
script_ref  = None

# ─── Sequence Feature Hesaplama ──────────────────────────────────────────────

MALWARE_CHAINS = [
    ("REFLECT",      "EXEC"),
    ("CRYPTO",       "NETWORK"),
    ("ROOT_CHECK",   "ANTI"),
    ("DEX_LOAD",     "REFLECT"),
    ("ANTI",         "EXEC"),
    ("ANTI",         "DEX_LOAD"),
    ("FILE_WRITE",   "NETWORK"),
    ("CONTACT_READ", "SMS"),
    ("DEX_LOAD",     "EXEC"),
    ("NATIVE_LOAD",  "REFLECT"),
]

def has_chain(tags: list, a: str, b: str) -> bool:
    """tags listesinde A'dan sonra B geliyor mu?"""
    found_a = False
    for tag in tags:
        if tag == a:
            found_a = True
        elif found_a and tag == b:
            return True
    return False

def count_triple_chains(tags: list) -> int:
    """3 aşamalı malware zinciri kaç kez oluştu?"""
    TRIPLE_CHAINS = [
        ("DEX_LOAD",   "REFLECT",  "EXEC"),
        ("ANTI",       "CRYPTO",   "NETWORK"),
        ("ROOT_CHECK", "DEX_LOAD", "EXEC"),
        ("REFLECT",    "CRYPTO",   "NETWORK"),
        ("DEX_LOAD",   "CRYPTO",   "NETWORK"),
    ]
    count = 0
    for a, b, c in TRIPLE_CHAINS:
        for i, tag in enumerate(tags):
            if tag == a:
                rest = tags[i+1:]
                for j, tag2 in enumerate(rest):
                    if tag2 == b:
                        if c in rest[j+1:]:
                            count += 1
                            break
    return count

def max_consecutive_malware_chain(tags: list) -> int:
    """Ardışık malware tag'lerinin en uzun dizisi."""
    MALWARE_TAGS = {
        "REFLECT", "DEX_LOAD", "EXEC", "DYNAMIC_CLS",
        "CRYPTO", "NETWORK", "FILE_WRITE", "ROOT_CHECK",
        "ANTI", "SMS", "CONTACT_READ", "NATIVE_LOAD"
    }
    max_len, current = 0, 0
    for tag in tags:
        if tag in MALWARE_TAGS:
            current += 1
            max_len = max(max_len, current)
        else:
            current = 0
    return max_len

def has_alternating_crypto_net(tags: list) -> bool:
    """CRYPTO→NETWORK→CRYPTO→NETWORK dönüşümlü pattern var mı? (en az 2 döngü)"""
    pattern = ["CRYPTO", "NETWORK", "CRYPTO", "NETWORK"]
    filtered = [t for t in tags if t in ("CRYPTO", "NETWORK")]
    for i in range(len(filtered) - 3):
        if filtered[i:i+4] == pattern:
            return True
    return False

def compute_sequence_features(seq_log: list) -> dict:
    """
    agent.ts'ten gelen _seq_log listesinden 10 sequence feature hesaplar.
    seq_log: [{"tag": "REFLECT", "ms": 123}, ...]
    """
    tags = [e.get("tag", "") for e in seq_log]
    s = {}
    s["seq_reflect_before_exec"]    = int(has_chain(tags, "REFLECT",      "EXEC"))
    s["seq_crypto_before_network"]  = int(has_chain(tags, "CRYPTO",       "NETWORK"))
    s["seq_root_check_before_exit"] = int(has_chain(tags, "ROOT_CHECK",   "ANTI"))
    s["seq_dex_then_reflect"]       = int(has_chain(tags, "DEX_LOAD",     "REFLECT"))
    s["seq_anti_before_payload"]    = int(
        has_chain(tags, "ANTI", "EXEC") or has_chain(tags, "ANTI", "DEX_LOAD")
    )
    s["seq_file_then_network"]      = int(has_chain(tags, "FILE_WRITE",   "NETWORK"))
    s["seq_contact_then_sms"]       = int(has_chain(tags, "CONTACT_READ", "SMS"))
    s["seq_triple_chain_count"]     = count_triple_chains(tags)
    s["seq_max_chain_length"]       = max_consecutive_malware_chain(tags)
    s["seq_alternating_crypto_net"] = int(has_alternating_crypto_net(tags))
    return s

# ─── Temporal Feature Hesaplama ───────────────────────────────────────────────

def compute_temporal_features(timings: dict, burst_peak: int, session_ms: int) -> dict:
    """
    agent.ts'ten gelen _timings, _burst_peak, _session_duration_ms verilerinden
    14 temporal feature hesaplar.
    """
    t = {}

    # Ham zamanlama değerleri (-1 = tetiklenmedi)
    t["first_network_ms"]       = timings.get("first_network_ms", -1)
    t["first_crypto_ms"]        = timings.get("first_crypto_ms", -1)
    t["first_anti_analysis_ms"] = timings.get("first_anti_analysis_ms", -1)
    t["first_file_write_ms"]    = timings.get("first_file_write_ms", -1)
    t["first_reflection_ms"]    = timings.get("first_reflection_ms", -1)
    t["first_exec_ms"]          = timings.get("first_exec_ms", -1)
    t["first_sms_ms"]           = timings.get("first_sms_ms", -1)
    t["first_dynamic_load_ms"]  = timings.get("first_dynamic_load_ms", -1)

    # Burst ve süre
    t["burst_peak_count"]    = burst_peak
    t["session_duration_ms"] = session_ms

    # ── Türetilmiş temporal feature'lar ──────────────────────────────────────

    # İlk 5 saniye (5000ms) içinde ağ çağrısı var mı?
    net_ms = t["first_network_ms"]
    t["early_network_flag"] = int(0 <= net_ms <= 5000)

    # İlk 5 saniye içinde anti-analysis var mı?
    anti_ms = t["first_anti_analysis_ms"]
    t["early_anti_analysis_flag"] = int(0 <= anti_ms <= 5000)

    # Şifreleme ağdan önce mi geldi? (her ikisi de tetiklendiyse)
    crypto_ms = t["first_crypto_ms"]
    t["crypto_before_network"] = int(
        crypto_ms >= 0 and net_ms >= 0 and crypto_ms < net_ms
    )

    # 5 saniyelik pencerede 20+ event = anormal hız = malware burst pattern
    t["rapid_burst_flag"] = int(burst_peak >= 20)

    return t

# ─── Türetilmiş Feature Hesaplama ────────────────────────────────────────────

def safe_ratio(numerator: float, denominator: float) -> float:
    """Sıfıra bölme hatası olmadan oran hesapla"""
    return round(numerator / denominator, 4) if denominator > 0 else 0.0

def compute_derived_features(c: dict) -> dict:
    """
    50 ham sayaçtan 20 türetilmiş feature hesaplar.
    c: agent.ts'ten gelen ham sayaç dict'i
    """
    derived = {}

    # ── Skor Feature'ları ─────────────────────────────────────────────────────

    derived["network_score"] = (
        c.get("socket_create_count", 0) +
        c.get("url_connection_count", 0) +
        c.get("dns_lookup_count", 0) +
        c.get("setRequestProperty_count", 0)
    )

    derived["anti_analysis_score"] = (
        c.get("system_exit_attempt", 0) +
        c.get("debugger_check_count", 0) +
        c.get("emulator_check_count", 0) +
        c.get("root_check_count", 0) +
        c.get("sleep_call_count", 0) +
        c.get("stack_trace_inspect_count", 0)
    )

    derived["persistence_score"] = (
        c.get("alarm_manager_set_count", 0) +
        c.get("job_scheduler_count", 0) +
        c.get("register_receiver_count", 0) +
        c.get("setComponentEnabled_count", 0)
    )

    derived["stealth_score"] = (
        c.get("reflection_invoke_count", 0) +
        c.get("dex_class_loader_count", 0) +
        c.get("dynamic_class_load_count", 0) +
        c.get("native_lib_load_count", 0)
    )

    derived["exfil_score"] = (
        derived["network_score"] +
        c.get("base64_encode_count", 0) +
        c.get("cipher_init_count", 0) +
        c.get("file_write_count", 0)
    )

    derived["privilege_score"] = (
        c.get("requestPermission_count", 0) +
        c.get("setComponentEnabled_count", 0) +
        c.get("process_list_query_count", 0) +
        c.get("content_resolver_insert_count", 0)
    )

    derived["surveillance_score"] = (
        c.get("getDeviceId_count", 0) +
        c.get("getSubscriberId_count", 0) +
        c.get("getPackageInfo_count", 0) +
        c.get("content_resolver_query_count", 0)
    )

    derived["dynamic_exec_score"] = (
        c.get("runtime_exec_count", 0) +
        c.get("dex_class_loader_count", 0) +
        c.get("reflection_invoke_count", 0) +
        c.get("native_lib_load_count", 0)
    )

    # ── Oran Feature'ları ─────────────────────────────────────────────────────

    total_crypto  = c.get("cipher_init_count", 0) + c.get("secret_key_gen_count", 0)
    total_network = derived["network_score"]
    total_events  = sum(c.values())

    derived["crypto_to_network_ratio"] = safe_ratio(total_crypto, total_network)

    derived["write_to_read_ratio"] = safe_ratio(
        c.get("file_write_count", 0),
        max(c.get("file_read_sensitive_count", 0), 1)
    )

    derived["anti_to_total_ratio"] = safe_ratio(
        derived["anti_analysis_score"],
        max(total_events, 1)
    )

    derived["reflection_to_exec_ratio"] = safe_ratio(
        c.get("reflection_invoke_count", 0),
        max(c.get("runtime_exec_count", 0), 1)
    )

    derived["network_to_activity_ratio"] = safe_ratio(
        total_network,
        max(c.get("startActivity_count", 0), 1)
    )

    # ── Boolean Kombinasyon Feature'ları ─────────────────────────────────────

    # Hem şifreleme hem ağ var mı?
    derived["has_crypto_and_network"] = int(
        total_crypto > 0 and total_network > 0
    )

    # base64 encode + ağ bağlantısı = encode et + gönder = exfiltration
    derived["has_exfil_pattern"] = int(
        c.get("base64_encode_count", 0) > 0 and total_network > 0
    )

    # Anti-analysis + dynamic load = tespiti atlatıp payload çalıştır
    derived["has_evasion_pattern"] = int(
        derived["anti_analysis_score"] > 0 and derived["dynamic_exec_score"] > 0
    )

    # En az 2 farklı persistence mekanizması
    persistence_mechanisms = [
        c.get("alarm_manager_set_count", 0) > 0,
        c.get("job_scheduler_count", 0) > 0,
        c.get("register_receiver_count", 0) > 0,
        c.get("setComponentEnabled_count", 0) > 0,
    ]
    derived["has_persistence_pattern"] = int(sum(persistence_mechanisms) >= 2)

    # Root check + native lib + dynamic load = privilege escalation üçlüsü
    derived["has_privilege_escalation"] = int(
        c.get("root_check_count", 0) > 0 and
        c.get("native_lib_load_count", 0) > 0 and
        derived["dynamic_exec_score"] > 0
    )

    # SMS gönderme + ağ = SMS exfiltration (bankacılık trojanı klasik pattern)
    derived["has_sms_exfil"] = int(
        c.get("sendTextMessage_count", 0) > 0 and total_network > 0
    )

    # DeviceId + SMS + ağ + crypto hepsi = tam casus yazılım pattern
    derived["has_full_spy_pattern"] = int(
        c.get("getDeviceId_count", 0) > 0 and
        c.get("sendTextMessage_count", 0) > 0 and
        total_network > 0 and
        total_crypto > 0
    )

    return derived

# ─── CSV ──────────────────────────────────────────────────────────────────────

def init_csv():
    write_header = not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0
    if write_header:
        with open(CSV_FILE, 'w', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow(ALL_COLUMNS)
        print(f"[*] CSV oluşturuldu: {CSV_FILE}")
        print(f"[*] Toplam sütun: {len(ALL_COLUMNS)}  (3 meta + 50 ham + 20 türetilmiş + 14 temporal + 10 sequence)")
    else:
        print(f"[*] Mevcut CSV'ye ekleniyor: {CSV_FILE}")

def write_row(counters: dict):
    derived  = compute_derived_features(counters)
    temporal = compute_temporal_features(
        latest_timings, latest_burst_peak, latest_session_duration_ms
    )
    sequence = compute_sequence_features(latest_seq_log)

    row = [PACKAGE_NAME, LABEL, datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
    for col in RAW_FEATURE_COLUMNS:
        row.append(counters.get(col, 0))
    for col in DERIVED_FEATURE_COLUMNS:
        row.append(derived.get(col, 0))
    for col in TEMPORAL_FEATURE_COLUMNS:
        row.append(temporal.get(col, -1))
    for col in SEQUENCE_FEATURE_COLUMNS:
        row.append(sequence.get(col, 0))

    # ── Terminal raporu ───────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"[+] CSV YAZILDI — {datetime.now().strftime('%H:%M:%S')}")
    print(f"    {PACKAGE_NAME}  |  {LABEL.upper()}")
    print(f"{'─'*60}")

    nonzero_raw = {k: v for k, v in counters.items() if isinstance(v, (int,float)) and v > 0}
    if nonzero_raw:
        print("  Ham Feature'lar (aktif):")
        for k, v in nonzero_raw.items():
            print(f"    {k:<44} {v}")
    else:
        print("  (Ham feature tetiklenmedi)")

    print(f"{'─'*60}")
    print("  Türetilmiş Skorlar:")
    for k in [x for x in DERIVED_FEATURE_COLUMNS if "score" in x or "ratio" in x]:
        v = derived[k]
        if v > 0:
            print(f"    {k:<44} {v}")

    active_bool = [k for k in DERIVED_FEATURE_COLUMNS if k.startswith("has_") and derived[k] == 1]
    if active_bool:
        print("  ⚠️  Aktif Boolean Patternler:")
        for k in active_bool:
            print(f"    {k}")

    print(f"{'─'*60}")
    print("  Temporal Bilgiler:")
    for k in [x for x in TEMPORAL_FEATURE_COLUMNS if x.endswith("_ms") and "session" not in x]:
        v = temporal[k]
        if v >= 0:
            print(f"    {k:<44} {v} ms")
    print(f"    {'burst_peak_count':<44} {temporal['burst_peak_count']}")
    active_flags = [k for k in ["early_network_flag","early_anti_analysis_flag",
                                 "crypto_before_network","rapid_burst_flag"]
                    if temporal.get(k) == 1]
    if active_flags:
        for k in active_flags:
            print(f"    🕐 {k}")

    print(f"{'─'*60}")
    print(f"  Sequence Log: {len(latest_seq_log)} event kayıt edildi")
    active_seq = {k: v for k, v in sequence.items() if v}
    if active_seq:
        print("  🔗 Aktif Sequence Patternler:")
        for k, v in active_seq.items():
            print(f"    {k:<44} {v}")
    else:
        print("  (Tehlikeli sequence tespit edilmedi)")

    if password_attempts:
        print(f"{'─'*60}")
        print(f"  Şifre denemeleri: {password_attempts}")

    print(f"{'='*60}\n")

    with open(CSV_FILE, 'a', newline='', encoding='utf-8') as f:
        csv.writer(f).writerow(row)

    # ── Terminal raporu ───────────────────────────────────────────────────────
    print(f"\n{'='*58}")
    print(f"[+] CSV YAZILDI — {datetime.now().strftime('%H:%M:%S')}")
    print(f"    {PACKAGE_NAME}  |  {LABEL.upper()}")
    print(f"{'─'*58}")

    nonzero_raw = {k: v for k, v in counters.items() if v > 0}
    if nonzero_raw:
        print("  Ham Feature'lar (aktif):")
        for k, v in nonzero_raw.items():
            print(f"    {k:<42} {v}")
    else:
        print("  (Ham feature tetiklenmedi)")

    print(f"{'─'*58}")
    print("  Türetilmiş Skorlar:")
    score_keys = [k for k in DERIVED_FEATURE_COLUMNS if "score" in k or "ratio" in k]
    for k in score_keys:
        v = derived[k]
        if v > 0:
            print(f"    {k:<42} {v}")

    active_patterns = [k for k in DERIVED_FEATURE_COLUMNS if k.startswith("has_") and derived[k] == 1]
    print("  Aktif Boolean Patternler:")
    if active_patterns:
        for k in active_patterns:
            print(f"    ⚠️  {k}")
    else:
        print("    (Tehlikeli pattern tespit edilmedi)")

    # Temporal özet
    print(f"{'─'*58}")
    print("  Temporal Bilgiler:")
    timing_keys = [k for k in TEMPORAL_FEATURE_COLUMNS if k.endswith("_ms") and not k.startswith("session")]
    for k in timing_keys:
        v = temporal[k]
        if v >= 0:
            print(f"    {k:<42} {v} ms")
    print(f"    {'burst_peak_count':<42} {temporal['burst_peak_count']}")
    print(f"    {'session_duration_ms':<42} {temporal['session_duration_ms']} ms")
    active_temporal_flags = [k for k in ["early_network_flag","early_anti_analysis_flag",
                                          "crypto_before_network","rapid_burst_flag"]
                             if temporal.get(k) == 1]
    if active_temporal_flags:
        print("  Aktif Temporal Flagler:")
        for k in active_temporal_flags:
            print(f"    🕐 {k}")

    if password_attempts:
        print(f"{'─'*58}")
        print(f"  Şifre denemeleri: {password_attempts}")

    print(f"{'='*58}\n")

# ─── Mesaj Handler ───────────────────────────────────────────────────────────

def on_message(message, data):
    global latest_counters, latest_timings, latest_burst_peak, latest_session_duration_ms, latest_seq_log

    try:
        if message['type'] == 'send':
            payload = message['payload']
            msg_type = payload.get('type', '')

            if msg_type == 'COUNTERS':
                raw = payload['payload']
                latest_timings             = raw.pop('_timings', {})
                latest_burst_peak          = raw.pop('_burst_peak', 0)
                latest_session_duration_ms = raw.pop('_session_duration_ms', 0)
                latest_seq_log             = raw.pop('_seq_log', [])
                latest_counters            = raw

                total   = sum(v for v in latest_counters.values() if isinstance(v, (int, float)))
                nonzero = sum(1 for v in latest_counters.values() if isinstance(v, (int, float)) and v > 0)
                print(f"[~] Snapshot — {total} event | {nonzero} aktif feature | "
                      f"burst: {latest_burst_peak} | seq: {len(latest_seq_log)} event")

            elif msg_type == 'PASSWORD_ATTEMPT':
                entry = payload['payload']
                password_attempts.append(entry)
                print(f"[!] Şifre: \"{entry['input']}\" -> {entry['result']}")

        elif message['type'] == 'log':
            print(f"    {message['payload']}")

        elif message['type'] == 'error':
            print(f"[-] JS HATA: {message['description']}")

    except Exception as e:
        print(f"[-] on_message hata: {e}")

# ─── Ana Akış ────────────────────────────────────────────────────────────────

def main():
    global session_ref, script_ref

    init_csv()

    print(f"[*] Agent derleniyor: {AGENT_TS}")
    compiler = frida.Compiler()
    project_root = os.path.dirname(os.path.abspath(AGENT_TS))
    bundle = compiler.build("agent.ts", project_root=project_root)
    print("[+] Derleme başarılı!")

    device = frida.get_usb_device(timeout=10)
    print(f"[*] Cihaz: {device.name}")

    print(f"[*] Spawn: {PACKAGE_NAME}")
    pid = device.spawn([PACKAGE_NAME])
    print(f"[*] PID: {pid}")

    session_ref = device.attach(pid)
    script_ref  = session_ref.create_script(bundle)
    script_ref.on('message', on_message)
    script_ref.load()
    device.resume(pid)

    print(f"[!] Analiz başladı. Süre: "
          f"{'sonsuz' if ANALYSIS_TIME == 0 else str(ANALYSIS_TIME) + 's'}")
    print("    Çıkmak için CTRL+C\n")

    start = time.time()
    try:
        while True:
            time.sleep(1)
            elapsed = time.time() - start
            if ANALYSIS_TIME > 0 and elapsed >= ANALYSIS_TIME:
                print(f"\n[*] {ANALYSIS_TIME}s doldu. Final snapshot isteniyor...")
                script_ref.post("flush")
                time.sleep(2)
                break

    except KeyboardInterrupt:
        print("\n[*] Kullanıcı durdurdu. Final snapshot isteniyor...")
        if script_ref:
            script_ref.post("flush")
            time.sleep(2)

    finally:
        if latest_counters:
            write_row(latest_counters)
        else:
            print("[-] Sayaç verisi alınamadı, boş satır yazılmıyor.")
        try:
            session_ref.detach()
        except Exception:
            pass
        print(f"\n[*] Bitti. CSV: {os.path.abspath(CSV_FILE)}")

if __name__ == "__main__":
    main()