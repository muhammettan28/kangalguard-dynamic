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
ANALYSIS_TIME = 60                # Kaç saniye analiz yapılsın (0 = sonsuz)
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

# ─── Tüm CSV sütunları: 3 meta + 50 ham + 20 türetilmiş = 73 sütun ──────────

ALL_COLUMNS = (
    ["package_name", "label", "timestamp"]
    + RAW_FEATURE_COLUMNS
    + DERIVED_FEATURE_COLUMNS
)

# ─── Global State ─────────────────────────────────────────────────────────────

latest_counters: dict = {}
password_attempts: list = []
session_ref = None
script_ref  = None

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
        print(f"[*] Toplam sütun: {len(ALL_COLUMNS)}  (3 meta + 50 ham + 20 türetilmiş)")
    else:
        print(f"[*] Mevcut CSV'ye ekleniyor: {CSV_FILE}")

def write_row(counters: dict):
    derived = compute_derived_features(counters)

    row = [PACKAGE_NAME, LABEL, datetime.now().strftime("%Y-%m-%d %H:%M:%S")]

    for col in RAW_FEATURE_COLUMNS:
        row.append(counters.get(col, 0))

    for col in DERIVED_FEATURE_COLUMNS:
        row.append(derived.get(col, 0))

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

    if password_attempts:
        print(f"{'─'*58}")
        print(f"  Şifre denemeleri: {password_attempts}")

    print(f"{'='*58}\n")

# ─── Mesaj Handler ───────────────────────────────────────────────────────────

def on_message(message, data):
    global latest_counters

    if message['type'] == 'send':
        payload = message['payload']
        msg_type = payload.get('type', '')

        if msg_type == 'COUNTERS':
            latest_counters = payload['payload']
            total   = sum(latest_counters.values())
            nonzero = sum(1 for v in latest_counters.values() if v > 0)
            print(f"[~] Snapshot — {total} event | {nonzero} aktif feature")

        elif msg_type == 'PASSWORD_ATTEMPT':
            entry = payload['payload']
            password_attempts.append(entry)
            print(f"[!] Şifre: \"{entry['input']}\" -> {entry['result']}")

    elif message['type'] == 'log':
        print(f"    {message['payload']}")

    elif message['type'] == 'error':
        print(f"[-] JS HATA: {message['description']}")

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