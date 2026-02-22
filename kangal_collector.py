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

# ─── Feature Sütunları (agent.ts ile birebir eşleşmeli) ──────────────────────

FEATURE_COLUMNS = [
    "package_name", "label", "timestamp",
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

# ─── Global State ─────────────────────────────────────────────────────────────

latest_counters: dict = {}
password_attempts: list = []
session_ref = None
script_ref  = None

# ─── CSV ──────────────────────────────────────────────────────────────────────

def init_csv():
    write_header = not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0
    if write_header:
        with open(CSV_FILE, 'w', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow(FEATURE_COLUMNS)
        print(f"[*] CSV oluşturuldu: {CSV_FILE}")
    else:
        print(f"[*] Mevcut CSV'ye ekleniyor: {CSV_FILE}")

def write_row(counters: dict):
    row = [
        PACKAGE_NAME,
        LABEL,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ]
    # Meta sütunlardan sonra feature sütunları
    for col in FEATURE_COLUMNS[3:]:
        row.append(counters.get(col, 0))

    with open(CSV_FILE, 'a', newline='', encoding='utf-8') as f:
        csv.writer(f).writerow(row)

    print(f"\n[+] CSV SATIRI YAZILDI — {datetime.now().strftime('%H:%M:%S')}")
    print(f"    Package : {PACKAGE_NAME}")
    print(f"    Label   : {LABEL}")

    # Sıfırdan farklı feature'ları göster
    nonzero = {k: v for k, v in counters.items() if v > 0}
    if nonzero:
        print("    Aktif feature'lar:")
        for k, v in nonzero.items():
            print(f"      {k}: {v}")
    else:
        print("    (Hiç feature tetiklenmedi)")

    if password_attempts:
        print(f"    Şifre denemeleri: {password_attempts}")

# ─── Mesaj Handler ───────────────────────────────────────────────────────────

def on_message(message, data):
    global latest_counters

    if message['type'] == 'send':
        payload = message['payload']
        msg_type = payload.get('type', '')

        if msg_type == 'COUNTERS':
            latest_counters = payload['payload']
            print(f"[~] Snapshot alındı — "
                  f"{sum(latest_counters.values())} toplam event")

        elif msg_type == 'PASSWORD_ATTEMPT':
            entry = payload['payload']
            password_attempts.append(entry)
            print(f"[!] Şifre denemesi: \"{entry['input']}\" -> {entry['result']}")

    elif message['type'] == 'log':
        print(f"    {message['payload']}")

    elif message['type'] == 'error':
        print(f"[-] JS HATA: {message['description']}")

# ─── Ana Akış ────────────────────────────────────────────────────────────────

def main():
    global session_ref, script_ref

    init_csv()

    # frida.Compiler ile agent.ts'i derle
    print(f"[*] Agent derleniyor: {AGENT_TS}")
    compiler = frida.Compiler()
    project_root = os.path.dirname(os.path.abspath(AGENT_TS))
    bundle = compiler.build("agent.ts", project_root=project_root)
    print("[+] Derleme başarılı!")

    device = frida.get_usb_device(timeout=10)
    print(f"[*] Cihaz: {device.name}")

    # spawn → attach → load → resume
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

            # Süre doldu mu?
            if ANALYSIS_TIME > 0 and elapsed >= ANALYSIS_TIME:
                print(f"\n[*] {ANALYSIS_TIME}s doldu. Final snapshot isteniyor...")
                script_ref.post("flush")
                time.sleep(2)  # Agent'ın yanıt vermesi için bekle
                break

    except KeyboardInterrupt:
        print("\n[*] Kullanıcı durdurdu. Final snapshot isteniyor...")
        if script_ref:
            script_ref.post("flush")
            time.sleep(2)

    finally:
        # Son sayaçları yaz
        if latest_counters:
            write_row(latest_counters)
        else:
            print("[-] Sayaç verisi alınamadı, boş satır yazılmıyor.")

        # Temizlik
        try:
            session_ref.detach()
        except Exception:
            pass

        print(f"\n[*] Bitti. CSV: {os.path.abspath(CSV_FILE)}")

if __name__ == "__main__":
    main()