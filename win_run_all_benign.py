#!/usr/bin/env python3
"""
win_run_all_benign.py
Windows karşılığı: run_all_benign.sh
"""

import subprocess
import sys
import time
import signal
from datetime import datetime

# ─── Konfigürasyon ────────────────────────────────────────────────────────────

GMTOOL = r"C:\Program Files\Genymobile\Genymotion\gmtool.exe"

LABEL  = "benign"
DIR    = r".\data\benign"
CSV    = "kangal_benign.csv"

RESTART_INTERVAL = 3600   # saniye (1 saat)

EMULATORS = {
    "127.0.0.1:6555": "40cbb896-7c86-43a7-ac91-74b870645f8c",
    "127.0.0.1:6562": "47866601-0852-4af6-8050-509dd72c244e",
    "127.0.0.1:6569": "acfa9d61-aed5-4d93-b871-cfab128bf9c3",
}

# ─── Yardımcılar ──────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def adb(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["adb"] + list(args),
                          capture_output=True, text=True)


def gmtool(*args) -> subprocess.CompletedProcess:
    return subprocess.run([GMTOOL] + list(args),
                          capture_output=True, text=True)


def device_state(ip: str) -> str:
    r = adb("-s", ip, "get-state")
    return r.stdout.strip()

# ─── Emülatör Yönetimi ────────────────────────────────────────────────────────

def stop_emulators() -> None:
    log("Emulatorler durduruluyor...")
    for ip, uuid in EMULATORS.items():
        adb("disconnect", ip)
        gmtool("admin", "stop", uuid)
    time.sleep(8)


def start_emulators() -> None:
    log("Emulatorler baslatiliyor...")
    for uuid in EMULATORS.values():
        gmtool("admin", "start", uuid)

    log("Ayaga kalkmalari icin 25s bekleniyor...")
    time.sleep(25)

    for ip in EMULATORS:
        adb("connect", ip)

    deadline = time.time() + 90
    while time.time() < deadline:
        if all(device_state(ip) == "device" for ip in EMULATORS):
            log("Tum emulatorler hazir.")
            return
        time.sleep(5)

    log("UYARI: Bazi emulatorler 90s icinde hazir olmadi. Devam ediliyor...")


def ensure_emulators_running() -> None:
    if all(device_state(ip) == "device" for ip in EMULATORS):
        log("Tum emulatorler zaten hazir.")
    else:
        log("Bazi emulatorler hazir degil, baslatiliyor...")
        stop_emulators()
        start_emulators()

# ─── Proses Yönetimi ──────────────────────────────────────────────────────────

_procs: list[subprocess.Popen] = []


def start_processes() -> None:
    global _procs
    _procs = []
    import os
    os.makedirs("logs", exist_ok=True)

    for ip in EMULATORS:
        log_path = f"logs/run_{ip.replace(':', '_')}.log"
        log_fh   = open(log_path, "a", encoding="utf-8")
        proc = subprocess.Popen(
            [sys.executable, "batch_analyzer.py",
             "--device", ip, "--dir", DIR, "--label", LABEL, "--csv", CSV],
            stdout=log_fh, stderr=log_fh,
        )
        _procs.append(proc)
        log(f"  {ip} -> PID {proc.pid} -> {log_path}")


def kill_processes() -> None:
    if not _procs:
        return
    log("Analiz processleri durduruluyor...")
    for p in _procs:
        try:
            p.terminate()
        except Exception:
            pass
    for p in _procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
    _procs.clear()


def all_done() -> bool:
    return all(p.poll() is not None for p in _procs)

# ─── Temiz Çıkış ─────────────────────────────────────────────────────────────

def _shutdown(signum=None, frame=None):
    log("Kesme sinyali alindi — temizleniyor...")
    kill_processes()
    sys.exit(0)

signal.signal(signal.SIGINT,  _shutdown)
signal.signal(signal.SIGTERM, _shutdown)

# ─── Ana Akış ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 44)
    print("KangalGuard win_run_all_benign.py")
    print(f"label={LABEL}  dir={DIR}  csv={CSV}")
    print(f"Restart interval: {RESTART_INTERVAL}s (1 saat)")
    print("=" * 44)

    ensure_emulators_running()

    cycle = 1
    while True:
        log(f"=== Cycle {cycle} basliyor ===")
        start_processes()
        print()
        log(f"Loglar: logs/run_127.0.0.1_65{{55,62,69}}.log")
        print()

        elapsed = 0
        while elapsed < RESTART_INTERVAL:
            time.sleep(15)
            elapsed += 15

            if all_done():
                log("Tum APK'lar islendi. Cikiliyor.")
                sys.exit(0)

        log("1 saat doldu — RAM temizleme icin restart yapiliyor...")
        kill_processes()
        stop_emulators()
        start_emulators()
        log("Emulatorler hazir. Kaldigi yerden devam ediliyor...")
        print()
        cycle += 1
