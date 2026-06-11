#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KangalGuard Batch Analyzer
==========================
Tek APK analizi için temiz bir fonksiyon arayüzü.
Döngü her zaman dışarıda — bu fonksiyon sadece tek APK'yı bilir.

Kullanım:
    python batch_analyzer.py --dir ./benign --label benign
    python batch_analyzer.py --dir ./malware --label malware
    python batch_analyzer.py --dir ./benign --label benign --limit 10 --timeout 45
"""

import os
import sys
import time
import subprocess
import argparse
import csv
import json
import traceback
import threading
import signal
from pathlib import Path
from datetime import datetime

import gc
import frida
from filelock import FileLock

# ─── KangalGuard engine — tüm feature hesaplama burada ──────────────────────
from kangal_collector import (
    init_csv,
    write_row,
    on_message,
    ALL_COLUMNS,
    AGENT_TS,
)
import kangal_collector as engine

# ─── Sabitler ────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT    = 120    # saniye (45→120: deferred C2, dropper behavior için)
DEFAULT_CSV        = "kangal_malware.csv"
ADB_INSTALL_WAIT   = 15      # kurulum sonrası bekleme (saniye)
ADB_UNINSTALL_WAIT = 5      # kaldırma sonrası bekleme (saniye)
FRIDA_ATTACH_WAIT  = 10      # attach sonrası bekleme (saniye)

FRIDA_SERVER_PATH  = "/data/local/tmp/frida-server"  # emülatörde frida-server yolu
FRIDA_SERVER_RESTART_WAIT = 6   # restart sonrası bekleme (saniye)

SNAPSHOT_NAME      = "kangal_clean"   # adb emu avd snapshot save kangal_clean ile oluşturulur
SNAPSHOT_TIMEOUT   = 90               # snapshot load için max bekleme (saniye) — 30s çok kısa
SNAPSHOT_SETTLE    = 3                # snapshot yüklenince stabilize bekleme (saniye)
SNAPSHOT_ENABLED   = os.environ.get("KANGAL_USE_SNAPSHOT", "0") == "1"

FAILED_LOG_FILE    = os.path.join("logs", "failed_apks.csv")  # skip/error APK logu

DEVICE_SERIAL      = ""   # adb device serial — --device argümanıyla set edilir

LOCK_FILE          = os.path.join("logs", "kangal.lock")       # cross-process advisory lock
IN_PROGRESS_FILE   = os.path.join("logs", "in_progress.json")  # hangi APK'lar işleniyor
CLAIM_STALE_AFTER  = 30 * 60  # SIGTERM/crash sonrası kalan claim'leri 30 dk sonra temizle

_csv_lock = FileLock(LOCK_FILE, timeout=120)   # 2 dk bekle, sonra hata

# TransportError/ProcessNotRespondingError: bunlar Frida server çöktüğünde
# ya da app Frida'yı öldürdüğünde çıkar. İsimle yakalıyoruz çünkü
# frida modülünde doğrudan erişilebilir sınıf olmayabilir.
_TRANSPORT_ERROR_NAMES = {
    "TransportError",
    "ProcessNotRespondingError",
    "InvalidArgumentError",
    "ServerNotRunningError",
}


def _request_shutdown(signum, _frame) -> None:
    """SIGTERM'i Python exception'a çevir; aktif APK claim'i finally ile temizlensin."""
    raise SystemExit(128 + signum)

# ─── Compiled agent bundle (bir kez derlenir, tüm APK'larda kullanılır) ─────

_compiled_bundle: str | None = None

def get_compiled_bundle() -> str:
    """Agent'ı bir kez derle, sonraki çağrılarda cache'den döndür."""
    global _compiled_bundle
    if _compiled_bundle is None:
        print("[*] Agent.ts derleniyor...")
        compiler = frida.Compiler()
        project_root = os.path.dirname(os.path.abspath(AGENT_TS))
        _compiled_bundle = compiler.build("agent.ts", project_root=project_root)
        print("[+] Derleme tamam — tüm APK'larda bu bundle kullanılacak.")
    return _compiled_bundle

# ─── APK Yardımcı Fonksiyonlar ───────────────────────────────────────────────

def get_package_name(apk_path: str) -> str | None:
    """
    APK dosyasından package name'i okur.
    Önce aapt dener, başarısız olursa androguard dener.
    """
    # Yöntem 1: aapt (Android SDK)
    try:
        result = subprocess.run(
            ["aapt", "dump", "badging", apk_path],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60
        )
        for line in result.stdout.splitlines():
            if line.startswith("package:"):
                # "package: name='com.example.app' ..." → com.example.app
                for part in line.split():
                    if part.startswith("name="):
                        return part.split("'")[1]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Yöntem 2: androguard (aapt yoksa fallback)
    try:
        from androguard.misc import AnalyzeAPK
        a, _, _ = AnalyzeAPK(apk_path)
        return a.get_package()
    except Exception:
        pass

    return None


def wait_for_package_manager(timeout_s: int = 30) -> bool:
    """
    PackageManagerService hazır olana kadar bekler.
    Snapshot restore sonrası system_server boot completion'ı için.
    True: hazır, False: timeout.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = adb_s(
                ["shell", "cmd", "package", "list", "packages"],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5
            )
            if r.returncode == 0 and "package:" in r.stdout:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def adb_install(apk_path: str, package_name: str | None = None) -> bool:
    """APK'yı cihaza kur. Başarılıysa True döner."""
    try:
        result = adb_s(
            ["install", "-r", "-t", apk_path],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60
        )
        if "Success" in result.stdout or "success" in result.stdout.lower():
            return True
        err = result.stdout.strip() + result.stderr.strip()
        # PackageManager servisi henüz hazır değil — 20s daha bekle ve bir kez retry yap
        if "Can't find service: package" in err:
            print(f"  [!] PackageManager hazır değil — 20s bekleniyor...")
            if wait_for_package_manager(20):
                result2 = adb_s(
                    ["install", "-r", "-t", apk_path],
                    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60
                )
                if "Success" in result2.stdout or "success" in result2.stdout.lower():
                    return True
                err = result2.stdout.strip() + result2.stderr.strip()
        if package_name and _install_failure_may_be_stale_package(err):
            print(f"  [!] Eski kurulum kalıntısı olabilir — {package_name} temizlenip retry yapılacak")
            adb_uninstall(package_name, abort_on_failure=False)
            result3 = adb_s(
                ["install", "-r", "-t", apk_path],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60
            )
            if "Success" in result3.stdout or "success" in result3.stdout.lower():
                return True
            err = result3.stdout.strip() + result3.stderr.strip()
        if _looks_like_dead_device(err):
            print(f"  [!] adb install cihaz hatası: {err}")
            _abort_dead_device()
        print(f"  [-] adb install başarısız: {err}")
        return False
    except Exception as e:
        if _looks_like_dead_device(str(e)):
            print(f"  [!] adb install cihaz hatası: {e}")
            _abort_dead_device()
        print(f"  [-] adb install hata: {e}")
        return False


def _install_failure_may_be_stale_package(text: str) -> bool:
    text = text.lower()
    return (
        "install_failed_update_incompatible" in text
        or "install_failed_already_exists" in text
        or "install_failed_version_downgrade" in text
        or "existing package" in text
        or "signatures do not match" in text
        or "has no signatures that match" in text
    )


def _package_visible_to_user(package_name: str) -> bool:
    try:
        result = adb_s(
            ["shell", "cmd", "package", "list", "packages", "--user", "0", package_name],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10
        )
        return f"package:{package_name}" in result.stdout.splitlines()
    except Exception:
        return False


def adb_uninstall(package_name: str, abort_on_failure: bool = True) -> bool:
    """APK'yı cihazdan kaldır. Device admin yetkisi varsa önce revoke eder."""
    # Bazı malwareler device admin alır → normal uninstall'ı reddeder.
    # Snapshot açıksa restore de temizler; Genymotion modunda uninstall kritik.
    adb_force_stop(package_name)

    try:
        adb_s(
            ["shell", "dpm", "remove-active-admin", f"{package_name}/.AdminReceiver"],
            capture_output=True, timeout=10
        )
    except Exception:
        pass

    commands = [
        ["uninstall", package_name],
        ["shell", "pm", "uninstall", "--user", "0", package_name],
        ["shell", "cmd", "package", "uninstall", "--user", "0", package_name],
    ]

    errors = []
    for cmd in commands:
        try:
            result = adb_s(
                cmd,
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60
            )
            out = (result.stdout.strip() + result.stderr.strip()).strip()
            if "Success" in out or (result.returncode == 0 and not _package_visible_to_user(package_name)):
                return True
            if "not installed" in out or "Unknown package" in out:
                return True
            if _looks_like_dead_device(out):
                print(f"  [!] adb uninstall cihaz hatası: {out}")
                _abort_dead_device()
            errors.append(" ".join(cmd) + f" -> {out or 'no output'}")
        except Exception as e:
            if _looks_like_dead_device(str(e)):
                print(f"  [!] adb uninstall cihaz hatası: {e}")
                _abort_dead_device()
            errors.append(" ".join(cmd) + f" -> {e}")

    try:
        adb_s(["shell", "pm", "clear", package_name], capture_output=True, timeout=20)
    except Exception:
        pass

    if not _package_visible_to_user(package_name):
        return True

    joined = " | ".join(errors)
    if SNAPSHOT_ENABLED:
        print(f"  [!] Uninstall başarısız ({joined}) — snapshot restore temizleyecek")
    else:
        print(f"  [!] Uninstall başarısız ({joined}) — Genymotion modu, emülatör restart gerekecek")
        if abort_on_failure:
            _abort_dead_device()
    return False


def adb_force_stop(package_name: str) -> None:
    """Uygulamayı zorla durdur (analiz sonrası temizlik)."""
    try:
        adb_s(["shell", "am", "force-stop", package_name], capture_output=True, timeout=60)
    except Exception:
        pass


def dismiss_dialogs() -> None:
    """
    Ekrandaki ANR / 'has stopped' sistem diyaloglarını kapatır.
    BACK tuşu çoğu diyaloğu kapatır; arkasından ENTER olası OK/Close düğmesini tetikler.
    Her APK başında ve analiz döngüsü içinde periyodik olarak çağrılır.
    """
    try:
        adb_s(["shell", "input", "keyevent", "4"], capture_output=True, timeout=5)   # KEYCODE_BACK
        time.sleep(0.3)
        adb_s(["shell", "input", "keyevent", "66"], capture_output=True, timeout=5)  # KEYCODE_ENTER → OK/Close
    except Exception:
        pass


def _call_with_timeout(fn, timeout_s: int) -> None:
    """fn()'i daemon thread içinde çalıştır; timeout_s sonra thread'i terk et.
    script.unload() / session.detach() gibi blocking Frida çağrıları için kullanılır."""
    t = threading.Thread(target=fn, daemon=True)
    t.start()
    t.join(timeout_s)


def _rpc_safe(script, timeout_s: int = 8) -> dict:
    """
    script.exports_sync.get_counters() çağrısını daemon thread ile timeout'a bağlar.
    ANR veya process freeze durumunda exports_sync sonsuz bloklanır; bu wrapper
    timeout_s saniye içinde cevap gelmezse RuntimeError("rpc_timeout") fırlatır.
    """
    result = [None]
    exc    = [None]

    def _call():
        try:
            result[0] = dict(script.exports_sync.get_counters())
        except Exception as e:
            exc[0] = e

    t = threading.Thread(target=_call, daemon=True)
    t.start()
    t.join(timeout_s)

    if t.is_alive():
        raise RuntimeError("rpc_timeout")
    if exc[0] is not None:
        raise exc[0]
    return result[0]


def get_launch_activity(apk_path: str) -> str | None:
    """
    APK'nın launch activity'sini aapt ile okur.
    aapt yoksa ya da activity bulunamazsa None döner.
    """
    try:
        result = subprocess.run(
            ["aapt", "dump", "badging", apk_path],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60
        )
        for line in result.stdout.splitlines():
            if line.startswith("launchable-activity:"):
                for part in line.split():
                    if part.startswith("name="):
                        return part.split("'")[1]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def adb_start_app(package: str, activity: str | None = None) -> bool:
    """
    Uygulamayı başlatır.

    Tercih sırası:
    1. am start -n package/activity  — activity biliniyorsa, kesin hedef
    2. monkey -p package LAUNCHER 1  — activity bilinmiyorsa fallback

    monkey -p ile hedef pakette LAUNCHER activity yoksa tüm uygulamalara
    fallback yapıp rastgele bir uygulamayı (örn. Amaze) başlatır.
    am start bu durumda temiz şekilde başarısız olur.
    """
    if activity:
        try:
            result = adb_s(
                ["shell", "am", "start", "-n", f"{package}/{activity}"],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60
            )
            out = result.stdout + result.stderr
            if "Starting:" in out or "Warning:" in out:
                return True
        except Exception:
            pass

    # Fallback: monkey
    try:
        result = adb_s(
            ["shell", "monkey", "-p", package,
             "-c", "android.intent.category.LAUNCHER", "1"],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60
        )
        return "Events injected: 1" in result.stdout
    except Exception:
        return False


def restart_frida_server() -> bool:
    """
    Frida server'ı adb üzerinden yeniden başlatır.
    TransportError / ProcessNotRespondingError sonrası çağrılır.
    Emülatörde su erişimi gerektirir.
    """
    print(f"  [*] Frida server yeniden başlatılıyor ({FRIDA_SERVER_PATH})...")
    try:
        adb_s(["shell", "su", "0", "pkill", "-f", "frida-server"], capture_output=True, timeout=10)
        time.sleep(2)
        adb_s_popen(["shell", "su", "0", FRIDA_SERVER_PATH],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(FRIDA_SERVER_RESTART_WAIT)
        print(f"  [+] Frida server yeniden başlatıldı ({FRIDA_SERVER_RESTART_WAIT}s beklendi)")
        return True
    except Exception as e:
        print(f"  [!] Frida server restart başarısız: {e}")
        return False


def restore_clean_snapshot() -> bool:
    """
    Emülatörü temiz AVD snapshot'ına döndürür.
    Her APK analizinden önce çağrılır — garantili temiz sistem + temiz frida-server.

    Bir kez kurulum:
        1. Emülatörü başlat, frida-server'ı çalıştır
        2. adb emu avd snapshot save kangal_clean
        3. Artık bu fonksiyon her APK öncesi otomatik çağrılır.

    Returns:
        True  — snapshot yüklendi, frida-server temiz
        False — snapshot bulunamadı/hata (eski yöntemle devam edilir)

    Raises:
        SystemExit — device offline kalıyorsa batch'i durdur, emülatörü manuel kontrol et
    """
    if not SNAPSHOT_ENABLED:
        print("  [*] Snapshot kapalı (Genymotion modu) — Frida runtime temizleniyor...")
        restart_frida_server()
        if not wait_for_package_manager(30):
            print(f"  [!] PackageManager 30s içinde hazır olmadı — emülatör durumu şüpheli")
        print(f"  [+] Runtime state hazır")
        return False

    try:
        print(f"  [*] Snapshot yükleniyor ({SNAPSHOT_NAME})...")
        r = adb_s(
            ["emu", "avd", "snapshot", "load", SNAPSHOT_NAME],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=SNAPSHOT_TIMEOUT
        )
        snapshot_ok = True
        if r.returncode != 0:
            err = (r.stdout.strip() + r.stderr.strip()).strip()
            state = _get_device_state()
            if state != "online":
                print(f"  [!] Snapshot load başarısız ({err or 'adb error'}) — emülatör state: {state}")
                _abort_dead_device()
            print(f"  [!] Snapshot load başarısız ({err or 'adb error'}) — runtime temizlenerek devam")
            snapshot_ok = False

        # AVD emülatörü başarıda "OK" döner, başarısızlıkta "KO"
        elif "KO" in r.stdout:
            print(f"  [!] Snapshot bulunamadı ({r.stdout.strip()}) — runtime temizlenerek devam")
            snapshot_ok = False

        # Emülatörün yeniden bağlanmasını bekle
        adb_s(["wait-for-device"], capture_output=True, timeout=SNAPSHOT_TIMEOUT)
        time.sleep(SNAPSHOT_SETTLE)

        # Frida-server'ı temiz başlat (snapshot'ta ne durumda olursa olsun)
        restart_frida_server()

        # PackageManagerService hazır olana kadar bekle.
        # adb wait-for-device sadece ADB daemon'ını kontrol eder; system_server
        # (PackageManagerService) daha geç başlayabilir — özellikle ağır malware
        # APK'larından sonra restore daha uzun sürebilir.
        if not wait_for_package_manager(30):
            print(f"  [!] PackageManager 30s içinde hazır olmadı — emülatör durumu şüpheli")

        if snapshot_ok:
            print(f"  [+] Temiz state hazır")
        else:
            print(f"  [+] Runtime state hazır (snapshot uygulanmadı)")
        return snapshot_ok

    except subprocess.TimeoutExpired:
        # Snapshot veya wait-for-device timeout → emülatör offline/crash olmuş olabilir
        print(f"  [!] Snapshot timeout — emülatör durumu kontrol ediliyor...")
        state = _get_device_state()
        if state != "online":
            print(f"  [!] Snapshot timeout (emülatör state: {state})")
            _abort_dead_device()
        print(f"  [!] Snapshot timeout (emülatör state: {state}) — eski yöntemle devam")
        return False

    except Exception as e:
        print(f"  [!] Snapshot yüklenemedi: {e} — eski yöntemle devam")
        return False


def _get_device_state() -> str:
    """'online', 'offline', 'unknown' döner."""
    try:
        r = adb_s(
            ["get-state"],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=5
        )
        out = r.stdout.strip().lower()
        err = r.stderr.strip().lower()
        if "device" in out:
            return "online"
        if "offline" in out or "offline" in err:
            return "offline"
        if r.returncode != 0 or "not found" in err or "no devices" in err:
            return "offline"
        return "unknown"
    except Exception:
        return "offline"


def _abort_dead_device() -> None:
    """Worker'ı durdurur; dış run_all script'i emülatörü yeniden başlatır."""
    print(f"\n{'!'*60}")
    print(f"  EMÜLATÖR ERİŞİLEMEZ — worker durduruluyor!")
    print(f"  Tekli çalıştırıyorsan adb connect / gmtool durumunu kontrol et.")
    print(f"  run_all_malware.sh ile çalışıyorsa dış script toparlamayı deneyecek.")
    print(f"{'!'*60}\n")
    sys.exit(2)


def _looks_like_dead_device(text: str) -> bool:
    text = text.lower()
    return (
        "device" in text and "not found" in text
    ) or "device offline" in text or "no devices" in text


def adb_s(cmd_args: list, **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run wrapper: tüm adb çağrılarına -s DEVICE_SERIAL ekler."""
    return subprocess.run(["adb", "-s", DEVICE_SERIAL] + cmd_args, **kwargs)


def adb_s_popen(cmd_args: list, **kwargs) -> subprocess.Popen:
    """subprocess.Popen wrapper: tüm adb çağrılarına -s DEVICE_SERIAL ekler."""
    return subprocess.Popen(["adb", "-s", DEVICE_SERIAL] + cmd_args, **kwargs)


def check_and_ensure_frida_server() -> "frida.core.Device":
    """
    Attach öncesi frida-server sağlığını test eder.
    enumerate_processes() ile hafif bir probe gönderir.
    Başarısız olursa server'ı yeniden başlatır, yeni device handle döner.

    Bu sayede önceki APK'dan kalan stale session / bozuk state
    attach denemesinden ÖNCE temizlenir — InvalidArgumentError azalır.
    """
    try:
        device = frida.get_device(DEVICE_SERIAL, timeout=10)
        device.enumerate_processes()   # hafif sağlık probu
        return device
    except Exception:
        print(f"  [!] Frida server sağlık kontrolü başarısız — yeniden başlatılıyor...")
        restart_frida_server()
        return frida.get_device(DEVICE_SERIAL, timeout=30)


def get_pid_by_package(package: str, retries: int = 8) -> int | None:
    """
    Çalışan uygulamanın PID'ini bul.
    frida enumerate_processes() güvenilmez olduğu için
    adb shell pidof ile alıyoruz — daha kesin sonuç verir.
    """
    for attempt in range(retries):
        try:
            result = adb_s(
                ["shell", "pidof", package],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60
            )
            pid_str = result.stdout.strip().split()[0]
            if pid_str.isdigit():
                return int(pid_str)
        except Exception:
            pass
        time.sleep(1)
    return None

# ─── Simülasyon Yardımcıları ─────────────────────────────────────────────────

def grant_sensitive_permissions(package: str) -> None:
    """
    APK kurulumundan hemen sonra çağrılır.
    BCAST_SMS_INTERCEPT, SURV_CAMERA, SURV_MIC_RECORD gibi tag'lerin
    tetiklenebilmesi için izin gerektiren APK'lara izinleri önceden ver.
    """
    perms = [
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_PHONE_STATE",
    ]
    for p in perms:
        try:
            adb_s(["shell", "pm", "grant", package, p],
                  capture_output=True, timeout=5)
        except Exception:
            pass

    # SCREEN_CAPTURE için appops izni (MediaProjection permission dialog'unu atlar)
    try:
        adb_s(["shell", "appops", "set", package, "PROJECT_MEDIA", "allow"],
              capture_output=True, timeout=5)
    except Exception:
        pass

    # NOTIF_LISTEN için (OTP bildirimlerini okuma)
    try:
        adb_s(["shell", "appops", "set", package, "RECEIVE_NOTIFICATIONS", "allow"],
              capture_output=True, timeout=5)
    except Exception:
        pass


def simulate_events(package: str) -> None:
    """
    Analiz penceresi içinde 15. ve 45. saniyelerde çağrılır.
    BCAST_SMS_INTERCEPT ve BCAST_SCREEN_WAKE gibi simülasyon gerektiren
    tag'lerin tetiklenmesi için broadcast gönderir.
    """
    # SMS broadcast — BCAST_SMS_INTERCEPT için
    try:
        adb_s([
            "shell", "am", "broadcast",
            "-a", "android.provider.Telephony.SMS_RECEIVED",
            "--es", "pdus", "0000"
        ], capture_output=True, timeout=10)
    except Exception:
        pass

    # Screen toggle — BCAST_SCREEN_WAKE için (ekran kapat → 2s bekle → aç)
    try:
        adb_s(["shell", "input", "keyevent", "KEYCODE_POWER"],
              capture_output=True, timeout=5)
        time.sleep(2)
        adb_s(["shell", "input", "keyevent", "KEYCODE_POWER"],
              capture_output=True, timeout=5)
    except Exception:
        pass

    # Test bildirimi gönder — NOTIF_LISTEN için
    try:
        adb_s([
            "shell", "cmd", "notification", "post",
            "-S", "bigtext", "--title", "Test", "KangalTest", "test_tag", "Test msg"
        ], capture_output=True, timeout=5)
    except Exception:
        pass


# ─── Tek APK Analizi — Temiz Arayüz ─────────────────────────────────────────

def analyze_apk(apk_path: str, label: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Tek bir APK'yı tam döngüyle analiz eder.

    Akış:
        get_package_name → adb install → frida spawn+hook →
        timeout/flush → write_csv → adb uninstall

    Returns:
        {"status": "ok"|"skip"|"error", "package": str, "reason": str}
    """
    apk_name = Path(apk_path).name
    print(f"\n{'━'*60}")
    print(f"[APK] {apk_name}")
    print(f"{'━'*60}")

    # ── 1. Package name + launch activity ────────────────────────────────────
    package = get_package_name(apk_path)
    if not package:
        print(f"  [-] Package name okunamadı → SKIP")
        return {"status": "skip", "package": None, "reason": "no_package_name"}

    launch_activity = get_launch_activity(apk_path)

    print(f"  [+] Package  : {package}")
    print(f"  [+] Activity : {launch_activity or '(yok — monkey fallback)'}")
    print(f"  [+] Label    : {label}")

    # ── 2. Install ────────────────────────────────────────────────────────────
    # Önceki APK'dan kalma diyalogları temizle (snapshot restore başarısız olursa birikir)
    dismiss_dialogs()
    if _package_visible_to_user(package):
        print(f"  [*] Önceki kurulum kalıntısı temizleniyor: {package}")
        if not adb_uninstall(package, abort_on_failure=not SNAPSHOT_ENABLED):
            return {"status": "skip", "package": package, "reason": "infra_uninstall_failed"}

    print(f"  [*] Kuruluyor...")
    if not adb_install(apk_path, package):
        return {"status": "skip", "package": package, "reason": "install_failed"}

    time.sleep(ADB_INSTALL_WAIT)
    print(f"  [+] Kurulum OK")

    # İzinleri önceden ver — CAMERA, SMS, MIC, NOTIF_LISTEN, SCREEN_CAPTURE için
    grant_sensitive_permissions(package)

    # ── 3. Frida analizi ──────────────────────────────────────────────────────
    session = None
    script  = None
    _monkey_proc = None

    # Engine'deki global state'i bu APK için sıfırla
    engine.latest_counters            = {}
    engine.latest_timings             = {}
    engine.latest_burst_peak          = 0
    engine.latest_session_duration_ms = 0
    engine.latest_seq_log             = []
    engine.password_attempts          = []
    engine.PACKAGE_NAME               = package
    engine.LABEL                      = label
    engine._seq_last_tag              = None
    engine._seq_last_count            = 0
    engine._tag_session_count         = {}

    _status = None  # finally bloğunda kullanılır

    try:
        bundle = get_compiled_bundle()

        # ── spawn() yerine: am start + PID bul + attach ──────────────────────
        # device.spawn() jailed Android'da "need Gadget" hatası veriyor.
        # Çözüm: am start (ya da monkey fallback) ile aç, PID'e attach et.

        method = "am start" if launch_activity else "monkey"
        print(f"  [*] Uygulama başlatılıyor ({method})...")
        started = adb_start_app(package, launch_activity)
        if not started:
            print(f"  [!] Başlatma başarısız, yine de PID aranıyor...")

        print(f"  [*] PID aranıyor...")
        pid = get_pid_by_package(package, retries=8)
        if pid is None:
            print(f"  [-] PID bulunamadı → SKIP")
            _status = {"status": "skip", "package": package, "reason": "pid_not_found"}
            return _status  # finally bloğu yine de çalışır, uninstall garantili

        print(f"  [+] PID: {pid} — attach ediliyor...")
        device  = check_and_ensure_frida_server()   # stale state'i temizle
        session = device.attach(pid)
        script  = session.create_script(bundle)
        script.on("message", on_message)
        script.load()

        # Monkey: UI etkileşimi olmadan tetiklenemeyen tag'ler için
        # (ACC_ACTION, OVERLAY_WINDOW, CLIPBOARD_ACCESS, SOCIAL_SHARE, MEDIA_PLAY vb.)
        # --throttle 800ms: çok hızlı flood etme; 500 event × 0.8s ≈ 400s > timeout
        _monkey_proc = adb_s_popen(
            ["shell", "monkey", "-p", package,
             "--throttle", "800",
             "--ignore-crashes", "--ignore-timeouts",
             "--ignore-security-exceptions",
             "500"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"  [+] Monkey başlatıldı (500 event, 800ms throttle)")

        print(f"  [!] Analiz başladı — {timeout}s")

        # ── Erken RPC — hızlı ölen processlerin verisini yakala ──────────────
        # Bazı malwareler emülatör tespiti sonrası 1-2s içinde ölür.
        # Polling döngüsü 1s uyur, ilk poll 5s sonra gelir — çok geç.
        # Burada script.load() hemen ardından bir poll yaparak ilk veriyi alıyoruz.
        time.sleep(1)  # Java.perform tamamlanmak için kısa süre tanı
        try:
            raw = _rpc_safe(script, timeout_s=5)
            engine.latest_timings             = raw.pop("_timings", {})
            engine.latest_burst_peak          = raw.pop("_burst_peak", 0)
            engine.latest_session_duration_ms = raw.pop("_session_duration_ms", 0)
            engine.latest_seq_log             = raw.pop("_seq_log", [])
            engine.latest_counters            = raw
        except Exception:
            pass  # process zaten öldüyse döngü de yakalayacak

        # ── RPC Polling döngüsü ───────────────────────────────────────────────
        # send()/on_message güvenilmez → Python her 5s'de RPC ile veri çeker.
        # Process ölünce RPC exception → döngüden çıkılır, son snapshot kalır.
        start            = time.time()
        last_rpc_poll    = start - 4      # ilk döngü pollu ~1s'de gerçekleşsin
        last_dismiss     = start - 20     # ilk dismiss ~5s'de gerçekleşsin
        rpc_freeze_count = 0
        MAX_RPC_FREEZES  = 3            # ardışık freeze → döngüden çık
        # BCAST_SMS_INTERCEPT + BCAST_SCREEN_WAKE için 15s ve 45s'de simülasyon
        _simulate_at     = [15, 45]
        _simulated       = set()

        while time.time() - start < timeout:
            time.sleep(1)

            # SMS broadcast + screen toggle simülasyonu (15s ve 45s'de bir kez)
            elapsed_s = int(time.time() - start)
            for sim_t in _simulate_at:
                if elapsed_s >= sim_t and sim_t not in _simulated:
                    _simulated.add(sim_t)
                    print(f"  [~] Simülasyon @{sim_t}s — SMS broadcast + screen toggle")
                    simulate_events(package)

            # Periyodik dialog dismiss — ANR/crash diyaloglarını temizler
            if time.time() - last_dismiss >= 15:
                last_dismiss = time.time()
                dismiss_dialogs()

            if time.time() - last_rpc_poll >= 5:
                last_rpc_poll = time.time()
                try:
                    raw = _rpc_safe(script, timeout_s=8)
                    rpc_freeze_count = 0   # başarılı poll → sıfırla
                    engine.latest_timings             = raw.pop("_timings", {})
                    engine.latest_burst_peak          = raw.pop("_burst_peak", 0)
                    engine.latest_session_duration_ms = raw.pop("_session_duration_ms", 0)
                    engine.latest_seq_log             = raw.pop("_seq_log", [])
                    engine.latest_counters            = raw
                    total = sum(v for v in raw.values() if isinstance(v, (int, float)))
                    elapsed = int(time.time() - start)
                    if total > 0:
                        print(f"  [~] RPC poll @{elapsed}s — {total} event")
                except RuntimeError:
                    # _rpc_safe timeout → process freeze (ANR)
                    rpc_freeze_count += 1
                    elapsed = int(time.time() - start)
                    print(f"  [!] RPC freeze #{rpc_freeze_count} (~{elapsed}s) — dialog kapatılıyor...")
                    dismiss_dialogs()
                    if rpc_freeze_count >= MAX_RPC_FREEZES:
                        print(f"  [!] {MAX_RPC_FREEZES} ardışık freeze — döngü sonlandırılıyor")
                        break
                except Exception:
                    elapsed = int(time.time() - start)
                    print(f"  [!] Process öldü (~{elapsed}s) — son snapshot kullanılıyor")
                    break

        # ── Final RPC ─────────────────────────────────────────────────────────
        print(f"  [*] Süre doldu, final RPC...")
        try:
            raw = _rpc_safe(script, timeout_s=10)
            engine.latest_timings             = raw.pop("_timings", {})
            engine.latest_burst_peak          = raw.pop("_burst_peak", 0)
            engine.latest_session_duration_ms = raw.pop("_session_duration_ms", 0)
            engine.latest_seq_log             = raw.pop("_seq_log", [])
            engine.latest_counters            = raw
            total = sum(v for v in raw.values() if isinstance(v, (int, float)))
            print(f"  [+] RPC OK — {total} event alındı")
        except Exception as rpc_e:
            snap_total = sum(
                v for v in engine.latest_counters.values()
                if isinstance(v, (int, float))
            )
            if engine.latest_counters:
                print(f"  [!] Final RPC başarısız — son poll verisi kullanılıyor: {snap_total} event")
            else:
                print(f"  [!] Final RPC başarısız ({rpc_e}) — toplanmış veri de yok")

    except frida.ProcessNotFoundError:
        print(f"  [!] Process ölmüş — mevcut verilerle devam ediliyor")
    except frida.TimedOutError:
        print(f"  [-] Frida timeout → SKIP")
        _status = {"status": "skip", "package": package, "reason": "frida_timeout"}
    except Exception as e:
        err_name = type(e).__name__
        if err_name in _TRANSPORT_ERROR_NAMES:
            # Frida server çöktü ya da app Frida'yı öldürdü. Bunu APK hatası
            # veya emülatör ölümü sayma; Frida'yı toparlayıp sonraki APK'ya geç.
            print(f"  [!] Transport hatası ({err_name}): {e}")
            restart_frida_server()
            _status = {"status": "skip", "package": package, "reason": f"infra_{err_name}"}
        else:
            print(f"  [-] Frida hata: {err_name}: {e}")
            _status = {"status": "error", "package": package, "reason": str(e)}
    else:
        _status = None  # hata yok, normal akış
    finally:
        # ── 4. Temizlik — HER DURUMDA çalışır ────────────────────────────────
        # Monkey'i durdur (timeout bitmeden önce de çıkılabilir)
        if _monkey_proc is not None:
            try:
                _monkey_proc.terminate()
            except Exception:
                pass

        # Timeout olmadan unload/detach sonsuz bloklanabilir (malware process'i öldürmez).
        if script:
            _call_with_timeout(script.unload, 5)
        if session:
            _call_with_timeout(session.detach, 5)

        adb_force_stop(package)

        # ── 5. CSV'ye yaz ────────────────────────────────────────────────────
        if engine.latest_counters:
            with _csv_lock:
                write_row(engine.latest_counters)
            print(f"  [+] CSV satırı yazıldı.")
        else:
            print(f"  [-] Sayaç verisi yok — boş satır yazılmıyor.")
            # Hiç veri toplanamadıysa ve başka bir hata kodu set edilmediyse,
            # bu APK'yı "skip" olarak işaretle — yoksa "ok" döner ve
            # bir sonraki run'da tekrar denenir (ne CSV'de ne failed_apks'te olur).
            if _status is None:
                _status = {"status": "skip", "package": package, "reason": "no_data_collected"}

        # ── 6. Uninstall — HER DURUMDA çalışır ───────────────────────────────
        ok = adb_uninstall(package)
        time.sleep(ADB_UNINSTALL_WAIT)
        if ok:
            print(f"  [+] Kaldırıldı: {package}")
        else:
            if SNAPSHOT_ENABLED:
                print(f"  [!] Kaldırılamadı: {package} — bir sonraki snapshot restore temizleyecek")
            else:
                print(f"  [!] Kaldırılamadı: {package} — Genymotion modu, worker yeniden başlatılacak")

    if _status:
        return _status
    return {"status": "ok", "package": package, "reason": ""}

# ─── APK Claiming — duplicate processing önleme ──────────────────────────────

def _read_in_progress() -> dict:
    """in_progress.json'ı oku. Lock altında çağrılmalı."""
    if not Path(IN_PROGRESS_FILE).exists():
        return {}
    try:
        with open(IN_PROGRESS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _write_in_progress(data: dict) -> None:
    """in_progress.json'a yaz. Lock altında çağrılmalı."""
    with open(IN_PROGRESS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def _drop_stale_claims(in_progress: dict) -> dict:
    """Crash/restart sonrası kalan eski in_progress kayıtlarını temizle."""
    now = datetime.now()
    fresh = {}
    for apk_name, claimed_at in in_progress.items():
        try:
            age = (now - datetime.fromisoformat(claimed_at)).total_seconds()
        except Exception:
            age = CLAIM_STALE_AFTER + 1
        if age <= CLAIM_STALE_AFTER:
            fresh[apk_name] = claimed_at
        else:
            print(f"[stale] in_progress temizlendi: {apk_name}")
    return fresh


def _claim_apk(apk_name: str) -> bool:
    """APK'yı in_progress.json'a ekle. Zaten varsa False döner. Lock altında çağrılmalı."""
    in_progress = _drop_stale_claims(_read_in_progress())
    if apk_name in in_progress:
        _write_in_progress(in_progress)
        return False
    in_progress[apk_name] = datetime.now().isoformat()
    _write_in_progress(in_progress)
    return True


def _unclaim_apk(apk_name: str) -> None:
    """APK'yı in_progress.json'dan çıkar. Lock altında çağrılmalı."""
    in_progress = _read_in_progress()
    in_progress.pop(apk_name, None)
    _write_in_progress(in_progress)


# ─── Batch Döngüsü — Dışarıda ────────────────────────────────────────────────

def batch_analyze(apk_dir: str, label: str, timeout: int, csv_file: str,
                  limit: int | None = None) -> None:
    """
    Bir klasördeki tüm APK'ları sırayla analyze_apk()'a gönderir.
    Döngü burada — analyze_apk tek APK'yı bilir.
    Paralel çalışmayı destekler: _csv_lock ile CSV/failed_apks yazmaları
    serialize edilir, in_progress.json ile duplicate processing önlenir.
    """
    apk_dir  = Path(apk_dir)
    apk_list = sorted(apk_dir.glob("*.apk"))

    if not apk_list:
        print(f"[-] {apk_dir} içinde APK bulunamadı.")
        return

    if limit:
        apk_list = apk_list[:limit]

    # Hızlı ön-filtre için pre-loaded setler (lock dışında, stale olabilir)
    done_packages = _load_done_packages(csv_file)
    failed_apks   = _load_failed_apks()

    # Engine CSV ve JSONL dosyalarını başlat
    with _csv_lock:
        engine.CSV_FILE     = csv_file
        engine.SEQ_LOG_FILE = csv_file.replace('.csv', '_seqlogs.jsonl')
        init_csv()

    total   = len(apk_list)
    results = {"ok": 0, "skip": 0, "error": 0}
    start_t = time.time()

    print(f"\n{'='*60}")
    print(f"  KangalGuard Batch Analyzer")
    print(f"{'='*60}")
    print(f"  Klasör  : {apk_dir}")
    print(f"  Label   : {label}")
    print(f"  APK     : {total}")
    print(f"  Timeout : {timeout}s / APK")
    print(f"  CSV     : {csv_file}")
    print(f"  Cihaz   : {DEVICE_SERIAL}")
    print(f"  Atlanacak (zaten işlenmiş): {len(done_packages)}")
    print(f"  Atlanacak (daha önce hatalı): {len(failed_apks)}")
    print(f"  Log     : {os.path.abspath(FAILED_LOG_FILE)}")
    print(f"{'='*60}\n")

    for i, apk_path in enumerate(apk_list, 1):
        apk_name = apk_path.name

        # Hızlı ön-kontrol (pre-loaded, stale olabilir — gerçek gate lock altında)
        if apk_name in failed_apks:
            print(f"[{i}/{total}] SKIP (daha önce hatalı): {apk_name}")
            results["skip"] += 1
            continue

        # Package name aapt ile lock dışında al (yavaş olabilir)
        pkg_candidate = get_package_name(str(apk_path))
        if pkg_candidate and pkg_candidate in done_packages:
            print(f"[{i}/{total}] SKIP (zaten işlenmiş): {apk_name}")
            results["skip"] += 1
            continue

        # Lock altında fresh kontrol + claiming
        claimed = False
        with _csv_lock:
            fresh_done   = _load_done_packages(csv_file)
            fresh_failed = _load_failed_apks()
            if apk_name in fresh_failed:
                print(f"[{i}/{total}] SKIP (daha önce hatalı): {apk_name}")
                results["skip"] += 1
                continue
            if pkg_candidate and pkg_candidate in fresh_done:
                print(f"[{i}/{total}] SKIP (zaten işlenmiş): {apk_name}")
                results["skip"] += 1
                continue
            if not _claim_apk(apk_name):
                print(f"[{i}/{total}] SKIP (diğer worker işliyor): {apk_name}")
                results["skip"] += 1
                continue
            claimed = True

        # APK claim edildi — lock dışında işle (~2-3 dakika)
        print(f"\n[{i}/{total}] İşleniyor...")
        try:
            # Her APK öncesi emülatörü temiz snapshot'a döndür.
            # Frida server crash, stale session, birikmiş kurulumlar → sıfırlanır.
            restore_clean_snapshot()

            result = analyze_apk(str(apk_path), label, timeout)
            results[result["status"]] += 1

            # skip veya error → failed log'a kaydet.
            # infra_* Frida/emülatör altyapısıdır; APK'yı kalıcı failed sayma.
            reason = result.get("reason", "unknown")
            if result["status"] in ("skip", "error") and not str(reason).startswith("infra_"):
                _log_failed_apk(
                    apk_name = apk_name,
                    package  = result.get("package"),
                    label    = label,
                    reason   = reason,
                )

            if result["status"] == "ok" and pkg_candidate:
                done_packages.add(pkg_candidate)   # pre-loaded seti güncelle

        finally:
            if claimed:
                with _csv_lock:
                    _unclaim_apk(apk_name)

        gc.collect()

        # İlerleme özeti
        elapsed  = time.time() - start_t
        done     = results["ok"] + results["skip"] + results["error"]
        rate     = done / elapsed if elapsed > 0 else 0
        remaining = (total - i) / rate if rate > 0 else 0
        print(f"\n  Durum: ✅ {results['ok']}  ⏭️  {results['skip']}  ❌ {results['error']}  "
              f"| ⏱️  ~{remaining/60:.1f} dk kaldı")

    # Final özet
    elapsed_total = time.time() - start_t
    print(f"\n{'='*60}")
    print(f"  TAMAMLANDI")
    print(f"{'='*60}")
    print(f"  ✅  Başarılı : {results['ok']}")
    print(f"  ⏭️   Atlanan  : {results['skip']}")
    print(f"  ❌  Hatalı   : {results['error']}")
    print(f"  ⏱️   Süre     : {elapsed_total/60:.1f} dakika")
    print(f"  💾  CSV      : {os.path.abspath(csv_file)}")
    print(f"  📋  Hata log : {os.path.abspath(FAILED_LOG_FILE)}")
    print(f"{'='*60}")


def _load_done_packages(csv_file: str) -> set:
    """Resume için daha önce işlenmiş package name'leri yükle."""
    done = set()
    if not Path(csv_file).exists():
        return done
    try:
        with open(csv_file, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                pkg = row.get("package_name", "").strip()
                if pkg:
                    done.add(pkg)
    except Exception:
        pass
    return done


def _load_failed_apks() -> set:
    """
    Daha önce skip/error olan APK dosya adlarını yükle.
    Bunlar bir sonraki çalıştırmada yeniden denenmez.
    """
    failed = set()
    if not Path(FAILED_LOG_FILE).exists():
        return failed
    try:
        with open(FAILED_LOG_FILE, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                apk = row.get("apk_name", "").strip()
                if apk:
                    failed.add(apk)
    except Exception:
        pass
    return failed


def _log_failed_apk(apk_name: str, package: str | None, label: str, reason: str) -> None:
    """
    Başarısız APK'yı logs/failed_apks.csv dosyasına kaydet.
    Sütunlar: apk_name, package_name, label, reason, timestamp
    """
    os.makedirs("logs", exist_ok=True)
    with _csv_lock:
        write_header = not Path(FAILED_LOG_FILE).exists() or Path(FAILED_LOG_FILE).stat().st_size == 0
        with open(FAILED_LOG_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow(["apk_name", "package_name", "label", "reason", "timestamp"])
            writer.writerow([
                apk_name,
                package or "",
                label,
                reason,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ])

# ─── Tee — stdout + stderr'i hem terminale hem log dosyasına yaz ─────────────

class _Tee:
    """
    sys.stdout / sys.stderr'in yerine geçer.
    Her satırın başına [HH:MM:SS] zaman damgası ekler,
    aynı anda hem terminale hem log dosyasına yazar.
    """
    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log      = log_file
        self._bol      = True   # beginning-of-line: yeni satır başı mı?

    def write(self, text: str):
        if not text:
            return
        stamped = ""
        for ch in text:
            if self._bol and ch not in ("\n", "\r"):
                ts = datetime.now().strftime("%H:%M:%S")
                stamped += f"[{ts}] "
                self._bol = False
            stamped += ch
            if ch == "\n":
                self._bol = True
        self._terminal.write(stamped)
        self._terminal.flush()
        self._log.write(stamped)
        self._log.flush()

    def flush(self):
        self._terminal.flush()
        self._log.flush()

    # fileno gerekirse doğrudan terminale yönlendir
    def fileno(self):
        return self._terminal.fileno()


# ─── CLI ─────────────────────────────────────────────────────────────────────

def setup_snapshot() -> None:
    """
    Tek seferlik kurulum: frida-server başlat, snapshot kaydet.
    Kullanım: python batch_analyzer.py --setup
    """
    print(f"[*] KangalGuard snapshot kurulumu başlıyor...")
    print(f"[*] Emülatörün açık ve bağlı olduğundan emin ol.\n")

    # 1. frida-server'ı başlat
    print(f"[*] Frida-server başlatılıyor ({FRIDA_SERVER_PATH})...")
    try:
        adb_s(["shell", "su", "0", "pkill", "-f", "frida-server"], capture_output=True, timeout=10)
        time.sleep(1)
        adb_s_popen(["shell", "su", "0", FRIDA_SERVER_PATH],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(FRIDA_SERVER_RESTART_WAIT)
    except Exception as e:
        print(f"[!] Frida-server başlatılamadı: {e}")
        sys.exit(1)

    # Frida-server gerçekten çalışıyor mu doğrula
    print(f"[*] Frida-server doğrulanıyor...")
    try:
        dev = frida.get_device(DEVICE_SERIAL, timeout=10)
        dev.enumerate_processes()
        print(f"[+] Frida-server çalışıyor ve bağlantı başarılı.")
    except Exception as e:
        print(f"\n[!] HATA: Frida-server bağlantısı kurulamadı: {e}")
        print(f"")
        print(f"    Büyük ihtimalle frida-server binary'si cihazda yok.")
        print(f"    Şunları çalıştır, sonra --setup'ı tekrarla:")
        print(f"")
        print(f"    adb push frida-server /data/local/tmp/")
        print(f"    adb shell chmod 755 /data/local/tmp/frida-server")
        sys.exit(1)

    # 2. Snapshot kaydet
    print(f"[*] Snapshot kaydediliyor ({SNAPSHOT_NAME})...")
    try:
        r = adb_s(
            ["emu", "avd", "snapshot", "save", SNAPSHOT_NAME],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=30
        )
        if "KO" in r.stdout:
            print(f"[!] Snapshot kaydedilemedi: {r.stdout.strip()}")
            print(f"    Emülatörün Android Studio AVD olduğundan emin ol.")
            sys.exit(1)
        print(f"[+] Snapshot kaydedildi: '{SNAPSHOT_NAME}'")
    except Exception as e:
        print(f"[!] Snapshot hatası: {e}")
        sys.exit(1)

    print(f"\n[+] Kurulum tamamlandı!")
    print(f"    Artık analiz başlatabilirsin:")
    print(f"    python batch_analyzer.py --dir ./data/benign --label benign")


def main():
    global DEVICE_SERIAL

    signal.signal(signal.SIGTERM, _request_shutdown)

    parser = argparse.ArgumentParser(
        description="KangalGuard Batch Analyzer — tek APK arayüzü, döngü dışarıda"
    )
    parser.add_argument("--device",  required=True,
                        help="ADB device serial (adb devices ile bak). Örn: 192.168.0.101:5555")
    parser.add_argument("--setup",   action="store_true",
                        help="Tek seferlik kurulum: frida-server başlat + snapshot kaydet")
    parser.add_argument("--dir",     help="APK klasörü (örn: ./benign)")
    parser.add_argument("--label",   choices=["benign", "malware"],
                        help="Tüm APK'lara uygulanacak label")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"APK başına analiz süresi saniye (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--csv",     default=DEFAULT_CSV,
                        help=f"Çıktı CSV dosyası (default: {DEFAULT_CSV})")
    parser.add_argument("--limit",   type=int, default=None,
                        help="Max kaç APK işlensin (test için)")

    args = parser.parse_args()
    DEVICE_SERIAL = args.device

    # logs/ dizinini oluştur (lock dosyası ve in_progress.json için)
    os.makedirs("logs", exist_ok=True)

    # ── Kurulum modu ─────────────────────────────────────────────────────────
    if args.setup:
        setup_snapshot()
        return

    # Normal mod: --dir ve --label zorunlu
    if not args.dir or not args.label:
        parser.error("--dir ve --label gerekli (ya da --setup ile kurulum yap)")

    # ── Log dosyası kur ───────────────────────────────────────────────────────
    log_name = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{args.label}.log"
    log_path = os.path.join("logs", log_name)
    log_file = open(log_path, "w", encoding="utf-8", buffering=1)

    sys.stdout = _Tee(sys.__stdout__, log_file)
    sys.stderr = _Tee(sys.__stderr__, log_file)

    print(f"[*] Log: {os.path.abspath(log_path)}\n")

    try:
        batch_analyze(
            apk_dir  = args.dir,
            label    = args.label,
            timeout  = args.timeout,
            csv_file = args.csv,
            limit    = args.limit,
        )
    finally:
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        log_file.close()
        print(f"[*] Log kaydedildi: {log_path}")

if __name__ == "__main__":
    main()
