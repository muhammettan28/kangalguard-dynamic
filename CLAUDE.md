# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# One-time setup: start frida-server on emulator and save clean snapshot
python batch_analyzer.py --setup

# Run batch analysis
python batch_analyzer.py --dir ./data/benign --label benign
python batch_analyzer.py --dir ./data/malware --label malware

# Test run (5 APKs, 30s timeout)
python batch_analyzer.py --dir ./data/benign --label benign --limit 5 --timeout 30

# Custom CSV output
python batch_analyzer.py --dir ./data/benign --label benign --csv custom_output.csv
```

## Architecture

The pipeline has three layers:

**`agent.ts`** — Frida TypeScript agent injected into the Android process. Hooks ~50 Java APIs across 8 categories (reflection, crypto, anti-analysis, IPC, file system, network, persistence, process/memory). Tracks raw event counters, per-category first-occurrence timings, burst peaks in 5s windows, and a sequential event log (`seqLog`). Exposes data via `rpc.exports.getCounters()` and also auto-flushes every 20s via `setInterval`. The agent file at the **root** (`agent.ts`) is the active agent — `agent/index.ts` is an unused template.

**`kangal_collector.py`** — Feature engineering module. Defines all 97 CSV columns and computes features from raw agent data:
- 50 raw counters (direct from agent)
- 20 derived features: 8 composite scores (`network_score`, `anti_analysis_score`, etc.), 5 ratios, 7 boolean pattern flags (`has_exfil_pattern`, etc.)
- 14 temporal features: first-occurrence timing per category + `burst_peak_count`, `rapid_burst_flag`, etc.
- 10 sequence features: behavioral chain detection (`seq_reflect_before_exec`, `seq_crypto_before_network`, etc.)

**`batch_analyzer.py`** — Orchestration loop. For each APK: restores clean AVD snapshot (`kangal_clean`) → installs APK → launches via `adb monkey` → attaches Frida by PID → polls RPC every 5s → writes CSV row → uninstalls APK. Supports resume (skips packages already in CSV and APKs in `logs/failed_apks.csv`). Compiles `agent.ts` once at startup using `frida.Compiler()` and reuses the bundle for all APKs.

## Key Design Decisions

- **PID attach, not `device.spawn()`**: `spawn()` fails with "need Gadget" on non-rooted/jailed Android. Workaround: launch via `adb shell monkey`, find PID with `adb shell pidof`, attach to that PID.
- **RPC polling over `on_message`**: `script.exports_sync.get_counters()` every 5s is more reliable than `send()`/`recv()` for batch collection.
- **Snapshot restore per APK**: `adb emu avd snapshot load kangal_clean` before every APK guarantees a clean emulator state including a fresh frida-server. The snapshot must be saved with frida-server already running.
- **Agent compiled once**: `frida.Compiler()` compiles `agent.ts` at startup; the bundle string is cached in `_compiled_bundle` and reused across all APKs.
- **Global state in `kangal_collector.py`**: `latest_counters`, `latest_timings`, `latest_burst_peak`, `latest_session_duration_ms`, `latest_seq_log`, `PACKAGE_NAME`, `LABEL` are module-level globals that `batch_analyzer.py` resets before each APK.

## Data Files

- `kangal_dataset.csv` — output dataset (97 columns, growing)
- `data/benign/` — APK files to process (source: KronoDroid, AndroZoo)
- `data/malware/` — empty, malware collection not started
- `logs/failed_apks.csv` — APKs that failed/were skipped (not retried on resume)
- `logs/run_<timestamp>_<label>.log` — timestamped console output per run

## Prerequisites

- Android emulator with root access (requires `su 0`)
- `frida-server` binary at `/data/local/tmp/frida-server` on the emulator
- Python packages: `frida`, `androguard` (fallback for package name extraction)
- Android SDK tools: `adb`, `aapt` (for package name extraction)
- AVD snapshot named `kangal_clean` (created via `--setup`)
