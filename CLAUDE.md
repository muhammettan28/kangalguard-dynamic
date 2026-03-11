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

**`agent.ts`** — Frida TypeScript agent injected into the Android process. Hooks **54** Java APIs across **11 categories** (reflection, crypto, anti-analysis, IPC, file system, network, persistence, process/memory, clipboard, accessibility, overlay). Tracks raw event counters, per-category first-occurrence timings, burst peaks in 5s windows, and a sequential event log (`seqLog`). Exposes data via `rpc.exports.getCounters()` and also auto-flushes every 20s via `setInterval`. The agent file at the **root** (`agent.ts`) is the active agent — `agent/index.ts` is an unused template.

**`kangal_collector.py`** — Feature engineering module. Defines all **143 CSV columns** and computes features from raw agent data:
- 54 raw counters (direct from agent)
- 36 derived features:
  - 8 composite scores (`network_score`, `anti_analysis_score`, etc.)
  - 5 ratios (`write_to_read_ratio`, `crypto_to_network_ratio`, etc.)
  - 7 boolean pattern flags (`has_exfil_pattern`, etc.)
  - 4 session-normalized scores (`network_score_per_sec`, etc.) — fixes reversed score problem where large benign apps scored higher than malware
  - 6 rate features (count / session_sec)
  - 6 log1p outlier features for columns with 80x–336x p99/max ratio
- 22 temporal features: first-occurrence timing per category + burst + session_anomaly_flag + 3 early-5s flags + 4 inter-event deltas
- 28 sequence features: binary chain flags + per-chain counts + first-chain timings + 8 new attack vector chains (SURVEIL→NETWORK, CLIPBOARD→NETWORK, etc.)

**`batch_analyzer.py`** — Orchestration loop. For each APK: restores clean AVD snapshot (`kangal_clean`) → installs APK → launches via `adb monkey` → attaches Frida by PID → polls RPC every 5s → writes CSV row → uninstalls APK. Supports resume (skips packages already in CSV and APKs in `logs/failed_apks.csv`). Compiles `agent.ts` once at startup using `frida.Compiler()` and reuses the bundle for all APKs.

## Key Design Decisions

- **PID attach, not `device.spawn()`**: `spawn()` fails with "need Gadget" on non-rooted/jailed Android. Workaround: launch via `adb shell monkey`, find PID with `adb shell pidof`, attach to that PID.
- **RPC polling over `on_message`**: `script.exports_sync.get_counters()` every 5s is more reliable than `send()`/`recv()` for batch collection.
- **Snapshot restore per APK**: `adb emu avd snapshot load kangal_clean` before every APK guarantees a clean emulator state including a fresh frida-server. The snapshot must be saved with frida-server already running.
- **Agent compiled once**: `frida.Compiler()` compiles `agent.ts` at startup; the bundle string is cached in `_compiled_bundle` and reused across all APKs.
- **Global state in `kangal_collector.py`**: `latest_counters`, `latest_timings`, `latest_burst_peak`, `latest_session_duration_ms`, `latest_seq_log`, `PACKAGE_NAME`, `LABEL` are module-level globals that `batch_analyzer.py` resets before each APK.
- **`_rpc_safe(timeout_s=8)`**: `exports_sync.get_counters()` has no built-in timeout — a frozen process (ANR) blocks it indefinitely. Wrapped in a daemon thread; raises `RuntimeError("rpc_timeout")` if no response within 8s. 3 consecutive freezes break the polling loop.
- **`dismiss_dialogs()`**: Sends `KEYCODE_BACK` + `KEYCODE_ENTER` via adb to dismiss ANR / "App Has Stopped" dialogs. Called before each APK install (clears residual dialogs) and every 15s during the polling loop.
- **Per-tag seqLog throttle**: Instead of a global `MAX_SEQ_EVENTS=200` cap (which high-frequency tags like REFLECT would exhaust instantly), each tag has its own limit (REFLECT/DYNAMIC_CLS: 15, NETWORK: 30, CLIPBOARD/OVERLAY: 10–20). Prevents benign-app noise from drowning out rare but critical events.

## Feature Schema (143 columns)

| Group | Count | Description |
|-------|-------|-------------|
| Meta | 3 | package_name, label, timestamp |
| Raw | 54 | Direct hook counters from agent.ts |
| Derived | 36 | Scores (8) + ratios (5) + booleans (7) + normalized scores (4) + rates (6) + log1p (6) |
| Temporal | 22 | First-occurrence timings (8) + burst/session (2) + flags (4) + early-5s flags (3) + deltas (4) + anomaly (1) |
| Sequence | 28 | Binary chains (10) + counts (5) + timings (5) + new attack vectors (8) |

### seqLog Tags (18 tags)
`REFLECT`, `DEX_LOAD`, `EXEC`, `DYNAMIC_CLS`, `CRYPTO`, `NETWORK`, `FILE_WRITE`, `ROOT_CHECK`, `ANTI`, `SMS`, `CONTACT_READ`, `NATIVE_LOAD`, `PERSIST`, `SURVEIL`, `IPC`, `CLIPBOARD`, `OVERLAY`, `ACCESSIBILITY`

### Known Strong Signals (validated on existing dataset)
| Feature | Malware | Benign | Type |
|---------|---------|--------|------|
| `write_to_read_ratio` | 0.47 | 0.007 | ratio |
| `seq_file_then_network` | 9.4% | 0.1% | binary |
| `first_sms_ms > 0` | present | absent | timing |
| `seq_reflect_before_exec` | 13.5% | 0.6% | binary |
| `seq_dex_then_reflect` | 10.9% | 0.9% | binary |
| `anti_to_total_ratio` | 0.27 | 0.12 | ratio |

### Feature Problem Fixes
- **Reversed scores** (network_score, anti_analysis_score, stealth_score, dynamic_exec_score): Benign apps made more absolute API calls because their sessions were longer. Fixed with `_per_sec` normalized variants.
- **Extreme outliers** (reflection_invoke_count 80x, dns_lookup_count 336x, etc.): Fixed with `log1p_*` derived features for ML stability without discarding raw data.
- **seqLog flooding**: Fixed with per-tag throttle replacing global cap.

## Emulator

Genymotion Android 8.0 with Genymotion-ARM-Translation_for_8.0 (ARM real-device behavior).

## Timing (per APK)

| Phase | Duration |
|-------|----------|
| Dialog dismiss + install | ~17s |
| adb monkey + PID find | ~5-8s |
| Frida attach | ~2s |
| Analysis window (DEFAULT_TIMEOUT) | 75s |
| Final RPC + force-stop | ~3s |
| Uninstall (ADB_UNINSTALL_WAIT) | ~5s |
| Snapshot restore | ~30-60s |
| **Total** | **~140-170s (~2.5-3 min)** |

## Data Files

- `kangal_dataset.csv` — output dataset (143 columns, growing)
- `data/benign/` — APK files to process (source: KronoDroid, AndroZoo)
- `data/malware/` — malware APKs
- `logs/failed_apks.csv` — APKs that failed/were skipped (not retried on resume)
- `logs/run_<timestamp>_<label>.log` — timestamped console output per run
- `arşiv/kangal_dataset.csv` — archived previous dataset (97-column schema, pre-feature-engineering update)

## Prerequisites

- Android emulator with root access (requires `su 0`)
- `frida-server` binary at `/data/local/tmp/frida-server` on the emulator
- Python packages: `frida`, `androguard` (fallback for package name extraction)
- Android SDK tools: `adb`, `aapt` (for package name extraction)
- AVD snapshot named `kangal_clean` (created via `--setup`)

## Claude Code Hooks

Hook scripts live in `.claude/hooks/` and are configured in `.claude/settings.json`.

| Event | Matcher | Script | Davranış |
|-------|---------|--------|----------|
| PreToolUse | Edit\|Write | `protect_csv.py` | `kangal_dataset.csv` ve `failed_apks.csv` dosyalarına doğrudan yazmayı engeller |
| PreToolUse | Bash | `filter_dangerous_bash.py` | `rm -rf`, CSV üzerine yazma, AVD silme gibi tehlikeli komutları engeller |
| PostToolUse | Edit\|Write | `check_agent_ts.py` | `agent.ts` değiştirildikten sonra `npx tsc --noEmit` çalıştırır |
| PostToolUse | Edit\|Write | `check_python_syntax.py` | `.py` dosyaları değiştirildikten sonra `py_compile` ile syntax kontrolü yapar |
| PostToolUse | Bash | `dataset_rowcount.py` | `batch_analyzer.py` çalıştırıldıktan sonra benign/malware sample sayısını raporlar |

## Code Style

- Use comments sparingly — only where logic is genuinely complex and non-obvious.
