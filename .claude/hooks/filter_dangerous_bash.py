"""
PreToolUse | Bash
Veri setini veya emulator durumunu bozabilecek tehlikeli komutlari engeller.
"""
import sys
import json
import re

DANGEROUS_PATTERNS = [
    (r"rm\s+-[a-z]*r[a-z]*f", "rm -rf komutu"),
    (r">\s*kangal_dataset\.csv", "Veri seti uzerine yazma (>)"),
    (r"truncate.*kangal_dataset", "Veri seti truncate"),
    (r">\s*logs/failed_apks\.csv", "failed_apks.csv uzerine yazma"),
    (r"adb\s+emu\s+avd\s+snapshot\s+delete", "AVD snapshot silme"),
    (r"avd\s+delete", "AVD silme"),
]

d = json.load(sys.stdin)
cmd = d.get("tool_input", {}).get("command", "")

for pattern, description in DANGEROUS_PATTERNS:
    if re.search(pattern, cmd, re.IGNORECASE):
        print(f"ENGELLENDI: {description} tespit edildi.")
        print(f"Komut: {cmd[:200]}")
        print("Devam etmek istiyorsan bu islemi manuel olarak calistir.")
        sys.exit(2)
