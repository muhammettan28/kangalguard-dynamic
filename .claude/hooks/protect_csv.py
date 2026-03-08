"""
PreToolUse | Edit, Write
kangal_dataset.csv ve failed_apks.csv dosyalarini elle duzenlemeden korur.
Bu dosyalar yalnizca pipeline tarafindan yazilmali.
"""
import sys
import json

PROTECTED = ["kangal_dataset.csv", "failed_apks.csv"]

d = json.load(sys.stdin)
file_path = d.get("tool_input", {}).get("file_path", "")

for protected in PROTECTED:
    if protected in file_path:
        print(f"ENGELLENDI: '{protected}' elle duzenlenemez.")
        print("Bu dosya yalnizca batch_analyzer.py pipeline'i tarafindan yazilmali.")
        sys.exit(2)
