"""
PostToolUse | Bash
batch_analyzer.py calistirildiktan sonra dataset durumunu raporlar.
"""
import sys
import json
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CSV_PATH = os.path.join(PROJECT_ROOT, "kangal_dataset.csv")

d = json.load(sys.stdin)
cmd = d.get("tool_input", {}).get("command", "")

if "batch_analyzer" not in cmd:
    sys.exit(0)

if not os.path.exists(CSV_PATH):
    print("Dataset bulunamadi: kangal_dataset.csv")
    sys.exit(0)

with open(CSV_PATH, encoding="utf-8") as f:
    lines = f.readlines()

total = len(lines) - 1  # header satirini cikar
if total < 0:
    total = 0

# Etiket dagilimini say
benign = sum(1 for l in lines[1:] if ",benign," in l)
malware = sum(1 for l in lines[1:] if ",malware," in l)

print(f"Dataset: {total} sample toplam | {benign} benign | {malware} malware")
