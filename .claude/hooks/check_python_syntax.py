"""
PostToolUse | Edit, Write
.py dosyalari degistirildikten sonra sozdizimi kontrolu yapar.
"""
import sys
import json
import subprocess

d = json.load(sys.stdin)
file_path = d.get("tool_input", {}).get("file_path", "")

if not file_path.endswith(".py"):
    sys.exit(0)

# Hook script'lerinin kendi kontrolunden muaf tut
if ".claude/hooks" in file_path.replace("\\", "/"):
    sys.exit(0)

result = subprocess.run(
    [sys.executable, "-m", "py_compile", file_path],
    capture_output=True,
    text=True,
)

if result.returncode != 0:
    print(f"Python sozdizimi HATASI: {file_path}")
    print(result.stderr)
    sys.exit(2)
else:
    print(f"Sozdizimi OK: {file_path}")
