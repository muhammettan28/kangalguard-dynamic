"""
PostToolUse | Edit, Write
agent.ts degistirildikten sonra TypeScript derleme kontrolu yapar.
Hata varsa Claude'u uyararak devam etmesini engeller.
"""
import sys
import json
import subprocess
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

d = json.load(sys.stdin)
file_path = d.get("tool_input", {}).get("file_path", "")

if not file_path.endswith("agent.ts"):
    sys.exit(0)

result = subprocess.run(
    ["npx", "tsc", "--noEmit"],
    cwd=PROJECT_ROOT,
    capture_output=True,
    text=True,
    timeout=60,
)

if result.returncode != 0:
    print("agent.ts TypeScript derleme HATASI:")
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    sys.exit(2)
else:
    print("agent.ts: TypeScript derleme OK")
