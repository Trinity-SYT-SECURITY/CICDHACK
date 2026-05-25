#!/usr/bin/env python3
"""
setup.py — First-time research lab setup

Run this ONCE after creating the lab to:
1. Install dependencies
2. Create the vulnerable baseline snapshot (app.py.vulnerable)
3. Smoke-test the full pipeline
"""
import subprocess, shutil, sys
from pathlib import Path

LAB = Path(__file__).parent
TARGET = LAB / "target"
APP_PY = TARGET / "app.py"
SNAP   = TARGET / "app.py.vulnerable"

def run(cmd, **kw):
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    r = subprocess.run(cmd, **kw)
    if r.returncode != 0:
        print(f"  [ERROR] exit code {r.returncode}")
        if hasattr(r, 'stderr') and r.stderr:
            print(r.stderr[:300])
    return r.returncode == 0

print("=== Research Lab Setup ===\n")

# 1. Install deps
print("[1] Installing Python dependencies...")
run([sys.executable, "-m", "pip", "install", "-q",
     "fastapi", "uvicorn", "httpx", "pydantic",
     "pytest", "pytest-json-report",
     "openai", "bandit"])

# 2. Snapshot vulnerable app
print("\n[2] Creating vulnerable baseline snapshot...")
shutil.copy2(APP_PY, SNAP)
print(f"  Saved: {SNAP}")

# 3. Smoke-test: compile
print("\n[3] Compile check on vulnerable app...")
ok = run([sys.executable, "-m", "py_compile", str(APP_PY)])
print(f"  compile: {'OK' if ok else 'FAIL'}")

# 4. Smoke-test: functional tests
print("\n[4] Running functional tests (expect some to pass)...")
r = subprocess.run(
    [sys.executable, "-m", "pytest", str(TARGET / "tests" / "test_functional.py"),
     "--tb=short", "-q"],
    cwd=str(TARGET)
)

# 5. Smoke-test: security oracle (expect ALL to FAIL on vulnerable baseline)
print("\n[5] Running security oracle (expect ALL EXPLOITABLE on baseline)...")
r = subprocess.run(
    [sys.executable, "-m", "pytest", str(TARGET / "tests" / "test_security.py"),
     "--tb=line", "-q"],
    cwd=str(TARGET)
)

# 6. Semgrep scan
print("\n[6] Semgrep scan (expect 5 findings)...")
r = subprocess.run(
    ["semgrep", "--config", str(LAB / ".semgrep" / "rules.yml"),
     str(APP_PY), "--text", "--quiet"],
    capture_output=True, text=True
)
print(r.stdout[:500] or "  (no output)")

print("\n=== Setup complete ===")
print("Next step:")
print("  python orchestration/loop_runner.py --iterations 5 --model mistral:latest")
print("  python orchestration/loop_runner.py --iterations 5 --attack feedback_poison")
