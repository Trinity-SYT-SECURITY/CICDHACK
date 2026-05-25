"""
experiments/analyze_transitions.py
Analyzes vulnerability transitions (Thrashing) across iterations to validate the Profile Shift phenomenon.
"""
import json
from pathlib import Path
from collections import defaultdict

LAB_ROOT = Path(__file__).parent.parent
LOGS_DIR = LAB_ROOT / "logs"

def is_valid_run(run_dir):
    hist = run_dir / "history.json"
    if not hist.exists(): return False
    try:
        h = json.loads(hist.read_text(encoding="utf-8", errors="ignore"))
        return any(m.get("tests_total", 0) > 0 for m in h)
    except: return False

def main():
    runs = []
    for d in sorted(LOGS_DIR.iterdir()):
        if not d.is_dir() or not is_valid_run(d): continue
        hist = json.loads((d / "history.json").read_text(encoding="utf-8", errors="ignore"))
        valid_hist = [m for m in hist if m.get("tests_total", 0) > 0]
        if valid_hist:
            runs.append({"run_id": d.name, "history": valid_hist})
            
    print(f"Loaded {len(runs)} valid runs for transition analysis.")
    
    vuln_ids = ["V1", "V2", "V3", "V4", "V5"]
    
    # We define a "Thrash" as going from NOT in exploitable_list to IN exploitable_list
    # Note: If it's exploitable initially, we wait until it's fixed, then if it becomes exploitable again, that's a thrash.
    thrash_counts = {vid: 0 for vid in vuln_ids}
    total_fixed_at_least_once = {vid: 0 for vid in vuln_ids}
    
    for r in runs:
        hist = r["history"]
        for vid in vuln_ids:
            state_history = [(vid in m.get("exploitable_list", [])) for m in hist]
            
            # Did it ever become False (fixed)?
            if False in state_history:
                total_fixed_at_least_once[vid] += 1
                first_fixed_idx = state_history.index(False)
                
                # Did it become True (exploitable) AFTER being fixed?
                if True in state_history[first_fixed_idx:]:
                    thrash_counts[vid] += 1
                    
    print("\n=== Vulnerability Thrashing (Profile Shift Validation) ===")
    print("Thrashing = Vulnerability was fixed in an early iteration, but broken again in a later iteration.")
    for vid in vuln_ids:
        fixed_count = total_fixed_at_least_once[vid]
        thrashes = thrash_counts[vid]
        rate = (thrashes / fixed_count * 100) if fixed_count > 0 else 0
        print(f"{vid}: Fixed at least once in {fixed_count} runs. Thrashed (re-broken) in {thrashes} runs. Thrashing Rate: {rate:.1f}%")

if __name__ == "__main__":
    main()
