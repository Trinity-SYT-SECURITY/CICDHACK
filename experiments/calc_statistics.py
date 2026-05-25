"""
experiments/calc_statistics.py
Calculates Mann-Whitney U test (p-values) and Cohen's d for the experimental results
to improve statistical rigor as requested by reviewers.
"""
import json, random
from pathlib import Path
from collections import Counter
import numpy as np
from scipy.stats import mannwhitneyu

LAB_ROOT = Path(__file__).parent.parent
LOGS_DIR = LAB_ROOT / "logs"

N_CROSS = 10
SEED    = 42

def is_valid_run(run_dir):
    step1 = run_dir / "iter_01" / "step.json"
    if not step1.exists(): return False
    try:
        d = json.loads(step1.read_text(encoding="utf-8", errors="ignore"))
        if "Connection error" in (d.get("error") or ""): return False
    except: return False
    hist = run_dir / "history.json"
    if not hist.exists(): return False
    try:
        h = json.loads(hist.read_text(encoding="utf-8", errors="ignore"))
        return any(m.get("tests_total", 0) > 0 for m in h)
    except: return False

def load_all_valid():
    runs = []
    for d in sorted(LOGS_DIR.iterdir()):
        if not d.is_dir(): continue
        if not is_valid_run(d): continue
        cfg_f = d / "config.json"
        if not cfg_f.exists(): continue
        try:
            cfg  = json.loads(cfg_f.read_text(encoding="utf-8", errors="ignore"))
            hist = json.loads((d / "history.json").read_text(encoding="utf-8", errors="ignore"))
        except: continue
        valid = [m for m in hist if m.get("tests_total", 0) > 0]
        if not valid: continue
        attack = cfg.get("attack") or "baseline"
        runs.append({"run_id": d.name, "model": cfg["model"], "attack": attack,
                     "history": hist, "valid_history": valid, "final": valid[-1]})
    return runs

def sub(runs, model, attack):
    return [r for r in runs if r["model"] == model and r["attack"] == attack]

def sample_n(lst, n, seed=SEED):
    rng = random.Random(seed)
    return rng.sample(lst, n) if len(lst) >= n else lst

SHARED_ATTACKS = ["baseline", "feedback_poison", "instruction_inject", "memory_poison"]

def build_sampled(runs):
    s = {}
    for att in SHARED_ATTACKS:
        s[("mistral:latest", att)] = sample_n(sub(runs, "mistral:latest", att), N_CROSS)
        s[("qwen2.5:7b",     att)] = sample_n(sub(runs, "qwen2.5:7b",     att), N_CROSS)
    s[("mistral:latest", "trusted_defense_poison")] = sample_n(sub(runs, "mistral:latest", "trusted_defense_poison"), N_CROSS)
    return s

def cohens_d(group1, group2):
    n1, n2 = len(group1), len(group2)
    var1, var2 = np.var(group1, ddof=1), np.var(group2, ddof=1)
    pooled_sd = np.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2))
    return (np.mean(group1) - np.mean(group2)) / pooled_sd if pooled_sd > 0 else 0

def bootstrap_ci(data, num_bootstraps=10000, alpha=0.05, seed=SEED):
    rng = np.random.default_rng(seed)
    means = [np.mean(rng.choice(data, size=len(data), replace=True)) for _ in range(num_bootstraps)]
    return np.percentile(means, [alpha/2 * 100, (1 - alpha/2) * 100])

if __name__ == "__main__":
    runs = load_all_valid()
    sampled = build_sampled(runs)
    
    print("=== Statistical Analysis (Mann-Whitney U, Cohen's d, Bootstrap 95% CI) ===")
    
    for model in ["mistral:latest", "qwen2.5:7b"]:
        baseline_grp = sampled.get((model, "baseline"), [])
        if not baseline_grp: continue
        
        baseline_vals = [r["final"]["vulns_exploitable"] for r in baseline_grp]
        print(f"\nModel: {model}")
        print(f"  Baseline Mean: {np.mean(baseline_vals):.2f} (SD: {np.std(baseline_vals, ddof=1):.2f})")
        ci = bootstrap_ci(baseline_vals)
        print(f"  Baseline 95% CI: [{ci[0]:.2f}, {ci[1]:.2f}]")
        
        attacks = [a for a in SHARED_ATTACKS if a != "baseline"]
        if model == "mistral:latest": attacks.append("trusted_defense_poison")
        
        for attack in attacks:
            grp = sampled.get((model, attack), [])
            if not grp: continue
            
            vals = [r["final"]["vulns_exploitable"] for r in grp]
            mean = np.mean(vals)
            sd = np.std(vals, ddof=1)
            ci = bootstrap_ci(vals)
            
            # Compare to baseline
            stat, p = mannwhitneyu(vals, baseline_vals, alternative="two-sided")
            d = cohens_d(vals, baseline_vals)
            
            print(f"\n  Condition: {attack}")
            print(f"    Mean: {mean:.2f} (SD: {sd:.2f})")
            print(f"    95% CI: [{ci[0]:.2f}, {ci[1]:.2f}]")
            print(f"    Mann-Whitney U p-value: {p:.4f}")
            print(f"    Cohen's d: {d:.2f}")
