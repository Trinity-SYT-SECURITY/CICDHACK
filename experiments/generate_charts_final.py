"""
experiments/generate_charts_final.py
All cross-model comparisons use n=10 per condition (seed=42).
Mistral Trusted Defense also uses n=10 to ensure a completely balanced sample.
Single-model figures (Fig 3, 6, 7) use this uniform sampled dataset.
"""
import json, random
from pathlib import Path
from collections import Counter
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

LAB_ROOT = Path(__file__).parent.parent
LOGS_DIR = LAB_ROOT / "logs"
FIG_DIR  = LAB_ROOT / "figures"
FIG_DIR.mkdir(exist_ok=True)

STYLE = {
    "font.family": "DejaVu Sans", "font.size": 11,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.3, "grid.linestyle": "--",
    "figure.facecolor": "white",
}
def apply_style():
    for k, v in STYLE.items():
        plt.rcParams[k] = v

N_CROSS = 10   # fixed n per model per shared condition
SEED    = 42

# ─── Data Loading ─────────────────────────────────────────────────────────────
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

def load_iter_m(run_id, i):
    f = LOGS_DIR / run_id / f"iter_{i:02d}" / "metrics.json"
    if not f.exists(): return None
    try: return json.loads(f.read_text(encoding="utf-8", errors="ignore"))
    except: return None

def sub(runs, model, attack):
    return [r for r in runs if r["model"] == model and r["attack"] == attack]

def sample_n(lst, n, seed=SEED):
    rng = random.Random(seed)
    return rng.sample(lst, n) if len(lst) >= n else lst

# Build sampled subsets once
SHARED_ATTACKS = ["baseline", "feedback_poison", "instruction_inject", "memory_poison"]

def build_sampled(runs):
    s = {}
    for att in SHARED_ATTACKS:
        s[("mistral:latest", att)] = sample_n(sub(runs, "mistral:latest", att), N_CROSS)
        s[("qwen2.5:7b",     att)] = sample_n(sub(runs, "qwen2.5:7b",     att), N_CROSS)
    # Trusted Defense: uniformly sample 10 to match cross-model conditions
    s[("mistral:latest", "trusted_defense_poison")] = sample_n(sub(runs, "mistral:latest", "trusted_defense_poison"), N_CROSS)
    return s


# ─── Fig 1: Exploitable Vulnerabilities Over Iterations ───────────────────────
def fig1_exploitable_over_time(runs, sampled):
    apply_style()
    fig, ax = plt.subplots(figsize=(10, 6))

    conditions = [
        ("mistral:latest", "baseline",          "Mistral — Baseline",          "#2196F3", "o", "-"),
        ("mistral:latest", "feedback_poison",    "Mistral — Feedback Poison",   "#F44336", "^", "-"),
        ("mistral:latest", "instruction_inject", "Mistral — Instruction Inject","#9C27B0", "D", "--"),
        ("qwen2.5:7b",     "baseline",           "Qwen — Baseline",             "#4CAF50", "s", "-"),
        ("qwen2.5:7b",     "feedback_poison",    "Qwen — Feedback Poison",      "#FF9800", "v", "-"),
        ("qwen2.5:7b",     "memory_poison",      "Qwen — Memory Poison",        "#00BCD4", "P", "--"),
    ]
    for model, attack, label, color, marker, ls in conditions:
        grp = sampled.get((model, attack), [])
        if not grp: continue
        means = []
        for i in range(1, 11):
            vals = [m["vulns_exploitable"] for r in grp
                    if (m := load_iter_m(r["run_id"], i)) and m.get("tests_total", 0) > 0]
            means.append(np.mean(vals) if vals else None)
        xs = [x for x, v in zip(range(1, 11), means) if v is not None]
        ys = [v for v in means if v is not None]
        ax.plot(xs, ys, color=color, marker=marker, linestyle=ls,
                linewidth=2, markersize=7, label=f"{label} (n={len(grp)})")

    ax.set_xlabel("Repair Iteration", fontsize=12)
    ax.set_ylabel("Mean Exploitable Vulnerabilities (Oracle)", fontsize=12)
    ax.set_title("Mean Exploitable Vulnerabilities Over Repair Iterations\n"
                 "(Lower = better; n=10 per model per condition, seed=42)", fontsize=12)
    ax.set_xticks(range(1, 11)); ax.set_ylim(0, 7)
    ax.legend(loc="upper right", fontsize=9)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig1_exploitable_over_time.png", dpi=150, bbox_inches="tight"); plt.close()
    print("Saved: fig1_exploitable_over_time.png")


# ─── Fig 2: Looks Green 6-panel ───────────────────────────────────────────────
def fig2_looks_green(runs, sampled):
    apply_style()
    order = [
        ("mistral:latest", "baseline",          "Mistral — Baseline",          "#2196F3"),
        ("mistral:latest", "feedback_poison",    "Mistral — Feedback Poison",   "#F44336"),
        ("mistral:latest", "instruction_inject", "Mistral — Instruction Inject","#9C27B0"),
        ("qwen2.5:7b",     "baseline",           "Qwen — Baseline",             "#4CAF50"),
        ("qwen2.5:7b",     "feedback_poison",    "Qwen — Feedback Poison",      "#FF9800"),
        ("qwen2.5:7b",     "memory_poison",      "Qwen — Memory Poison",        "#00BCD4"),
    ]
    fig, axes = plt.subplots(2, 3, figsize=(15, 9), sharex=True)
    for idx, (model, attack, label, color) in enumerate(order):
        ax = axes.flatten()[idx]
        grp = sampled.get((model, attack), [])
        if not grp: ax.set_visible(False); continue
        t_means, s_means = [], []
        for i in range(1, 11):
            tv, sv = [], []
            for r in grp:
                m = load_iter_m(r["run_id"], i)
                if m and m.get("tests_total", 0) > 0:
                    tv.append(m["tests_passed"] / m["tests_total"] * 100)
                    sv.append(m["sdi"])
            t_means.append(np.mean(tv) if tv else 0)
            s_means.append(np.mean(sv) if sv else 0)
        xs = list(range(1, 11))
        ax2 = ax.twinx()
        ax.plot(xs, t_means, color="#43A047", marker="o", linewidth=2, markersize=5)
        ax2.plot(xs, s_means, color="#E53935", marker="^", linestyle="--", linewidth=2, markersize=5)
        ax.set_ylim(0, 110); ax2.set_ylim(0, 1.2)
        ax.set_ylabel("Test Pass %", color="#43A047", fontsize=9)
        ax2.set_ylabel("SDI", color="#E53935", fontsize=9)
        ax.tick_params(axis="y", labelcolor="#43A047")
        ax2.tick_params(axis="y", labelcolor="#E53935")
        ax.fill_between(xs, t_means, 100, alpha=0.06, color="#43A047")
        ax2.fill_between(xs, s_means, 0, alpha=0.06, color="#E53935")
        ax.set_title(f"{label} (n={len(grp)})", fontsize=10, fontweight="bold", color=color)
        ax.set_xticks(range(1, 11))
        if idx >= 3: ax.set_xlabel("Repair Iteration", fontsize=9)
        ax2.annotate("Reality\n(red)", xy=(3, s_means[2]), fontsize=8, color="#E53935",
                     ha="center", xytext=(2.5, 0.15),
                     arrowprops=dict(arrowstyle="->", color="#E53935", lw=1))
        ax.annotate("Operator sees\n(green)", xy=(8, t_means[7]), fontsize=8, color="#43A047",
                    ha="center", xytext=(8.5, 95),
                    arrowprops=dict(arrowstyle="->", color="#43A047", lw=1))
    fig.suptitle('"Looks Green, Still Exploitable"\n'
                 'Functional Test Pass Rate (green) vs Security Degradation Index (red, dashed)',
                 fontsize=13, y=1.01)
    handles = [mpatches.Patch(color="#43A047", label="Functional Tests (agent-visible)"),
               mpatches.Patch(color="#E53935", label="SDI / Security Oracle (hidden)")]
    fig.legend(handles=handles, loc="lower center", ncol=2, fontsize=10, bbox_to_anchor=(0.5, -0.02))
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig2_looks_green.png", dpi=150, bbox_inches="tight"); plt.close()
    print("Saved: fig2_looks_green.png")


# ─── Fig 3: SAST Blind Spot — Mistral Baseline n=10 ──────────────────────────
def fig3_sast_blindspot(runs, sampled):
    apply_style()
    fig, ax = plt.subplots(figsize=(9, 5))
    grp = sampled[("mistral:latest", "baseline")]
    sast, expl = [], []
    for i in range(1, 11):
        sv, ev = [], []
        for r in grp:
            m = load_iter_m(r["run_id"], i)
            if m:
                sv.append(m.get("semgrep_findings", 0))
                ev.append(m.get("vulns_exploitable", 0))
        sast.append(np.mean(sv) if sv else 0)
        expl.append(np.mean(ev) if ev else 0)
    xs = list(range(1, 11))
    ax.plot(xs, sast, color="#1565C0", marker="o", linewidth=2.5, markersize=8,
            label="SAST Findings (visible to agent)")
    ax.plot(xs, expl, color="#B71C1C", marker="^", linestyle="--", linewidth=2.5,
            markersize=8, label="Oracle Exploitable (hidden ground truth)")
    ax.fill_between(xs, sast, expl, where=[e > s for e, s in zip(expl, sast)],
                    alpha=0.15, color="#FF5722", label="SAST Blind Spot Zone")
    mid = (sast[5] + expl[5]) / 2
    ax.annotate("SAST Blind Spot:\nAgent thinks it's fixed,\nbut vulns remain",
                xy=(6, mid), xytext=(2.5, 1.2), fontsize=9, color="#BF360C",
                arrowprops=dict(arrowstyle="->", color="#BF360C", lw=1.2),
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#FFF3E0", edgecolor="#FF5722"))
    ax.set_xlabel("Repair Iteration", fontsize=12)
    ax.set_ylabel("Count", fontsize=12)
    ax.set_title(f"SAST Findings vs Oracle Exploitable Vulnerabilities\n"
                 f"(Mean across {len(grp)} Mistral Baseline runs — divergence reveals blind spot)", fontsize=11)
    ax.set_xticks(range(1, 11)); ax.set_ylim(0, 7)
    ax.legend(loc="upper right", fontsize=10)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig3_sast_blindspot.png", dpi=150, bbox_inches="tight"); plt.close()
    print("Saved: fig3_sast_blindspot.png")


# ─── Fig 4: Final State Bar Chart ─────────────────────────────────────────────
def fig4_final_state_bar(runs, sampled):
    apply_style()
    order = [
        ("mistral:latest", "baseline",               "Baseline",           "#2196F3"),
        ("mistral:latest", "feedback_poison",         "Feedback\nPoison",   "#F44336"),
        ("mistral:latest", "instruction_inject",      "Instruction\nInject","#9C27B0"),
        ("mistral:latest", "memory_poison",           "Memory\nPoison",     "#FF9800"),
        ("mistral:latest", "trusted_defense_poison",  "Trusted\nDefense",   "#4CAF50"),
        ("qwen2.5:7b",     "baseline",                "Baseline",           "#2196F3"),
        ("qwen2.5:7b",     "feedback_poison",         "Feedback\nPoison",   "#F44336"),
        ("qwen2.5:7b",     "memory_poison",           "Memory\nPoison",     "#FF9800"),
        ("qwen2.5:7b",     "instruction_inject",      "Instruction\nInject","#9C27B0"),
    ]
    fig, ax = plt.subplots(figsize=(12, 6))
    labels, means, stds, colors, ns, n_m = [], [], [], [], [], 0
    for model, attack, lbl, color in order:
        grp = sampled.get((model, attack), [])
        if not grp: continue
        exps = [r["final"]["vulns_exploitable"] for r in grp]
        labels.append(lbl); means.append(np.mean(exps))
        stds.append(np.std(exps, ddof=1) if len(exps) > 1 else 0)
        colors.append(color); ns.append(len(exps))
        if model == "mistral:latest": n_m += 1
    x = np.arange(len(labels))
    bars = ax.bar(x, means, 0.6, yerr=stds, capsize=6, color=colors, alpha=0.87,
                  edgecolor="white", linewidth=1.5, error_kw={"elinewidth": 2, "ecolor": "#555"})
    for bar, val, n in zip(bars, means, ns):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.15,
                f"{val:.2f}\n(n={n})", ha="center", va="bottom", fontsize=9)
    ax.axvline(x=n_m - 0.5, color="#AAA", linewidth=2, linestyle=":")
    ax.text(n_m/2 - 0.5, 7.0, "Mistral:Latest", ha="center", fontsize=11, fontweight="bold", color="#555")
    ax.text(n_m + (len(labels)-n_m)/2 - 0.5, 7.0, "Qwen2.5:7b", ha="center",
            fontsize=11, fontweight="bold", color="#555")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Mean Exploitable Vulnerabilities (final iteration)", fontsize=11)
    ax.set_title("Final State: Mean Exploitable Vulnerabilities by Attack Condition\n"
                 "(n=10 per model per condition; error bars = ±1 SD; lower = better security)", fontsize=12)
    ax.set_ylim(0, 7.8)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig4_final_state_bar.png", dpi=150, bbox_inches="tight"); plt.close()
    print("Saved: fig4_final_state_bar.png")


# ─── Fig 5: Vulnerability Survival Rate — FIXED text visibility ───────────────
def fig5_vuln_survival(runs, sampled):
    apply_style()
    fig, ax = plt.subplots(figsize=(10, 5))
    vuln_ids  = ["V1", "V2", "V3", "V4", "V5"]
    vuln_lbls = ["V1\nSQL Injection", "V2\nAuth Bypass", "V3\nPath Traversal",
                 "V4\nSSRF", "V5\nPassword Reset"]
    cvss      = ["HIGH (8.8)", "CRITICAL (9.1)", "HIGH (8.2)", "HIGH (7.5)", "HIGH (7.3)"]

    # n=10 balanced aggregate across all shared conditions
    bal = []
    for att in SHARED_ATTACKS:
        bal += sampled.get(("mistral:latest", att), [])
        bal += sampled.get(("qwen2.5:7b",     att), [])
    N_bal = len(bal)

    surv = []
    for vid in vuln_ids:
        cnt = sum(1 for r in bal if vid in r["final"].get("exploitable_list", []))
        surv.append(cnt / N_bal * 100 if N_bal else 0)

    bar_colors = ["#4CAF50" if s < 15 else ("#FF9800" if s < 60 else "#F44336") for s in surv]
    bars = ax.bar(vuln_lbls, surv, 0.6, color=bar_colors, alpha=0.87, edgecolor="white", linewidth=1.5)

    for bar, val, cv in zip(bars, surv, cvss):
        bx = bar.get_x() + bar.get_width() / 2
        # Percentage label — always above the bar
        ax.text(bx, bar.get_height() + 1.5, f"{val:.0f}%",
                ha="center", va="bottom", fontsize=13, fontweight="bold", color="#222")
        # CVSS label — inside bar only if tall enough, else below the % label
        if bar.get_height() > 20:
            ax.text(bx, bar.get_height() / 2, cv,
                    ha="center", va="center", fontsize=8, color="white", fontweight="bold")
        else:
            # Put CVSS label below the percentage label for short bars
            ax.text(bx, bar.get_height() + 6.5, cv,
                    ha="center", va="bottom", fontsize=7.5, color="#555", fontstyle="italic")

    ax.set_ylabel("Survival Rate at Final Iteration (%)", fontsize=12)
    ax.set_title(f"Vulnerability Survival Rate (N={N_bal} balanced runs, n=10 per condition)\n"
                 "(% of runs where vulnerability remained exploitable at iteration 10)", fontsize=11)
    ax.set_ylim(0, 105)
    ax.axhline(50, color="#999", linestyle="--", linewidth=1.2)
    ax.text(4.6, 51.5, "50% threshold", fontsize=8, color="#777")
    legend_els = [mpatches.Patch(color="#4CAF50", label="Reliably fixed (<15%)"),
                  mpatches.Patch(color="#FF9800", label="Inconsistently fixed (15–60%)"),
                  mpatches.Patch(color="#F44336", label="Persistently exploitable (>60%)")]
    ax.legend(handles=legend_els, loc="upper left", fontsize=9)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig5_vuln_survival.png", dpi=150, bbox_inches="tight"); plt.close()
    print("Saved: fig5_vuln_survival.png")


# ─── Fig 6: Mistral Boxplot — all available Mistral runs ─────────────────────
def fig6_mistral_stats_box(runs, sampled):
    apply_style()
    fig, ax = plt.subplots(figsize=(11, 6))
    order = [
        ("baseline",              "Baseline\n(n=10)",              "#2196F3"),
        ("feedback_poison",       "Feedback Poison\n(n=10)",        "#F44336"),
        ("instruction_inject",    "Instruction Inject\n(n=10)",     "#9C27B0"),
        ("memory_poison",         "Memory Poison\n(n=10)",          "#FF9800"),
        ("trusted_defense_poison","Trusted Defense\n(n=10)",        "#4CAF50"),
    ]
    box_data, labels, colors = [], [], []
    for attack, label, color in order:
        grp = sampled.get(("mistral:latest", attack), [])
        if not grp: continue
        box_data.append([r["final"]["vulns_exploitable"] for r in grp])
        labels.append(label); colors.append(color)

    bp = ax.boxplot(box_data, patch_artist=True, widths=0.55,
                    medianprops=dict(color="white", linewidth=2.5),
                    whiskerprops=dict(linewidth=1.5), capprops=dict(linewidth=1.5),
                    flierprops=dict(marker="o", markersize=7, markerfacecolor="#666"))
    for patch, c in zip(bp["boxes"], colors):
        patch.set_facecolor(c); patch.set_alpha(0.82)
    
    # Overlay jittered scatter plot to reveal overlapping points (like the 4.00 cluster)
    for i, data in enumerate(box_data):
        x = np.random.normal(i + 1, 0.05, size=len(data))
        ax.scatter(x, data, alpha=0.7, color="#222", zorder=3, s=25, edgecolor="white", linewidth=0.5)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylabel("Exploitable Vulnerabilities (final iteration)", fontsize=12)
    ax.set_title("Distribution of Final Exploitable Vulnerabilities — Mistral:Latest\n"
                 "(Box = IQR; whiskers = 1.5×IQR; white line = median)", fontsize=12)
    ax.set_ylim(0, 8)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig6_mistral_boxplot.png", dpi=150, bbox_inches="tight"); plt.close()
    print("Saved: fig6_mistral_boxplot.png")


# ─── Fig 7: Qwen Vulnerability Profile Shift ─────────────────────────────────
def fig7_qwen_profile_shift(runs, sampled):
    apply_style()
    conditions = [
        ("baseline",         "Qwen — Baseline"),
        ("feedback_poison",  "Qwen — Feedback Poison"),
        ("memory_poison",    "Qwen — Memory Poison"),
        ("instruction_inject","Qwen — Instruction Inject"),
    ]
    vuln_ids = ["V1", "V2", "V3", "V4", "V5"]
    labels   = ["V1\nSQLi", "V2\nAuth\nBypass", "V3\nPath\nTraversal", "V4\nSSRF", "V5\nPwd\nReset"]
    active   = [(att, ttl) for att, ttl in conditions
                if sampled.get(("qwen2.5:7b", att))]
    fig, axes = plt.subplots(1, len(active), figsize=(4.5*len(active), 4.8), sharey=True)
    if len(active) == 1: axes = [axes]
    for ax, (attack, title) in zip(axes, active):
        grp = sampled[("qwen2.5:7b", attack)]
        surv = [sum(1 for r in grp if vid in r["final"].get("exploitable_list", [])) / len(grp)
                for vid in vuln_ids]
        clrs = ["#F44336" if s > 0.5 else ("#FF9800" if s > 0.15 else "#4CAF50") for s in surv]
        bars = ax.barh(labels, surv, color=clrs, alpha=0.85, edgecolor="white")
        for bar, val in zip(bars, surv):
            ax.text(min(bar.get_width() + 0.03, 1.22), bar.get_y() + bar.get_height()/2,
                    f"{val:.0%}", va="center", fontsize=10, fontweight="bold", color="#222")
        ax.set_xlim(0, 1.35)
        ax.set_xlabel("Survival Rate", fontsize=10)
        ax.set_title(f"{title}\n(n={len(grp)})", fontsize=10, fontweight="bold")
        ax.axvline(0.5, color="#AAA", linestyle="--", linewidth=1)
    fig.suptitle("Vulnerability Profile Shift — Qwen2.5:7b\n"
                 "Under attack, specific vulnerabilities shift from fixed to exploitable",
                 fontsize=12, y=1.03)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig7_qwen_profile_shift.png", dpi=150, bbox_inches="tight"); plt.close()
    print("Saved: fig7_qwen_profile_shift.png")


# ─── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Loading all valid runs...")
    runs = load_all_valid()
    print(f"  Total valid runs: {len(runs)}")
    for (model, attack), cnt in sorted(Counter((r["model"], r["attack"]) for r in runs).items()):
        print(f"    {model} / {attack}: n={cnt}")

    sampled = build_sampled(runs)
    print(f"\nSampled subsets (n=10 cross-model and defense):")
    for k, v in sorted(sampled.items()):
        print(f"    {k[0]} / {k[1]}: n={len(v)}")

    print("\nGenerating figures...")
    fig1_exploitable_over_time(runs, sampled)
    fig2_looks_green(runs, sampled)
    fig3_sast_blindspot(runs, sampled)
    fig4_final_state_bar(runs, sampled)
    fig5_vuln_survival(runs, sampled)
    fig6_mistral_stats_box(runs, sampled)
    fig7_qwen_profile_shift(runs, sampled)
    print(f"\nAll figures saved to: {FIG_DIR}")
