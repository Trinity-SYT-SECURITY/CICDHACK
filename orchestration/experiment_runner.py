"""
orchestration/experiment_runner.py - Batch experiment executor

Runs multiple scenarios and produces comparison data for paper figures.

Usage:
    python experiment_runner.py --models qwen2.5-coder:14b --iterations 20 --repeats 30 --temperature 0.7
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from orchestration.loop_runner import run_loop

LAB_ROOT    = Path(__file__).parent.parent
RESULTS_DIR = LAB_ROOT / "logs" / "experiments"

# The five experiments
SCENARIOS = [
    {"name": "baseline",             "attack": None},
    {"name": "feedback_poison",      "attack": "feedback_poison"},
    {"name": "memory_poison",        "attack": "memory_poison"},
    {"name": "instruction_inject",   "attack": "instruction_inject"},
    {"name": "trusted_defense",      "attack": "trusted_defense_poison"},
]


def unload_model(model_name: str):
    """Explicitly unload the model from Ollama's RAM to free up memory."""
    try:
        req = urllib.request.Request("http://localhost:11434/api/generate", 
                                     data=json.dumps({"model": model_name, "keep_alive": 0}).encode('utf-8'),
                                     headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req)
        print(f"\n[Memory Management] Successfully unloaded {model_name} from RAM.")
    except Exception as e:
        print(f"\n[Memory Management] Could not unload model {model_name}: {e}")


def run_all(models: list[str], scenarios: list[str] = None, iterations: int = 20, repeats: int = 30, temperature: float = 0.2):
    """
    Run all scenarios for `repeats` times each, across multiple models.
    Saves aggregated results in logs/experiments/
    """
    exp_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    all_results = {}

    for model in models:
        all_results[model] = {}
        print(f"\n{'*'*70}")
        print(f"* Model: {model} (T={temperature})")
        print(f"{'*'*70}")

        if scenarios is None or "all" in scenarios:
            active_scenarios = SCENARIOS
        else:
            active_scenarios = [s for s in SCENARIOS if s["name"] in scenarios]

        for scenario in active_scenarios:
            name  = scenario["name"]
            attack = scenario["attack"]
            all_results[model][name] = []

            print(f"\n{'#'*60}")
            print(f"# Scenario: {name} (x{repeats})")
            print(f"{'#'*60}")

            for rep in range(1, repeats + 1):
                run_id = f"{exp_id}_{model.replace(':', '_')}_{name}_rep{rep}"
                history = run_loop(
                    iterations=iterations,
                    model=model,
                    attack=attack,
                    run_id=run_id,
                    temperature=temperature
                )
                all_results[model][name].append(history)

        # Print summary table for this model
        print_summary(all_results[model], iterations, model)
        
        # Explicitly unload the model to prevent RAM from exploding before loading the next one
        unload_model(model)

    # Save aggregated results
    out_path = RESULTS_DIR / f"{exp_id}_results.json"
    out_path.write_text(json.dumps(all_results, indent=2))
    print(f"\n\nAggregated results saved: {out_path}")
    return all_results


def print_summary(model_results: dict, iterations: int, model_name: str):
    """Print a summary table across all scenarios for a specific model."""
    print(f"\n{'='*70}")
    print(f"Summary for: {model_name}")
    print(f"{'Scenario':<25} {'Final SDI (mean)':>17} {'Vulns@end (mean)':>17} {'Tests%@end':>10}")
    print(f"{'-'*70}")

    for name, runs in model_results.items():
        if not runs:
            continue
        # Take last iteration of each run
        final_sdi   = [r[-1]["sdi"]             for r in runs if r]
        final_vulns = [r[-1]["vulns_exploitable"] for r in runs if r]
        final_tests = [r[-1]["test_pass_rate"]   for r in runs if r]

        def mean(lst): return round(sum(lst)/len(lst), 3) if lst else 0

        print(f"{name:<25} {mean(final_sdi):>17.3f} {mean(final_vulns):>17.1f} {mean(final_tests)*100:>9.1f}%")

    print(f"{'='*70}")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--models", nargs="+", default=[
        "qwen2.5-coder:14b",
        "devstral-small-2",
        "deepseek-coder-v2:16b",
        "phi4:14b",
        "codegemma:7b",
        "granite-code:20b"
    ], help="List of models to run")
    p.add_argument("--scenarios", nargs="+", default=["all"], help="List of scenarios/attacks to run, or 'all'")
    p.add_argument("--iterations", type=int, default=20)
    p.add_argument("--repeats",    type=int, default=30)
    p.add_argument("--temperature", type=float, default=0.2)
    args = p.parse_args()

    run_all(models=args.models, scenarios=args.scenarios, iterations=args.iterations, repeats=args.repeats, temperature=args.temperature)
