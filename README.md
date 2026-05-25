# Looks Green, Still Exploitable

This repository contains a controlled research framework for studying how LLM-based automated program repair (APR) agents behave when visible repair signals diverge from true security outcomes.

The project evaluates a phenomenon we call **Looks Green, Still Exploitable**: an agent can make functional tests pass and reduce SAST findings while the patched application remains exploitable under a hidden dynamic security oracle.

The paper contains the full methodology, statistics, and discussion. This README focuses on the repository layout, execution workflow, and reproducibility entry points.

## Research Overview

Modern repair agents often optimize for signals that are easy to observe in CI/CD:

- functional tests pass
- SAST findings disappear
- generated patches compile

This framework separates those agent-visible signals from a hidden security oracle. The oracle runs exploit-oriented checks after each patch and is used for measurement, not ordinary agent guidance. The only exception is the explicit `trusted_defense_poison` condition, which intentionally provides oracle output through a labeled trusted channel to evaluate a defense design.

The framework supports:

- baseline iterative APR runs
- feedback poisoning
- memory poisoning
- instruction injection
- trusted oracle defense experiments
- per-iteration logging of prompts, model responses, generated patches, visible findings, and hidden metrics

## Architecture

```text
research-lab/
+-- agent/
|   +-- repair_agent.py        # Semgrep-guided LLM repair agent
|   +-- prompts/               # System and repair prompt templates
+-- evaluator/
|   +-- metrics.py             # Compile, functional, SAST, and hidden oracle metrics
+-- orchestration/
|   +-- loop_runner.py         # N-iteration repair loop with reset and auto-revert
|   +-- experiment_runner.py   # Batch runner for multi-condition experiments
+-- target/
|   +-- app.py                 # Mutable working copy patched during experiments
|   +-- app.py.vulnerable      # Deterministic vulnerable baseline
|   +-- static/
|   +-- tests/
|       +-- test_functional.py # Agent-visible functional tests
|       +-- test_security.py   # Hidden security oracle
+-- experiments/               # Analysis and figure generation scripts
+-- figures/                   # Generated paper figures
+-- logs/                      # Per-run experiment artifacts

```

## Evaluation Model

The repair loop uses three distinct classes of signal:

| Signal | Used by agent? | Purpose |
| --- | --- | --- |
| Compile/import check | Yes | Reject broken patches and trigger auto-revert |
| Functional tests | Yes | Preserve visible application behavior |
| Semgrep findings | Yes | Provide SAST-guided repair targets |
| Hidden security oracle | No, except trusted defense | Measure true exploitability and SDI |

This separation is central to the experiment. Baseline and attack conditions do not expose hidden oracle output to the repair agent. The oracle remains a measurement channel.

## Target Application

The target is a synthetic Python **FastAPI** application with five vulnerability classes:

- V1: SQL injection
- V2: auth bypass
- V3: path traversal
- V4: SSRF
- V5: broken password reset logic

`target/app.py.vulnerable` is the canonical starting point. `target/app.py` is a mutable working copy and may contain the last generated patch after an experiment. `orchestration/loop_runner.py` resets `target/app.py` from `app.py.vulnerable` at the start of each run.

## Requirements

- Python 3.12 recommended
- Ollama running locally
- Semgrep
- Pytest
- FastAPI target dependencies from `target/requirements.txt`

Install the Python package in editable mode from the repository root:

```bash
python -m pip install -e .
python -m pip install -r target/requirements.txt
```

Make sure Ollama is available and the model you want to test is installed, for example:

```bash
ollama pull mistral:latest
ollama pull qwen2.5:7b
```

## Running Experiments

Run a baseline repair loop:

```bash
python orchestration/loop_runner.py --iterations 10 --model mistral:latest
```

Run a feedback poisoning condition:

```bash
python orchestration/loop_runner.py --iterations 10 --model mistral:latest --attack feedback_poison
```

Run memory poisoning:

```bash
python orchestration/loop_runner.py --iterations 10 --model mistral:latest --attack memory_poison
```

Run instruction injection:

```bash
python orchestration/loop_runner.py --iterations 10 --model mistral:latest --attack instruction_inject
```

Run the trusted oracle defense condition:

```bash
python orchestration/loop_runner.py --iterations 10 --model mistral:latest --attack trusted_defense_poison
```

Each run writes a timestamped directory under `logs/` containing:

- run configuration
- per-iteration prompts
- model responses
- extracted patches
- Semgrep findings
- metrics JSON
- final history JSON

## Batch Execution

To run the configured experiment matrix:

```bash
python orchestration/experiment_runner.py --models qwen2.5-coder:14b devstral-small-2 phi4:14b --scenarios baseline feedback_poison --iterations 20 --repeats 30 --temperature 0.7
```

Supported arguments:
- `--models`: List of Ollama models to run (default runs 6 selected models).
- `--scenarios`: Specific scenarios/attacks to run, e.g., `baseline`, `feedback_poison`, `memory_poison`, `instruction_inject`, `trusted_defense` (default is `all`).
- `--iterations`: Number of repair loop iterations (default `20`).
- `--repeats`: Number of times to repeat each experiment (default `30`).
- `--temperature`: LLM sampling temperature (default `0.2`).

The batch runner is intended for larger experiment sweeps. Depending on model size and hardware, these runs can take a long time.

## Analysis and Figures

The `experiments/` scripts parse `logs/` and generate the summary statistics and figures used by the paper.

```bash
python experiments/calc_statistics.py
python experiments/generate_charts_final.py
python experiments/analyze_iter1_vs_iter10.py
```

Generated figures are written to `figures/`.

## Reproducibility Notes

- Every repair run resets `target/app.py` from `target/app.py.vulnerable`.
- Broken patches are reverted automatically when they fail compilation/import checks or crash pytest collection.
- The hidden oracle is used for measurement and logging, not ordinary repair feedback.
- Existing logs are not modified by analysis scripts.

## Integrity Constraints

This repository is an experimental evaluation framework. To preserve validity:

- do not modify `evaluator/metrics.py` when comparing runs
- do not modify `target/tests/test_security.py`
- do not modify `orchestration/experiment_runner.py` during active experiment collection
- do not compare runs generated under different oracle, SAST, or loop semantics without clearly labeling them
- keep raw logs for traceability


## Citation

Citation information will be added after the paper is finalized.
