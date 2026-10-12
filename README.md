# Runtime External Safety Control for Highly Autonomous AI

Reproducibility package for the manuscript **Runtime External Safety Control for Highly Autonomous Artificial Intelligence**.

This repository releases the deterministic local prototype, fixed inputs, raw trial-level results, holdout results, and repeated local efficiency measurements used in the manuscript. It is an evidence package for the stated execution semantics; it is not a production safety certification, a network-latency benchmark, or a claim about real-world incident rates.

## Contents

- `src/runtime_control_lab_v3.py` — deterministic local outbound-action prototype.
- `src/benchmark_runtime_control_v3.py` — repeated local efficiency benchmark.
- `src/holdout_object_mutation_v3.py` — 500 unseen attachment-byte holdout.
- `src/transfer_domain_check_v1.py` — separate code-deployment-like digital-write transfer check.
- `data/lab_v3_run_20261009_final/` — 243 fixtures, 12 configurations, 2,916 trial records, summaries, verification, and minimal counterexamples.
- `data/benchmark_v3_20261012_scale/` — 20 repetitions over 243 inputs and 5 configurations (24,300 local trials), including trial-level results, summaries, and semantic reproducibility digests.
- `data/holdout_v3_20261011_final/` — 500 unseen attachment-byte cases and summary.
- `data/transfer_domain_v1_20261012/` — 96 deterministic digital-write transfer checks and summary.

Per-trial sandbox traces and generated outbox files are intentionally not duplicated here. The released raw records, fixtures, configurations, code, hashes, and rerun commands are sufficient to regenerate them.

## Reproduce

Run from the repository root with Python 3.12+:

```powershell
python -B src/runtime_control_lab_v3.py --output output/lab_reproduce
python -B src/benchmark_runtime_control_v3.py --output output/benchmark_reproduce --repetitions 20
python -B src/holdout_object_mutation_v3.py --output output/holdout_reproduce
python -B src/transfer_domain_check_v1.py --output output/transfer_reproduce
```

Each output directory must be new. The programs perform local file, JSON, HMAC, SHA-256, claim, and outbox operations only. They do not access a network, call an online model, or send real mail/deployment actions.

## Fixed release evidence

- Main lab: 2,916 executions; target-boundary and integrated validation paths have zero violating trials and 33/33 legitimate fixtures completed and confirmed.
- Ablations: 32, 8, 52, 16, 8, 8, and 32 violating trials for object binding, policy isolation, path closure, revocation, claim deduplication, feedback state, and stop priority.
- Efficiency: 20 repetitions × 243 fixtures × 5 configurations = 24,300 local trials; semantic digests are identical across repetitions.
- Attachment-byte holdout: 500 unseen byte strings; target-boundary and integrated paths produce zero unauthorized outbox effects, while the body-string-only path produces 500.
- Transfer check: 48 cases per configuration over a code-deployment-like digital-write target; target-boundary produces zero unauthorized effects, operation-only control produces 66.

## Integrity hashes

The manuscript build report records the document and PDF hashes. Script hashes for this release are recorded in `data/*/environment.json` or `data/transfer_domain_v1_20261012/summary.json`.

## License

Code is released under the MIT License. Experimental result data and figures are released under CC BY 4.0. See `LICENSE` and `DATA_LICENSE`.
