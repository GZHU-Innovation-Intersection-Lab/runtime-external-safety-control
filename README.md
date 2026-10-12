# Runtime External Safety Control for Highly Autonomous AI

Reproducibility package for the manuscript **Runtime External Safety Control for Highly Autonomous Artificial Intelligence**.

本仓库公开论文的运行期控制原型、固定输入、逐试次结果、未见附件测试与本地效率基准，支持复核主结果、运行消融和重建执行轨迹。

The package supports reproducing the manuscript's local execution-control results, comparing the control configurations, and regenerating traces and outbox effects. All fixtures, attachment contents, addresses, and keys are synthetic test data. Measurements use a deterministic local filesystem sandbox.

## Contents

- `src/runtime_control_lab_v3.py` — deterministic local outbound-action prototype.
- `src/benchmark_runtime_control_v3.py` — repeated local efficiency benchmark.
- `src/holdout_object_mutation_v3.py` — 500 unseen attachment-byte holdout.
- `tools/verify_release.py` — release-file hashes and independent result aggregation.
- `data/lab_v3_run_20261009_final/` — 243 fixtures, 12 configurations, 2,916 trial records, summaries, and verification.
- `data/benchmark_v3_20261012_scale/` — 20 repetitions over 243 inputs and 5 configurations (24,300 local trials), including trial-level results, summaries, and semantic reproducibility digests.
- `data/holdout_v3_20261011_final/` — 500 unseen attachment-byte cases and summary.

The main run regenerates per-trial traces, outbox files, and minimal counterexamples. See [EVIDENCE.md](EVIDENCE.md) for measurement definitions and the relation between raw records and reported results.

## Reproduce

Run from the repository root with Python 3.12+ (tested with Python 3.12.7). Only the Python standard library is required.

```powershell
python -B tools/verify_release.py
python -B src/runtime_control_lab_v3.py --output output/lab_reproduce
python -B src/benchmark_runtime_control_v3.py --output output/benchmark_reproduce --repetitions 20
python -B src/holdout_object_mutation_v3.py --output output/holdout_reproduce
```

Each output directory must be new. The programs perform local file, JSON, HMAC, SHA-256, claim, and outbox operations. Runs create synthetic local effects; they need no network connection or online model.

## Fixed release evidence

- Main lab: 2,916 executions; target-boundary and integrated validation paths have zero violating trials and 33/33 legitimate fixtures completed and confirmed.
- Ablations: 32, 8, 52, 16, 8, 8, and 32 violating trials for object binding, policy isolation, path closure, revocation, claim deduplication, feedback state, and stop priority.
- Efficiency: 20 repetitions × 243 fixtures × 5 configurations = 24,300 local trials; semantic results are identical across repetitions. The release verifier also checks configuration labels.
- Attachment-byte holdout: 500 unseen byte strings; target-boundary and integrated paths produce zero unauthorized outbox effects, while the body-string-only path produces 500.

## Integrity hashes

`SHA256SUMS` fixes the bytes of every release file. `python -B tools/verify_release.py` verifies that manifest and independently checks the published result records. The original script hashes are also recorded in the experiment metadata. `.gitattributes` preserves those bytes across platforms.

The fixed release is tagged `v52-20261012`; cite that version when using its results. Runtime measurements will vary with the host; fixtures and semantic outcomes can be compared directly.

## License

Code is released under the MIT License. Experimental data, fixtures, summaries, and metadata are released under CC BY 4.0. See `LICENSE` and `DATA_LICENSE`.
