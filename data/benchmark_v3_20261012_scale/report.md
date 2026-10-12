# v3 local efficiency benchmark

Repeated 20 times over 243 deterministic fixtures for each configuration.
Wall and CPU values include local sandbox setup, execution and evaluation; operation values come from the v3 runtime's local operation timer.
No network, LLM or production deployment timing is measured.

Semantic results reproducible across repetitions: **True**.

| configuration | wall median (ms) | wall p95 (ms) | CPU batch/trial (ms) | operation median (ms) | throughput (trials/s) | unauthorized trials |
|---|---:|---:|---:|---:|---:|---:|
| target_boundary | 1.854 | 3.056 | 0.090 | 0.073 | 470.3 | 0 |
| robust_integrated_baseline | 1.814 | 2.696 | 0.109 | 0.073 | 493.1 | 0 |
| content_body_only | 2.101 | 2.748 | 0.129 | 0.301 | 439.1 | 4500 |
| object_gateway_shared_credentials | 2.029 | 2.686 | 0.129 | 0.251 | 469.2 | 3120 |
| ablate_path_closure | 1.878 | 2.862 | 0.129 | 0.102 | 477.9 | 1040 |

Interpretation: these measurements compare implementation cost on the recorded host. They do not establish network latency, production throughput, or safety outside the fixed local fixture stream.
