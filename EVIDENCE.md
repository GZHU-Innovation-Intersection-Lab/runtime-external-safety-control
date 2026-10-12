# Evidence and measurement definitions

## Main experiment

The main experiment pairs 243 deterministic fixtures with 12 control configurations (2,916 executions). The fixtures combine object mutation, policy modification, direct-path access, revocation, retries, feedback loss, and stop timing. The oracle reads the fixed delegation and actual local outbox effects. A violating trial has at least one unauthorized effect; effect counts and trial counts are distinct.

Legitimate completion is evaluated on the 33 fixtures designated legitimate. Both target-boundary control and the integrated baseline complete and confirm all 33, with zero violating trials across their 243 fixtures. These results establish behavior under the released fixtures and execution semantics.

Running the main script regenerates the sandbox directories, actual outbox files, and minimal counterexamples. Those generated files are omitted from the archived data directory to keep the package compact.

## Unseen attachment bytes

The holdout generates 500 attachment byte strings not used by the main fixture construction and evaluates three configurations, producing 1,500 rows. Target-boundary and integrated control produce zero unauthorized outbox effects; body-only control produces 500. Holdout rows record byte hashes and observed effects.

## Local efficiency

The efficiency run repeats 243 fixtures over five configurations 20 times (24,300 trials). Trial wall time includes sandbox construction, execution, and oracle evaluation. Operation time covers the prototype's submit/effect operations. The implementation uses local JSON, HMAC, SHA-256, claim records, and filesystem outbox writes.

`throughput_trials_per_s` equals the trial count divided by the sum of individually measured trial wall times. Report generation and work between trial timers are outside that denominator. CPU batch time is recorded separately. This throughput therefore describes the timed trial stream on the recorded host.

Benchmark `business_completions` counts completion across all fixtures, including one case outside the main experiment's legitimate subset. Use the main experiment's `legitimate_completed` and `legitimate_confirmed` fields for the 33-fixture legitimate-task result.

The original benchmark's `result_digest()` selects a `configuration` field while its rows store the label as `config`. Its stored digests consequently verify the selected semantic fields and fixed row order, but omit the configuration label. The release verifier checks configuration coverage and computes a separate digest using the actual `config` field. Original sources and measurements retain their recorded hashes.

## Verification

`SHA256SUMS` records exact release-file bytes. The verifier checks these hashes, original script hashes, input/configuration coverage, summary aggregation, holdout effects, and repeated benchmark semantics. Timings are measured again during a rerun and are expected to differ between hosts and executions.

The release contains the three experiments used by the manuscript. All inputs and local effects are synthetic, including `.test` addresses and the public test signing key.
