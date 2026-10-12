# v52-20261012

Fixed code and data package for the manuscript's runtime-control experiments:

- 243 fixed inputs across 12 configurations: 2,916 executions with trial-level records and summaries.
- 500 unseen attachment byte strings across three configurations: 1,500 holdout rows.
- 20 local efficiency repetitions over 243 inputs and five configurations: 24,300 trial-level measurements.
- Standard-library reproduction scripts, MIT code license, and CC BY 4.0 experiment data.
- Exact-byte SHA-256 manifest and an independent verifier for raw aggregation, source hashes, configuration coverage, and repeated semantics.

The main run regenerates local traces, outbox effects, and minimal counterexamples. Measurement definitions are in EVIDENCE.md; reproduction commands are in README.md.
