"""Repeated local efficiency benchmark for the v3 runtime-control prototype.

This benchmark measures the existing sandbox implementation only.  It does not
create network traffic, invoke an LLM, or simulate network latency.  Each trial
still performs the same JSON/HMAC/hash/claim/outbox operations as the v3 lab.
The benchmark keeps semantic results and timing measurements separate so timing
noise cannot change the safety conclusion.

Example:
    python -B benchmark_runtime_control_v3.py --output benchmark_20261011 --repetitions 5
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import platform
import statistics
import sys
from pathlib import Path
from time import perf_counter_ns, process_time_ns


HERE = Path(__file__).resolve().parent
LAB_PATH = HERE / "runtime_control_lab_v3.py"


def load_lab_module():
    spec = importlib.util.spec_from_file_location("runtime_control_lab_v3", LAB_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {LAB_PATH}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves postponed annotations through sys.modules while the
    # dynamically loaded lab module is being initialized.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def percentile(values: list[int], q: float) -> int:
    ordered = sorted(values)
    if not ordered:
        return 0
    index = min(len(ordered) - 1, max(0, int(q * (len(ordered) - 1))))
    return ordered[index]


def result_digest(rows: list[dict]) -> str:
    """Digest semantic fields only; timing is intentionally excluded."""
    keys = (
        "configuration",
        "fixture_id",
        "effects",
        "unauthorized_effects",
        "duplicate_effects",
        "business_completed",
        "confirmed_business_completed",
        "observation",
        "attempt_count",
    )
    payload = [tuple(row.get(key) for key in keys) for row in rows]
    return sha256_bytes(json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def run_trial(lab_module, fixture, config, root: Path):
    started_wall = perf_counter_ns()
    started_cpu = process_time_ns()
    lab = lab_module.Lab(fixture, config, root)
    row = lab.run()
    row.update(lab_module.Oracle().evaluate(fixture, lab.outbox))
    row["confirmed_business_completed"] = (
        row["business_completed"] and row["client_effect_confirmed"]
    )
    ended_cpu = process_time_ns()
    ended_wall = perf_counter_ns()
    row.update(
        benchmark_wall_ns=ended_wall - started_wall,
        benchmark_cpu_ns=ended_cpu - started_cpu,
    )
    return row


def summarize_rows(rows: list[dict], lab_module, selected_names: list[str]) -> list[dict]:
    result = []
    all_configs = {config.name: config for config in lab_module.configurations()}
    for config_name in selected_names:
        config = all_configs[config_name]
        part = [row for row in rows if row["config"] == config.name]
        wall = [row["benchmark_wall_ns"] for row in part]
        cpu = [row["benchmark_cpu_ns"] for row in part]
        operation = [row["measured_local_operation_ns"] for row in part]
        inner = [row["measured_trial_execution_ns"] for row in part]
        total_wall = sum(wall)
        total_cpu = sum(cpu)
        result.append(
            {
                "configuration": config.name,
                "trials": len(part),
                "repetitions": len({row["repetition"] for row in part}),
                "unauthorized_trials": sum(row["unauthorized_effects"] > 0 for row in part),
                "business_completions": sum(row["business_completed"] for row in part),
                "confirmed_business_completions": sum(
                    row["confirmed_business_completed"] for row in part
                ),
                "semantic_digest": result_digest(
                    [
                        {
                            "configuration": row["config"],
                            "fixture_id": row["fixture_id"],
                            **{key: row[key] for key in (
                                "effects",
                                "unauthorized_effects",
                                "duplicate_effects",
                                "business_completed",
                                "confirmed_business_completed",
                                "observation",
                                "attempt_count",
                            )},
                        }
                        for row in part
                    ]
                ),
                "wall_ms_mean": statistics.mean(wall) / 1e6,
                "wall_ms_median": statistics.median(wall) / 1e6,
                "wall_ms_p95": percentile(wall, 0.95) / 1e6,
                "cpu_ms_mean": statistics.mean(cpu) / 1e6,
                "cpu_ms_median": statistics.median(cpu) / 1e6,
                "cpu_ms_p95": percentile(cpu, 0.95) / 1e6,
                "cpu_batch_ms_per_trial_mean": statistics.mean(
                    row["batch_cpu_ns_per_trial"] for row in part
                )
                / 1e6,
                "wall_batch_ms_per_trial_mean": statistics.mean(
                    row["batch_wall_ns_per_trial"] for row in part
                )
                / 1e6,
                "inner_trial_ms_mean": statistics.mean(inner) / 1e6,
                "operation_ms_mean": statistics.mean(operation) / 1e6,
                "operation_ms_median": statistics.median(operation) / 1e6,
                "operation_ms_p95": percentile(operation, 0.95) / 1e6,
                "cpu_wall_ratio_mean": total_cpu / total_wall if total_wall else 0.0,
                "throughput_trials_per_s": len(part) / (total_wall / 1e9)
                if total_wall
                else 0.0,
            }
        )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument(
        "--configs",
        nargs="+",
        default=[
            "target_boundary",
            "robust_integrated_baseline",
            "content_body_only",
            "object_gateway_shared_credentials",
            "ablate_path_closure",
        ],
    )
    args = parser.parse_args()
    if args.repetitions < 2:
        raise SystemExit("--repetitions must be at least 2")
    output = args.output.resolve()
    if output.exists():
        raise SystemExit("Output must be a new directory; existing evidence is preserved.")
    output.mkdir(parents=True)

    lab_module = load_lab_module()
    all_configs = {config.name: config for config in lab_module.configurations()}
    missing = [name for name in args.configs if name not in all_configs]
    if missing:
        raise SystemExit(f"unknown configurations: {missing}")
    configs = [all_configs[name] for name in args.configs]
    fixtures = list(lab_module.fixtures())

    # One warm-up run reduces import and filesystem-cache effects in the first
    # recorded repetition. It is stored separately and never enters summaries.
    warmup_root = output / "warmup" / configs[0].name / fixtures[0].fixture_id
    run_trial(lab_module, fixtures[0], configs[0], warmup_root)

    rows: list[dict] = []
    for repetition in range(1, args.repetitions + 1):
        for config in configs:
            batch_wall_started = perf_counter_ns()
            batch_cpu_started = process_time_ns()
            config_rows = []
            for fixture in fixtures:
                root = output / "runs" / f"rep_{repetition:02d}" / config.name / fixture.fixture_id
                row = run_trial(lab_module, fixture, config, root)
                row["repetition"] = repetition
                config_rows.append(row)
            batch_wall_ns = perf_counter_ns() - batch_wall_started
            batch_cpu_ns = process_time_ns() - batch_cpu_started
            for row in config_rows:
                row["batch_wall_ns_per_trial"] = batch_wall_ns / len(config_rows)
                row["batch_cpu_ns_per_trial"] = batch_cpu_ns / len(config_rows)
                rows.append(row)

    # Per-repetition digests establish semantic reproducibility independent of
    # timing noise and preserve a checkable list for reviewers.
    repetition_digests = []
    for repetition in range(1, args.repetitions + 1):
        part = [row for row in rows if row["repetition"] == repetition]
        repetition_digests.append(
            {"repetition": repetition, "semantic_digest": result_digest(part)}
        )
    reproducible = len({item["semantic_digest"] for item in repetition_digests}) == 1

    summary = summarize_rows(rows, lab_module, args.configs)
    with (output / "raw_trials.jsonl").open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=summary[0].keys())
        writer.writeheader()
        writer.writerows(summary)
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (output / "reproducibility.json").write_text(
        json.dumps(
            {
                "repetitions": args.repetitions,
                "fixtures_per_configuration": len(fixtures),
                "configurations": args.configs,
                "reproducible_semantic_results": reproducible,
                "repetition_digests": repetition_digests,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    metadata = {
        "benchmark_script_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "lab_script_sha256": sha256_bytes(LAB_PATH.read_bytes()),
        "python": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "fixtures": len(fixtures),
        "configurations": args.configs,
        "repetitions": args.repetitions,
        "trials": len(rows),
        "timers": {
            "wall": "time.perf_counter_ns around local trial including sandbox setup, execution, and oracle evaluation",
            "cpu": "time.process_time_ns around the same local trial",
            "operation": "runtime_control_lab_v3 measured_local_operation_ns",
        },
        "scope": "local JSON/HMAC/SHA-256/claim/outbox prototype; no network, no LLM, no deployment",
        "simulated_ticks": "unchanged v3 discrete-event ticks; not elapsed wall time",
    }
    (output / "environment.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    markdown = [
        "# v3 local efficiency benchmark",
        "",
        f"Repeated {args.repetitions} times over {len(fixtures)} deterministic fixtures for each configuration.",
        "Wall and CPU values include local sandbox setup, execution and evaluation; operation values come from the v3 runtime's local operation timer.",
        "No network, LLM or production deployment timing is measured.",
        "",
        f"Semantic results reproducible across repetitions: **{reproducible}**.",
        "",
        "| configuration | wall median (ms) | wall p95 (ms) | CPU batch/trial (ms) | operation median (ms) | throughput (trials/s) | unauthorized trials |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for item in summary:
        markdown.append(
            "| {configuration} | {wall_ms_median:.3f} | {wall_ms_p95:.3f} | {cpu_batch_ms_per_trial_mean:.3f} | {operation_ms_median:.3f} | {throughput_trials_per_s:.1f} | {unauthorized_trials} |".format(
                **item
            )
        )
    markdown += [
        "",
        "Interpretation: these measurements compare implementation cost on the recorded host. They do not establish network latency, production throughput, or safety outside the fixed local fixture stream.",
    ]
    (output / "report.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {"output": str(output), "reproducible_semantic_results": reproducible, "summary": summary},
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
