"""Independently verify release bytes and published trial-level aggregates.

Run ``python -B tools/verify_release.py`` from any directory. The default is
read-only. ``--write-manifest`` explicitly writes SHA256SUMS before verification.
Only the Python standard library is used; experiment modules are not imported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import random
import re
import statistics
import sys


LAB = "data/lab_v3_run_20261009_final"
HOLDOUT = "data/holdout_v3_20261011_final"
BENCHMARK = "data/benchmark_v3_20261012_scale"
BENCHMARK_CONFIGS = [
    "target_boundary", "robust_integrated_baseline", "content_body_only",
    "object_gateway_shared_credentials", "ablate_path_closure",
]
SEMANTIC_FIELDS = (
    "effects", "unauthorized_effects", "duplicate_effects", "business_completed",
    "confirmed_business_completed", "observation", "attempt_count",
)
EXCLUDED_DIRECTORIES = {".git", "output", "__pycache__"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(root, relative):
    return json.loads((root / relative).read_text(encoding="utf-8"))


def read_rows(root, relative):
    return [json.loads(line) for line in
            (root / relative).read_text(encoding="utf-8").splitlines() if line]


def sha256(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def json_digest(value):
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


def labeled_semantic_digest(rows):
    """Include the actual raw-record config label, never a missing alias."""
    ordered = sorted(rows, key=lambda row: (row["config"], row["fixture_id"]))
    return json_digest([
        (row["config"], row["fixture_id"], *(row[key] for key in SEMANTIC_FIELDS))
        for row in ordered
    ])


def release_files(root):
    paths = []
    for directory, subdirectories, filenames in os.walk(root, followlinks=False):
        subdirectories[:] = [name for name in subdirectories
                             if name not in EXCLUDED_DIRECTORIES]
        for name in subdirectories:
            require(not (Path(directory) / name).is_symlink(),
                    f"Symlink directory is outside the release format: {name}")
        for name in filenames:
            if name == "SHA256SUMS" or name.endswith((".pyc", ".pyo", ".swp")):
                continue
            path = Path(directory) / name
            require(not path.is_symlink(), f"Symlink file is outside the release format: {name}")
            paths.append(path.relative_to(root).as_posix())
    return sorted(paths)


def write_manifest(root):
    content = "".join(f"{sha256(root / name)}  {name}\n" for name in release_files(root))
    (root / "SHA256SUMS").write_text(content, encoding="utf-8", newline="\n")


def verify_manifest(root):
    manifest = root / "SHA256SUMS"
    require(manifest.is_file(), "SHA256SUMS is missing; the release maintainer must create it.")
    expected = {}
    for number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-fA-F]{64})  (.+)", line)
        require(match is not None, f"Invalid SHA256SUMS line {number}")
        checksum, name = match.groups()
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts
                and "\\" not in name and ":" not in name and relative.as_posix() == name,
                f"Unsafe or noncanonical manifest path: {name}")
        require(name not in expected, f"Duplicate manifest path: {name}")
        expected[name] = checksum.lower()
    actual = release_files(root)
    require(set(actual) == set(expected),
            f"Manifest file set differs: missing={sorted(set(expected) - set(actual))}, "
            f"unlisted={sorted(set(actual) - set(expected))}")
    mismatches = [name for name in actual if sha256(root / name) != expected[name]]
    require(not mismatches, f"SHA-256 mismatch: {mismatches}")
    return {"files": len(actual), "all_file_bytes_match": True}


def verify_script_hash(root, source, recorded):
    require(sha256(root / source) == recorded, f"Recorded source hash differs: {source}")


def compare_fields(actual, expected, context):
    require(set(actual) == set(expected), f"Summary fields differ: {context}")
    for key, value in expected.items():
        found = actual[key]
        if isinstance(value, float):
            require(isinstance(found, (int, float)) and math.isfinite(found)
                    and math.isclose(found, value, rel_tol=1e-12, abs_tol=1e-12),
                    f"Summary value differs: {context}/{key}")
        else:
            require(found == value, f"Summary value differs: {context}/{key}")


def verify_lab(root):
    rows = read_rows(root, f"{LAB}/raw_trials.jsonl")
    fixtures_list = read_json(root, f"{LAB}/fixtures.json")
    fixtures = {item["fixture_id"]: item for item in fixtures_list}
    configs = [item["name"] for item in read_json(root, f"{LAB}/configurations.json")]
    require(len(fixtures_list) == len(fixtures) == 243, "Main lab must have 243 unique fixtures")
    require(len(configs) == len(set(configs)) == 12, "Main lab must have 12 unique configurations")
    keys = [(row["config"], row["fixture_id"]) for row in rows]
    expected_keys = {(config, fixture) for config in configs for fixture in fixtures}
    require(len(rows) == len(set(keys)) == 2916 and set(keys) == expected_keys,
            "Main lab must contain exactly 2,916 unique configuration/fixture pairs")
    stored = read_json(root, f"{LAB}/summary.json")
    require(len(stored) == 12 and [row["configuration"] for row in stored] == configs,
            "Main summary configuration coverage/order differs")
    for config, summary in zip(configs, stored):
        part = [row for row in rows if row["config"] == config]
        legitimate = [row for row in part if row["legitimate_business_fixture"]]
        unknown = [row for row in part if row["unknown_seen"]]
        bypass = [row for row in part if fixtures[row["fixture_id"]]["direct_bypass"]]
        latency = sorted(row["measured_local_operation_ns"] for row in part)
        computed = {
            "configuration": config, "trials": len(part),
            "trials_with_unauthorized_effect": sum(row["unauthorized_effects"] > 0 for row in part),
            "unauthorized_effects": sum(row["unauthorized_effects"] for row in part),
            "duplicate_effects": sum(row["duplicate_effects"] for row in part),
            "legitimate_fixtures": len(legitimate),
            "business_completions": sum(row["business_completed"] for row in legitimate),
            "confirmed_business_completions": sum(row["confirmed_business_completed"] for row in legitimate),
            "receipt_loss_fixture_inputs": sum(fixtures[row["fixture_id"]]["receipt_lost"] for row in part),
            "unknown_observations": len(unknown),
            "correct_unknown_handling": sum(row["unknown_handling_correct"] for row in unknown),
            "bypass_fixtures": len(bypass),
            "bypass_trials_with_unauthorized_effect": sum(row["unauthorized_effects"] > 0 for row in bypass),
            "local_operation_ns_median": latency[len(latency) // 2],
            "local_operation_ns_p95": latency[int(.95 * (len(latency) - 1))],
        }
        compare_fields(summary, computed, f"main/{config}")
        if config in {"target_boundary", "robust_integrated_baseline"}:
            require(computed["trials_with_unauthorized_effect"] == 0
                    and computed["confirmed_business_completions"] == 33,
                    f"Full-path safety/completion differs: {config}")
    environment = read_json(root, f"{LAB}/environment.json")
    require(environment["fixtures"] == 243 and environment["trials"] == 2916,
            "Main environment counts differ")
    verify_script_hash(root, "src/runtime_control_lab_v3.py", environment["script_sha256"])
    return {"trials": 2916, "unique_configuration_fixture_pairs": 2916,
            "summary_recomputed": True, "full_path_confirmed_legitimate_fixtures": 33}


def verify_holdout(root):
    rows = read_rows(root, f"{HOLDOUT}/rows.jsonl")
    summary = read_json(root, f"{HOLDOUT}/summary.json")
    configs = ["target_boundary", "robust_integrated_baseline", "content_body_only"]
    require(len(rows) == 1500 and summary["configurations"] == configs,
            "Holdout must have 1,500 rows across the three expected configurations")
    require(summary["seed"] == 20261011 and summary["cases_per_configuration"] == 500
            and summary["unseen_payloads"] == 500, "Holdout generation settings differ")
    rng = random.Random(20261011)
    payload_hashes = [hashlib.sha256(bytes(rng.randrange(256) for _ in range(16 + index % 31)))
                      .hexdigest() for index in range(500)]
    require(len(set(payload_hashes)) == 500, "Holdout generated payloads are not unique")
    effects = []
    for config, digest_key in zip(configs, ["target_semantics_digest", "integrated_semantics_digest", "weak_semantics_digest"]):
        part = [row for row in rows if row["configuration"] == config]
        require(len(part) == 500 and [row["index"] for row in part] == list(range(500)),
                f"Holdout index coverage/order differs: {config}")
        require([row["payload_sha256"] for row in part] == payload_hashes,
                f"Holdout payload hashes differ from fixed-seed generation: {config}")
        require(all(row["expected_unsafe"] is True for row in part),
                f"Holdout expected-unsafe flags differ: {config}")
        normalized = [{key: value for key, value in row.items() if key != "configuration"} for row in part]
        require(json_digest(normalized) == summary[digest_key], f"Holdout semantic digest differs: {config}")
        expected_effect = 1 if config == "content_body_only" else 0
        require(all(row["effects"] == expected_effect and row["accepted_attempts"] == expected_effect for row in part),
                f"Holdout effect/acceptance count differs: {config}")
        effects.append(sum(row["effects"] for row in part))
    require(effects == [summary["target_unauthorized_effects"], summary["integrated_unauthorized_effects"],
                        summary["weak_unauthorized_effects"]] == [0, 0, 500], "Holdout totals differ")
    verify_script_hash(root, "src/runtime_control_lab_v3.py", summary["lab_script_sha256"])
    verify_script_hash(root, "src/holdout_object_mutation_v3.py", summary["holdout_script_sha256"])
    return {"rows": 1500, "unique_payloads": 500, "unauthorized_effects": effects,
            "fixed_seed_bytes_and_semantic_digests_match": True}


def percentile(values, q):
    ordered = sorted(values)
    return ordered[int(q * (len(ordered) - 1))]


def benchmark_summary(part, config):
    wall = [row["benchmark_wall_ns"] for row in part]
    cpu = [row["benchmark_cpu_ns"] for row in part]
    operation = [row["measured_local_operation_ns"] for row in part]
    total_wall = sum(wall)
    result = {
        "configuration": config, "trials": len(part),
        "repetitions": len({row["repetition"] for row in part}),
        "unauthorized_trials": sum(row["unauthorized_effects"] > 0 for row in part),
        "business_completions": sum(row["business_completed"] for row in part),
        "confirmed_business_completions": sum(row["confirmed_business_completed"] for row in part),
        # Match the published per-configuration order and digest; labels are explicit.
        "semantic_digest": json_digest([(row["config"], row["fixture_id"],
                           *(row[key] for key in SEMANTIC_FIELDS)) for row in part]),
        "cpu_batch_ms_per_trial_mean": statistics.mean(row["batch_cpu_ns_per_trial"] for row in part) / 1e6,
        "wall_batch_ms_per_trial_mean": statistics.mean(row["batch_wall_ns_per_trial"] for row in part) / 1e6,
        "inner_trial_ms_mean": statistics.mean(row["measured_trial_execution_ns"] for row in part) / 1e6,
        "cpu_wall_ratio_mean": sum(cpu) / total_wall if total_wall else 0.0,
        "throughput_trials_per_s": len(part) / (total_wall / 1e9) if total_wall else 0.0,
    }
    for prefix, values in (("wall", wall), ("cpu", cpu), ("operation", operation)):
        result[f"{prefix}_ms_mean"] = statistics.mean(values) / 1e6
        result[f"{prefix}_ms_median"] = statistics.median(values) / 1e6
        result[f"{prefix}_ms_p95"] = percentile(values, .95) / 1e6
    return result


def verify_benchmark(root):
    rows = read_rows(root, f"{BENCHMARK}/raw_trials.jsonl")
    metadata = read_json(root, f"{BENCHMARK}/environment.json")
    reproduction = read_json(root, f"{BENCHMARK}/reproducibility.json")
    fixture_ids = {row["fixture_id"] for row in read_json(root, f"{LAB}/fixtures.json")}
    expected = {(rep, config, fixture) for rep in range(1, 21)
                for config in BENCHMARK_CONFIGS for fixture in fixture_ids}
    keys = [(row["repetition"], row["config"], row["fixture_id"]) for row in rows]
    require(len(rows) == len(set(keys)) == 24300 and set(keys) == expected,
            "Benchmark must contain 24,300 unique repetition/configuration/fixture triples")
    require(metadata["trials"] == 24300 and metadata["repetitions"] == 20
            and metadata["fixtures"] == 243 and metadata["configurations"] == BENCHMARK_CONFIGS,
            "Benchmark environment counts/configurations differ")
    require(reproduction["repetitions"] == 20 and reproduction["fixtures_per_configuration"] == 243
            and reproduction["configurations"] == BENCHMARK_CONFIGS
            and reproduction["reproducible_semantic_results"] is True,
            "Benchmark reproducibility metadata differs")
    verify_script_hash(root, "src/runtime_control_lab_v3.py", metadata["lab_script_sha256"])
    verify_script_hash(root, "src/benchmark_runtime_control_v3.py", metadata["benchmark_script_sha256"])
    summaries = read_json(root, f"{BENCHMARK}/summary.json")
    require(len(summaries) == 5 and [row["configuration"] for row in summaries] == BENCHMARK_CONFIGS,
            "Benchmark summary configuration coverage/order differs")
    for config, stored in zip(BENCHMARK_CONFIGS, summaries):
        part = [row for row in rows if row["config"] == config]
        compare_fields(stored, benchmark_summary(part, config), f"benchmark/{config}")
    labeled_digests = [labeled_semantic_digest([row for row in rows if row["repetition"] == rep])
                       for rep in range(1, 21)]
    require(len(set(labeled_digests)) == 1,
            "Benchmark config-labeled semantic results differ between repetitions")
    main_rows = read_rows(root, f"{LAB}/raw_trials.jsonl")
    main = {(row["config"], row["fixture_id"]): tuple(row[key] for key in SEMANTIC_FIELDS)
            for row in main_rows}
    require(all(tuple(row[key] for key in SEMANTIC_FIELDS) == main[(row["config"], row["fixture_id"])]
                for row in rows), "Benchmark semantic results differ from the fixed main lab")
    return {"trials": 24300, "repetitions": 20, "summary_recomputed": True,
            "config_labeled_semantics_identical": True,
            "config_labeled_semantic_sha256": labeled_digests[0],
            "matches_main_lab_semantics": True,
            "legacy_unlabeled_repetition_digest_used": False,
            "throughput_definition": "trials / sum(per-trial measured wall seconds)"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1],
                        help="Release repository root (default: this script's parent repository)")
    parser.add_argument("--write-manifest", action="store_true",
                        help="Explicitly create/replace SHA256SUMS, then verify the release")
    args = parser.parse_args()
    root = args.root.resolve()
    report = {"passed": False, "manifest_written": False, "checks": {}, "errors": []}
    if args.write_manifest:
        try:
            write_manifest(root)
            report["manifest_written"] = True
        except (OSError, ValueError) as error:
            report["errors"].append({"check": "write_manifest", "message": str(error)})
    for name, verify in (("file_integrity", verify_manifest), ("main_lab", verify_lab),
                         ("holdout", verify_holdout), ("efficiency", verify_benchmark)):
        try:
            report["checks"][name] = {"passed": True, **verify(root)}
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            report["checks"][name] = {"passed": False}
            report["errors"].append({"check": name, "message": str(error)})
    report["passed"] = not report["errors"]
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
