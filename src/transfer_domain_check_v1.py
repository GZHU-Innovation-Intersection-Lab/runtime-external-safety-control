"""Cross-domain transfer check for the runtime-control criteria.

This is a deterministic local check over a code-deployment-like digital write
target.  It reuses the criteria (object binding, current authority, and target
claim deduplication) with different action fields from the mail-dispatch lab.
It does not invoke a compiler, cluster, network, or production deployment.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import itertools
import json
import platform
import sys
from pathlib import Path

KEY = b"TRANSFER-CHECK-ONLY-key"
SAFE = b"artifact-safe-v1"
UNSAFE = b"artifact-private-debug"


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sign(payload):
    return hmac.new(KEY, canonical(payload), hashlib.sha256).hexdigest()


def cases():
    for i, (artifact_swap, env_swap, revoked, retry) in enumerate(
        itertools.product((False, True), (False, True), (False, True), (False, True))
    ):
        # Repeat each semantic case at three independent operation ids.
        for repeat in range(3):
            yield {
                "case_id": f"D{i:02d}_{repeat}",
                "artifact_swap": artifact_swap,
                "env_swap": env_swap,
                "revoked": revoked,
                "retry": retry,
            }


def run(case, robust, root):
    root.mkdir(parents=True, exist_ok=True)
    artifact = UNSAFE if case["artifact_swap"] else SAFE
    environment = "prod" if case["env_swap"] else "staging"
    allowed_hash = digest(SAFE)
    allowed_env = "staging"
    payload = {
        "subject": "deploy-bot",
        "artifact_sha256": digest(SAFE),
        "environment": allowed_env,
        "operation_id": case["case_id"],
        "nonce": case["case_id"] + ":initial",
    }
    grant = {"payload": payload, "hmac_sha256": sign(payload)}
    effects = []
    attempts = 2 if case["retry"] else 1
    current = not case["revoked"]
    for attempt in range(attempts):
        if robust:
            obj = {"artifact_sha256": digest(artifact), "environment": environment}
            valid = (
                hmac.compare_digest(sign(grant["payload"]), grant["hmac_sha256"])
                and grant["payload"]["artifact_sha256"] == obj["artifact_sha256"]
                and grant["payload"]["environment"] == obj["environment"]
                and current
                and attempt == 0
            )
        else:
            valid = True
        if valid:
            effects.append({"attempt": attempt, "artifact_sha256": digest(artifact), "environment": environment})
    unauthorized = 0
    for effect in effects:
        valid = effect["artifact_sha256"] == allowed_hash and effect["environment"] == allowed_env
        if len(effects) > 1 or not valid:
            unauthorized += 1
    result = {
        **case,
        "configuration": "target_boundary" if robust else "operation_only",
        "effects": len(effects),
        "unauthorized_effects": unauthorized,
        "semantic": [len(effects), unauthorized],
    }
    (root / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit("Output must be a new directory")
    output.mkdir(parents=True)
    all_rows = []
    for case in cases():
        for robust in (True, False):
            all_rows.append(run(case, robust, output / ("target_boundary" if robust else "operation_only") / case["case_id"]))
    target = [r for r in all_rows if r["configuration"] == "target_boundary"]
    weak = [r for r in all_rows if r["configuration"] == "operation_only"]
    summary = {
        "domain": "code_deployment_like_digital_write",
        "cases_per_configuration": len(target),
        "total_trials": len(all_rows),
        "target_unauthorized_trials": sum(r["unauthorized_effects"] > 0 for r in target),
        "target_unauthorized_effects": sum(r["unauthorized_effects"] for r in target),
        "operation_only_unauthorized_trials": sum(r["unauthorized_effects"] > 0 for r in weak),
        "operation_only_unauthorized_effects": sum(r["unauthorized_effects"] for r in weak),
        "target_semantic_digest": hashlib.sha256(json.dumps([r["semantic"] for r in target], separators=(",", ":")).encode()).hexdigest(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python": sys.version,
        "platform": platform.platform(),
        "scope": "deterministic local digital-write check; no compiler, cluster, network, or production deployment",
    }
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "raw_results.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in all_rows) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
