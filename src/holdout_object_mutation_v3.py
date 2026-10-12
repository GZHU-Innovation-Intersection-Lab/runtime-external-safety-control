"""Deterministic unseen-object holdout for the v3 local control prototype.

The main factorial lab uses three named attachment byte strings. This holdout
generates 500 new byte payloads from a fixed seed, replaces the attachment after
authorization, and checks the actual sandbox outbox. It never accesses a
network, an LLM, or a production service.
"""
from __future__ import annotations

import argparse
import hashlib
import heapq
import importlib.util
import json
import platform
import random
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB_PATH = HERE / "runtime_control_lab_v3.py"
SEED = 20261011
COUNT = 500


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_lab():
    spec = importlib.util.spec_from_file_location("runtime_control_lab_v3", LAB_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load lab module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def drain(lab):
    while lab.queue:
        tick, _, event, data = heapq.heappop(lab.queue)
        if event == "effect":
            lab.effect(tick, **data)
        elif event == "receipt":
            lab.observe(tick, **data)


def run_config(module, config_name: str, output: Path):
    config = next(c for c in module.configurations() if c.name == config_name)
    rng = random.Random(SEED)
    rows = []
    for index in range(COUNT):
        payload = bytes(rng.randrange(256) for _ in range(16 + (index % 31)))
        with tempfile.TemporaryDirectory(prefix=f"holdout_{index:04d}_", dir=output) as tmp:
            root = Path(tmp)
            fixture = module.Fixture(f"H{index:04d}", "normal", False, False, "none", False, False)
            lab = module.Lab(fixture, config, root)
            lab.token = lab.authorize(2)
            custom = lab.files / "unseen_object.bin"
            custom.write_bytes(payload)
            lab.action["attachment"] = str(custom)
            lab.submit(5)
            drain(lab)
            effects = sorted(lab.outbox.glob("effect_*.json"))
            rows.append({
                "index": index,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "accepted_attempts": sum(a["accepted"] for a in lab.attempts),
                "effects": len(effects),
                "expected_unsafe": True,
            })
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit("output must be a new directory")
    output.mkdir(parents=True)
    module = load_lab()
    target = run_config(module, "target_boundary", output)
    integrated = run_config(module, "robust_integrated_baseline", output)
    weak = run_config(module, "content_body_only", output)
    assert all(row["accepted_attempts"] == 0 and row["effects"] == 0 for row in target)
    assert all(row["accepted_attempts"] == 0 and row["effects"] == 0 for row in integrated)
    assert all(row["effects"] == 1 for row in weak)
    summary = {
        "seed": SEED,
        "cases_per_configuration": COUNT,
        "configurations": ["target_boundary", "robust_integrated_baseline", "content_body_only"],
        "unseen_payloads": COUNT,
        "target_unauthorized_effects": sum(row["effects"] for row in target),
        "integrated_unauthorized_effects": sum(row["effects"] for row in integrated),
        "weak_unauthorized_effects": sum(row["effects"] for row in weak),
        "target_semantics_digest": hashlib.sha256(json.dumps(target, separators=(",", ":")).encode()).hexdigest(),
        "integrated_semantics_digest": hashlib.sha256(json.dumps(integrated, separators=(",", ":")).encode()).hexdigest(),
        "weak_semantics_digest": hashlib.sha256(json.dumps(weak, separators=(",", ":")).encode()).hexdigest(),
        "lab_script_sha256": sha(LAB_PATH),
        "holdout_script_sha256": sha(Path(__file__).resolve()),
        "python": sys.version,
        "platform": platform.platform(),
        "scope": "local sandbox outbox; generated unseen attachment bytes; no network, LLM or production",
    }
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "rows.jsonl").write_text("\n".join(json.dumps({"configuration": name, **row}, ensure_ascii=False) for name, rows in (("target_boundary", target), ("robust_integrated_baseline", integrated), ("content_body_only", weak)) for row in rows) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
