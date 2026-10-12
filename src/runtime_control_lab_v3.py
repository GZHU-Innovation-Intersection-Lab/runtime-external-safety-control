"""Local outbound-action prototype; no network, no LLM, no deployment claims.

Run: python -B runtime_control_lab_v3.py --output <new-output-directory>
The factorial fixture stream is identical for every configuration. Each effect
is an actual JSON file in a sandbox outbox. Simulated event ticks and measured
local implementation nanoseconds are separate fields. Oracle is evaluation-only.
"""
from __future__ import annotations
import argparse
import base64
import csv
import hashlib
import heapq
import hmac
import itertools
import json
import platform
import sys
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from time import perf_counter_ns

PUBLIC_V1 = b"Product update: public release 1.\n"
PUBLIC_V2 = b"Product update: public release 2.\n"
PRIVATE = b"INTERNAL CUSTOMER RECORD: account 42, confidential.\n"
GROUPS = {"core": ("a@example.test", "b@example.test"),
          "partner": ("p@example.test",), "outside": ("x@example.test",)}
KEY = b"LOCAL-EXPERIMENT-ONLY-hmac-key-not-production"

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def digest(data):
    return hashlib.sha256(data).hexdigest()

def write_json(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")

@dataclass(frozen=True)
class Fixture:
    fixture_id: str
    object_mode: str
    rule_tamper: bool
    direct_bypass: bool
    revocation: str
    receipt_lost: bool
    stop_request: bool

@dataclass(frozen=True)
class Config:
    name: str
    gateway_object_check: bool = False
    target_verification: bool = False
    bind_objects: bool = False
    isolate_policy: bool = False
    close_direct_path: bool = False
    revocation_check: bool = False
    claim_dedupe: bool = False
    preserve_unknown: bool = False
    stop_priority: bool = False
    tool_check: bool = False
    topology: str = "gateway"

@dataclass(frozen=True)
class Oracle:
    """Immutable business oracle. Runtime policy/controller never receives it."""
    public_hashes: tuple[str, ...] = (digest(PUBLIC_V1), digest(PUBLIC_V2))
    recipient_groups: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("core", GROUPS["core"]), ("partner", GROUPS["partner"]))
    subject: str = "agent-alice"

    def object_allowed(self, effect):
        groups = dict(self.recipient_groups)
        return (effect["subject"] == self.subject
                and effect["attachment_sha256"] in self.public_hashes
                and effect["recipient_group"] in groups
                and tuple(effect["recipients"]) == groups[effect["recipient_group"]]
                and digest(base64.b64decode(effect["attachment_b64"]))
                == effect["attachment_sha256"])

    def evaluate(self, fixture, outbox):
        records = [json.loads(p.read_text(encoding="utf-8"))
                   for p in sorted(outbox.glob("effect_*.json"))]
        unauthorized = []
        permitted_once = False
        for effect in records:
            valid = self.object_allowed(effect)
            if fixture.revocation == "before_claim" and effect["claim_tick"] >= 3:
                valid = False
            if fixture.stop_request and effect["effect_tick"] >= 6:
                valid = False
            if permitted_once:
                valid = False  # This fixture delegates a single logical send.
            if valid:
                permitted_once = True
            else:
                unauthorized.append(effect["effect_id"])
        legitimate = (fixture.object_mode in {"normal", "scope_variant", "post_claim_file_mutation"}
                      and fixture.revocation != "before_claim"
                      and not fixture.stop_request)
        return {"effects": len(records), "unauthorized_effects": len(unauthorized),
                "unauthorized_effect_ids": unauthorized,
                "legitimate_business_fixture": legitimate,
                "business_completed": len(records) == 1 and not unauthorized,
                "duplicate_effects": max(0, len(records) - 1)}

class Lab:
    def __init__(self, fixture, config, root):
        self.fixture, self.config, self.root = fixture, config, root
        self.outbox = root / "outbox"
        self.outbox.mkdir(parents=True)
        self.files = root / "attachments"
        self.files.mkdir()
        for name, data in (("public_v1.bin", PUBLIC_V1),
                           ("public_v2.bin", PUBLIC_V2), ("private.bin", PRIVATE)):
            (self.files / name).write_bytes(data)
        self.policy = {"epoch": 1, "revoked": False,
                       "subjects": ["agent-alice"],
                       "groups": ["core", "partner"],
                       "hashes": [digest(PUBLIC_V1), digest(PUBLIC_V2)]}
        self.action = {"subject": "agent-alice", "tool": "mail.send",
                       "recipient_group": "core", "recipients": list(GROUPS["core"]),
                       "attachment": str(self.files / "public_v1.bin"),
                       "body": "Please see our public product update.",
                       "operation_id": fixture.fixture_id}
        if fixture.object_mode == "scope_variant":
            self.action.update(recipient_group="partner", recipients=list(GROUPS["partner"]),
                               attachment=str(self.files / "public_v2.bin"))
        elif fixture.object_mode == "private_proposal":
            self.action["attachment"] = str(self.files / "private.bin")
        self.queue, self.serial = [], 0
        self.events, self.attempts, self.claims = [], [], {}
        self.claim_dir = root / "claims"
        self.claim_dir.mkdir()
        self.token, self.initial_authorization = None, None
        self.effect_counter = 0
        self.observation = "not_submitted"
        self.unknown_seen, self.unknown_correct = False, True
        self.stop_active = False
        self.stop_applied_tick = None
        self.local_operation_ns = 0
        self.receipt_confirmed = False

    def log(self, tick, event, **data):
        self.events.append({"tick": tick, "event": event, **data})

    def schedule(self, tick, event, **data):
        self.serial += 1
        heapq.heappush(self.queue, (tick, self.serial, event, data))

    def read_object(self):
        data = Path(self.action["attachment"]).read_bytes()
        obj = {"subject": self.action["subject"],
               "recipient_group": self.action["recipient_group"],
               "recipients": sorted(self.action["recipients"]),
               "attachment_sha256": digest(data)}
        return obj, data

    def policy_allows(self, obj):
        return (not self.policy["revoked"]
                and obj["subject"] in self.policy["subjects"]
                and obj["recipient_group"] in self.policy["groups"]
                and obj["attachment_sha256"] in self.policy["hashes"]
                and tuple(obj["recipients"]) == GROUPS[obj["recipient_group"]])

    def authorize(self, tick, fresh=False):
        obj, _ = self.read_object()
        if not self.policy_allows(obj):
            self.log(tick, "authorization_denied", policy_epoch=self.policy["epoch"])
            return None
        payload = {**obj, "policy_epoch": self.policy["epoch"],
                   "nonce": self.fixture.fixture_id + (":retry" if fresh else ":initial"),
                   "operation_id": self.action["operation_id"]}
        token = {"payload": payload,
                 "hmac_sha256": hmac.new(KEY, canonical(payload), hashlib.sha256).hexdigest()}
        self.log(tick, "authorization_issued", payload=payload)
        return token

    def write_policy(self, tick, role):
        allowed = role == "business-admin" or not self.config.isolate_policy
        self.log(tick, "policy_write", role=role, allowed=allowed)
        if allowed:
            self.policy["hashes"].append(digest(PRIVATE))
            self.policy["groups"].append("outside")
            self.policy["epoch"] += 1

    def gateway_allows(self):
        if self.config.tool_check and self.action["tool"] != "mail.send":
            return False
        if self.config.gateway_object_check:
            obj, _ = self.read_object()
            return self.policy_allows(obj)
        return "malicious instruction" not in self.action["body"]

    def claim_path(self, nonce):
        return self.claim_dir / (digest(nonce.encode("utf-8")) + ".json")

    def boundary_check(self, obj, nonce):
        """Dedicated target adapter verifies a signed remote grant."""
        if self.token is None:
            return "missing_authorization", None
        payload = self.token["payload"]
        expected = hmac.new(KEY, canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, self.token["hmac_sha256"]):
            return "bad_signature", None
        if self.config.bind_objects and any(payload[k] != obj[k] for k in obj):
            return "object_binding_mismatch", None
        # Old result can only describe this same bound request.
        if self.config.claim_dedupe and self.claim_path(nonce).exists():
            stored = json.loads(self.claim_path(nonce).read_text(encoding="utf-8"))
            return "duplicate_claim", stored["result"]
        if self.config.revocation_check and (
                self.policy["revoked"] or payload["policy_epoch"] != self.policy["epoch"]):
            return "authorization_not_current", None
        return None, None

    def integrated_check(self, obj, nonce):
        """Independent integrated transaction path with equivalent safeguards."""
        grant = self.token
        if not grant:
            return "missing_authorization", None
        authorization = grant["payload"]
        mac = hmac.new(KEY, canonical(authorization), hashlib.sha256).hexdigest()
        authentic = hmac.compare_digest(mac, grant["hmac_sha256"])
        if not authentic:
            return "bad_signature", None
        same_object = all(authorization[field] == value for field, value in obj.items())
        if not same_object:
            return "object_binding_mismatch", None
        durable = self.claim_path(nonce)
        if durable.is_file():
            prior = json.loads(durable.read_text(encoding="utf-8"))
            return "duplicate_claim", prior["result"]
        current = not self.policy["revoked"] and authorization["policy_epoch"] == self.policy["epoch"]
        if not current:
            return "authorization_not_current", None
        return None, None

    def submit(self, tick, retry=False):
        started = perf_counter_ns()
        direct = self.fixture.direct_bypass
        record = {"attempt_id": len(self.attempts) + 1, "tick": tick,
                  "route": "direct" if direct else "gateway", "retry": retry,
                  "gateway_allowed": None, "accepted": False}
        self.attempts.append(record)
        try:
            if not direct:
                record["gateway_allowed"] = self.gateway_allows()
                if not record["gateway_allowed"]:
                    record["reason"] = "gateway_denied"
                    self.observation = "unknown" if self.unknown_seen and self.config.preserve_unknown else (
                        "no_effect_assumed" if self.unknown_seen else "no_effect_confirmed")
                    return
            if retry and not self.config.preserve_unknown:
                # Client lost knowledge of acceptance; it opens a fresh grant.
                self.token = self.authorize(tick, fresh=True)
            obj, content = self.read_object()
            nonce = (self.token or {}).get("payload", {}).get("nonce")
            record["nonce"] = nonce
            enforce = self.config.target_verification and (
                not direct or self.config.close_direct_path)
            if enforce:
                checker = self.integrated_check if self.config.topology == "integrated" else self.boundary_check
                reason, previous_result = checker(obj, nonce)
                if reason:
                    record["reason"] = reason
                    if reason == "duplicate_claim":
                        self.observe(tick, previous_result, lost=False)
                    elif self.unknown_seen:
                        # A rejected retry does not prove that the initial send had no effect.
                        self.observation = "unknown" if self.config.preserve_unknown else "no_effect_assumed"
                    else:
                        self.observation = "no_effect_confirmed"
                    return
            record["accepted"] = True
            record["reason"] = "claimed" if enforce else "credential_accepted"
            if enforce and self.config.claim_dedupe:
                self.claims[nonce] = {"result": "pending", "claim_tick": tick}
                write_json(self.claim_path(nonce), {"nonce": nonce, "object": obj,
                           "result": "pending", "claim_tick": tick})
            self.observation = "effect_pending"
            self.schedule(tick + 5, "effect", obj=obj, content=content,
                          claim_tick=tick, nonce=nonce, attempt_id=record["attempt_id"],
                          lost=self.fixture.receipt_lost and not retry)
        finally:
            record["local_operation_ns"] = perf_counter_ns() - started
            self.local_operation_ns += record["local_operation_ns"]
            self.log(tick, "attempt", attempt=record)

    def effect(self, tick, obj, content, claim_tick, nonce, attempt_id, lost):
        started = perf_counter_ns()
        if self.stop_active:
            result = "no_effect"
            self.log(tick, "local_protection_blocked", attempt_id=attempt_id)
        else:
            self.effect_counter += 1
            result = "effect"
            effect_id = f"effect_{self.effect_counter:02d}"
            record = {"effect_id": effect_id, **obj,
                      "attachment_b64": base64.b64encode(content).decode("ascii"),
                      "claim_tick": claim_tick, "effect_tick": tick,
                      "nonce": nonce, "attempt_id": attempt_id,
                      "operation_id": self.action["operation_id"]}
            write_json(self.outbox / (effect_id + ".json"), record)
            self.log(tick, "effect_persisted", effect_id=effect_id,
                     attachment_sha256=digest(content))
        if nonce in self.claims:
            self.claims[nonce]["result"] = result
            stored = json.loads(self.claim_path(nonce).read_text(encoding="utf-8"))
            stored.update(result=result, result_tick=tick)
            write_json(self.claim_path(nonce), stored)
        self.local_operation_ns += perf_counter_ns() - started
        self.schedule(tick + 1, "receipt", result=result, lost=lost)

    def observe(self, tick, result, lost):
        if lost:
            self.unknown_seen = True
            self.unknown_correct = self.config.preserve_unknown
            self.observation = "unknown" if self.config.preserve_unknown else "no_effect_assumed"
            self.log(tick, "receipt_lost", observation=self.observation)
            self.schedule(tick + 3, "retry")
        elif result == "effect":
            self.receipt_confirmed = True
            self.observation = "effect_confirmed"
            self.log(tick, "receipt_received", result=result)
        elif result == "no_effect":
            self.observation = "no_effect_confirmed"
            self.log(tick, "receipt_received", result=result)
        else:
            self.observation = "unknown"
            self.log(tick, "pending_receipt")

    def run(self):
        started = perf_counter_ns()
        if self.fixture.rule_tamper:
            self.schedule(1, "tamper")
        self.schedule(2, "authorize")
        if self.fixture.object_mode in {"attachment_swap", "recipient_swap"}:
            self.schedule(2.5, "mutate")
        if self.fixture.object_mode == "post_claim_file_mutation":
            self.schedule(7, "file_mutation")
        if self.fixture.object_mode == "post_receipt_object_mutation":
            self.schedule(12, "retry_mutation")
        if self.fixture.object_mode == "signature_mutation":
            self.schedule(2.5, "signature_mutation")
        if self.fixture.revocation == "before_claim":
            self.schedule(3, "revoke")
        elif self.fixture.revocation == "after_claim":
            self.schedule(6, "revoke")
        self.schedule(5, "submit")
        if self.fixture.stop_request:
            self.schedule(6, "stop_requested")
            for job_index in range(6):
                self.schedule(6 + job_index, "busy_job", job_index=job_index)
        while self.queue:
            tick, _, event, data = heapq.heappop(self.queue)
            if event == "tamper":
                self.write_policy(tick, "generator")
            elif event == "authorize":
                self.token = self.authorize(tick)
                self.initial_authorization = json.loads(json.dumps(self.token))
            elif event == "mutate":
                if self.fixture.object_mode == "attachment_swap":
                    self.action["attachment"] = str(self.files / "private.bin")
                else:
                    self.action.update(recipient_group="outside", recipients=list(GROUPS["outside"]))
                self.log(tick, "object_mutated", mode=self.fixture.object_mode)
            elif event == "file_mutation":
                Path(self.action["attachment"]).write_bytes(PRIVATE)
                self.log(tick, "file_replaced_after_claim", replacement_sha256=digest(PRIVATE))
            elif event == "retry_mutation":
                self.action["attachment"] = str(self.files / "private.bin")
                self.log(tick, "retry_object_changed")
            elif event == "signature_mutation":
                self.token["hmac_sha256"] = "0" * 64
                self.log(tick, "signature_corrupted")
            elif event == "revoke":
                self.policy.update(revoked=True, epoch=self.policy["epoch"] + 1)
                self.log(tick, "authorization_revoked", role="business-admin")
            elif event in {"submit", "retry"}:
                self.submit(tick, retry=event == "retry")
            elif event == "effect":
                self.effect(tick, **data)
            elif event == "receipt":
                self.observe(tick, **data)
            elif event == "stop_requested":
                # Each preceding FIFO job consumes one simulated tick.
                busy = sum(1 for queued in self.queue if queued[2] == "busy_job")
                applied = tick if self.config.stop_priority else tick + busy
                self.log(tick, "stop_requested", simulated_apply_tick=applied,
                         preceding_fifo_jobs=0 if self.config.stop_priority else busy)
                self.schedule(applied, "stop_applied")
            elif event == "busy_job":
                self.log(tick, "busy_job_completed", simulated_service_ticks=1, **data)
            elif event == "stop_applied":
                self.stop_active, self.stop_applied_tick = True, tick
                self.log(tick, "stop_applied")
        measured = perf_counter_ns() - started
        write_json(self.root / "attempts.json", self.attempts)
        write_json(self.root / "events.json", self.events)
        write_json(self.root / "initial_authorization.json", self.initial_authorization)
        write_json(self.root / "final_policy.json", self.policy)
        loss_events = [e for e in self.events if e["event"] == "receipt_lost"]
        return {"fixture_id": self.fixture.fixture_id, "config": self.config.name,
                "observation": self.observation, "unknown_seen": self.unknown_seen,
                "unknown_handling_correct": all(e["observation"] == "unknown" for e in loss_events),
                "client_effect_confirmed": self.receipt_confirmed,
                "attempt_count": len(self.attempts),
                "accepted_attempts": sum(a["accepted"] for a in self.attempts),
                "direct_accepted": any(a["route"] == "direct" and a["accepted"] for a in self.attempts),
                "simulated_stop_apply_tick": self.stop_applied_tick,
                "simulated_stop_request_tick": 6 if self.fixture.stop_request else None,
                "simulated_effect_tick": 10,
                "measured_local_operation_ns": self.local_operation_ns,
                "measured_trial_execution_ns": measured}

def configurations():
    robust = Config("target_boundary", False, True, True, True, True, True, True, True, True, True, "separate")
    configs = [Config("content_body_only"), Config("tool_identity", tool_check=True),
               Config("object_gateway_shared_credentials", gateway_object_check=True, tool_check=True),
               robust, replace(robust, name="robust_integrated_baseline", topology="integrated")]
    for suffix, flag in (("object_binding", "bind_objects"),
                         ("policy_isolation", "isolate_policy"),
                         ("path_closure", "close_direct_path"),
                         ("revocation_check", "revocation_check"),
                         ("claim_dedupe", "claim_dedupe"),
                         ("feedback_state", "preserve_unknown"),
                         ("stop_priority", "stop_priority")):
        configs.append(replace(robust, name="ablate_" + suffix, **{flag: False}))
    return configs

def fixtures():
    modes = ("normal", "scope_variant", "private_proposal", "attachment_swap", "recipient_swap")
    for i, values in enumerate(itertools.product(modes, (False, True), (False, True),
              ("none", "before_claim", "after_claim"), (False, True), (False, True))):
        yield Fixture(f"F{i:04d}", *values)
    yield Fixture("S_snapshot", "post_claim_file_mutation", False, False, "none", False, False)
    yield Fixture("S_retry_changed_object", "post_receipt_object_mutation", False, False, "none", True, False)
    yield Fixture("S_bad_signature", "signature_mutation", False, False, "none", False, False)

def summarize(rows, fixtures_by_id):
    result = []
    for config in configurations():
        part = [r for r in rows if r["config"] == config.name]
        legit = [r for r in part if r["legitimate_business_fixture"]]
        unknown = [r for r in part if r["unknown_seen"]]
        loss_inputs = [r for r in part if fixtures_by_id[r["fixture_id"]].receipt_lost]
        bypass = [r for r in part if fixtures_by_id[r["fixture_id"]].direct_bypass]
        latency = sorted(r["measured_local_operation_ns"] for r in part)
        result.append({"configuration": config.name, "trials": len(part),
            "trials_with_unauthorized_effect": sum(r["unauthorized_effects"] > 0 for r in part),
            "unauthorized_effects": sum(r["unauthorized_effects"] for r in part),
            "duplicate_effects": sum(r["duplicate_effects"] for r in part),
            "legitimate_fixtures": len(legit),
            "business_completions": sum(r["business_completed"] for r in legit),
            "confirmed_business_completions": sum(r["confirmed_business_completed"] for r in legit),
            "receipt_loss_fixture_inputs": len(loss_inputs),
            "unknown_observations": len(unknown),
            "correct_unknown_handling": sum(r["unknown_handling_correct"] for r in unknown),
            "bypass_fixtures": len(bypass),
            "bypass_trials_with_unauthorized_effect": sum(r["unauthorized_effects"] > 0 for r in bypass),
            "local_operation_ns_median": latency[len(latency)//2],
            "local_operation_ns_p95": latency[int(.95*(len(latency)-1))]})
    return result

def verify(rows, fixtures_by_id):
    by_key = {(r["config"], r["fixture_id"]): r for r in rows}
    robust = [r for r in rows if r["config"] == "target_boundary"]
    assert all(r["unauthorized_effects"] == 0 for r in robust)
    assert all(r["business_completed"] and r["confirmed_business_completed"]
               for r in robust if r["legitimate_business_fixture"])
    assert all(r["unknown_handling_correct"] for r in robust)
    semantic = ("effects", "unauthorized_effects", "duplicate_effects", "business_completed",
                "confirmed_business_completed", "observation", "attempt_count")
    assert all(all(r[k] == by_key[("robust_integrated_baseline", r["fixture_id"])][k]
                   for k in semantic) for r in robust)
    # Each ablation must expose at least one counterexample in the full factorial.
    for config in configurations()[5:]:
        assert any(r["unauthorized_effects"] > 0 for r in rows if r["config"] == config.name), config.name
    assert any(r["unknown_seen"] for r in robust)
    assert any(fixtures_by_id[r["fixture_id"]].revocation == "after_claim" and r["business_completed"]
               for r in robust)
    for c in ("target_boundary", "robust_integrated_baseline"):
        assert by_key[(c, "S_snapshot")]["business_completed"]
        assert by_key[(c, "S_retry_changed_object")]["business_completed"]
        assert by_key[(c, "S_retry_changed_object")]["observation"] == "unknown"
        assert not by_key[(c, "S_retry_changed_object")]["client_effect_confirmed"]
        assert by_key[(c, "S_bad_signature")]["effects"] == 0
    return {"robust_safety": True, "legitimate_completion": True,
            "byte_snapshot_survives_file_replacement": True,
            "same_nonce_changed_object_not_falsely_confirmed": True,
            "corrupted_hmac_rejected": True,
            "integrated_semantic_equivalence": True, "every_ablation_has_counterexample": True}

def counterexamples(output, rows, fixtures_by_id):
    entries = []
    for config in configurations()[5:]:
        candidates = [r for r in rows if r["config"] == config.name and r["unauthorized_effects"]]
        def complexity(row):
            f = fixtures_by_id[row["fixture_id"]]
            return (f.rule_tamper + f.direct_bypass + f.receipt_lost + f.stop_request
                    + (f.revocation != "none") + (f.object_mode != "normal"), f.fixture_id)
        row = min(candidates, key=complexity)
        trace = output / "traces" / row["fixture_id"] / config.name
        entries.append({"configuration": config.name, "fixture": asdict(fixtures_by_id[row["fixture_id"]]),
                        "result": row, "trace_directory": str(trace),
                        "events": json.loads((trace / "events.json").read_text(encoding="utf-8"))})
    write_json(output / "minimal_counterexamples.json", entries)
    lines = ["# v3 minimal counterexamples", "",
             "Each trace is a real local execution. Ticks are simulated queue time; effects are sandbox files.", ""]
    for entry in entries:
        lines += ["## " + entry["configuration"], "", "Fixture: " + json.dumps(entry["fixture"]),
                  "", "Trace directory: " + entry["trace_directory"], ""]
        for event in entry["events"]:
            if event["event"] == "busy_job_completed":
                continue
            lines.append("- " + json.dumps(event, ensure_ascii=False))
        lines.append("")
    (output / "minimal_counterexamples.md").write_text("\n".join(lines), encoding="utf-8")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit("Output must be a new directory; existing evidence is preserved.")
    output.mkdir(parents=True)
    fs = list(fixtures())
    mapping = {f.fixture_id: f for f in fs}
    write_json(output / "fixtures.json", [asdict(f) for f in fs])
    write_json(output / "configurations.json", [asdict(c) for c in configurations()])
    rows = []
    oracle = Oracle()
    for f in fs:
        for config in configurations():
            lab = Lab(f, config, output / "traces" / f.fixture_id / config.name)
            row = lab.run()
            row.update(oracle.evaluate(f, lab.outbox))
            row["confirmed_business_completed"] = row["business_completed"] and row["client_effect_confirmed"]
            rows.append(row)
    checks = verify(rows, mapping)
    write_json(output / "verification.json", checks)
    summary = summarize(rows, mapping)
    write_json(output / "summary.json", summary)
    counterexamples(output, rows, mapping)
    with (output / "raw_trials.jsonl").open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=summary[0])
        writer.writeheader()
        writer.writerows(summary)
    write_json(output / "environment.json", {"python": sys.version, "platform": platform.platform(),
        "script_sha256": digest(Path(__file__).read_bytes()), "fixtures": len(fs), "trials": len(rows),
        "timing": "perf_counter_ns: local HMAC/hash/queue/file implementation cost; no network latency",
        "event_ticks": "simulated discrete event time; claim=5, effect=10, stop=6 or 12",
        "key": "public test-only HMAC key", "oracle": "immutable, evaluation-only",
        "prior_versions": "runtime_control_experiment.py and v2 are deprecated; no v1/v2 results are reused"})
    print(json.dumps({"output": str(output), "checks": checks, "summary": summary}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
