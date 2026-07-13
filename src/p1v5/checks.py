"""Machine predicates v5.2. Deep cross-field validation on top of Draft-7,
by-construction score independence, pinned G9a evidence, chained attestation."""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from .config import (MANIFEST_PATH, ROOT, ManifestError, display_yaml_in_sync,
                     get_config, load_manifest, manifest_sha256)

TRUSTED_ROOT_PATH = ROOT.parent / "phase_b2/09_p1_proposal/p1_v5_trusted_root.txt"
ATTESTATION_ANCHOR_PATH = ROOT.parent / "phase_b2/09_p1_proposal/p1_v5_attestation_anchor.txt"
LOCK_PATH = ROOT / "locks/artifact.lock.json"
# N9-R2: the lock is an INPUT lock. Generated evidence/results are explicitly
# excluded, so producing evidence never invalidates the lock it must bind to —
# the round-9 self-reference loop is structurally gone. Evidence integrity is
# instead recorded in the release attestation (gate_runner --release).
INVENTORY_EXCLUDE = ("build/", "locks/", "evidence/", "data/", "__pycache__",
                     ".pytest_cache", ".git")

CANONICAL_GATES = ["G9a", "G0", "G1", "G2", "G3", "G4", "G5a", "G5b", "G6",
                   "G7a", "G7b", "G8", "G9b", "G10", "LOCK", "FREEZE"]

# N9-R1: the FULL gate specification is a versioned code constant. deep_validate
# compares the manifest against every field of this table; renaming, remapping a
# predicate, editing a dependency edge, or moving an evidence path is a G0 FAIL.
# Dependency-set semantics: UNORDERED set equality.
GATE_SPEC_VERSION = "gate-spec-1"
CANONICAL_GATE_SPEC = {
    "G9a":    {"predicate": "check_g9a_search_protocol", "depends_on": set(), "evidence_path": None},
    "G0":     {"predicate": "check_g0_manifest", "depends_on": {"G9a"}, "evidence_path": None},
    "G1":     {"predicate": "check_g1_estimators", "depends_on": {"G0"}, "evidence_path": None},
    "G2":     {"predicate": "check_g2_invariance", "depends_on": {"G1"}, "evidence_path": None},
    "G3":     {"predicate": "check_g3_clocks", "depends_on": {"G2"}, "evidence_path": None},
    "G8":     {"predicate": "evidence_gate", "depends_on": {"G2"}, "evidence_path": "evidence/g8_rights_matrix.json"},
    "G4":     {"predicate": "evidence_gate", "depends_on": {"G3"}, "evidence_path": "evidence/g4_replay_route.json"},
    "G10":    {"predicate": "check_g10_placebos", "depends_on": {"G3"}, "evidence_path": None},
    "G7a":    {"predicate": "evidence_gate", "depends_on": {"G3"}, "evidence_path": "evidence/g7a_cost_micropilot.json"},
    "G5a":    {"predicate": "evidence_gate", "depends_on": {"G4", "G10", "G7a"}, "evidence_path": "evidence/g5a_yield_audit.json"},
    "G6":     {"predicate": "evidence_gate", "depends_on": {"G5a"}, "evidence_path": "evidence/g6_power_type1_sim.json"},
    "G5b":    {"predicate": "evidence_gate", "depends_on": {"G6"}, "evidence_path": "evidence/g5b_calendar_feasibility.json"},
    "G7b":    {"predicate": "evidence_gate", "depends_on": {"G6"}, "evidence_path": "evidence/g7b_full_budget_bom.json"},
    "G9b":    {"predicate": "evidence_gate", "depends_on": {"G5b", "G7b"}, "evidence_path": "evidence/g9b_final_search.json"},
    "LOCK":   {"predicate": "check_lock_artifacts", "depends_on": {"G9b", "G8"}, "evidence_path": None},
    "FREEZE": {"predicate": "check_freeze_preconditions", "depends_on": {"LOCK"}, "evidence_path": None},
}

# N9-R1: the paper's co-primary contrasts are pinned as code constants.
CANONICAL_COPRIMARY = [
    {"id": "C1", "arm_a": "diff_agent_credit", "arm_b": "shared_surplus"},
    {"id": "C2", "arm_a": "c3_action", "arm_b": "c3_compute_matched_sham"},
]
CANONICAL_ARMS = ["no_update", "shared_surplus", "diff_agent_credit",
                  "c3_action", "c3_compute_matched_sham"]
CANONICAL_BRANCHES = ["meaningful_benefit", "practical_equivalence",
                      "meaningful_harm", "inconclusive"]
CANONICAL_CLOCK_FIELDS = ["rules_version", "rules_effective_at", "trading_state",
                          "oracle_round", "oracle_status", "terminal_outcome_kind",
                          "source_published_at", "source_retrieved_at",
                          "prediction_cutoff", "outcome_public_time", "forecast_at",
                          "finalized_at", "observed_at", "applied_at",
                          "prompt_state_cutoff"]
CANONICAL_PLACEBO = ["c3_compute_matched_sham_arm", "planted_oracle_fixtures",
                     "settlement_batch_label_permutation_offline"]

# typed FROZEN values (r8 finding #3: FROZEN + garbage must be rejected)
FROZEN_TYPES = {
    "estimand.assignment.trajectories_per_arm_K": ("int_ge", 2),
    "estimand.population_frame.inclusion_rulebook": ("str", 8),
    "estimand.endpoint.horizon_T": ("int_ge", 1),
    "estimand.endpoint.label_follow_up_days": ("int_ge", 1),
    "estimand.contrasts.smallest_worthwhile_effect": ("pos_number", 0),
    "theory_h3.artifact": ("str", 8),
}

EXTERNAL_PINS = {
    "polymarket_terms": {
        "path": "../phase_b2/05_rights/polymarket_terms_2026-07-06/polymarket_terms_raw.txt",
        "sha256": "27828b629e92eef373a9d2d91a29c349053f8a5b4cd102995a1396d3de04efd0"},
    "v4_frozen_spec": {
        "path": "../phase_b2/09_p1_proposal/p1_v4_spec.yaml",
        "sha256": "84e0e9251aa03d640a205403d9d9b30a19647735c40ec11de43b15fc53b666c8"},
    "r7_failed_baseline": {
        "path": "../archive/p1_v5_r7_failed_baseline.tar.gz",
        "sha256": "80a43d1879359a85afa20f428d88fdeecca2300881fc44f3b64dfc1d6e398013"},
    "r9_failed_baseline_v52": {
        "path": "../archive/p1_v5_r9_failed_baseline_v52.tar.gz",
        "sha256": "be5258021685f99f00022833e2801fd6bc454d924c557dbfe3e1474d135a3329"},
}

# G9a evidence pins (r8 finding #9: content swap must break the gate)
G9A_EVIDENCE_PINS = {
    "credit_priors_verification.md": "913fb36b9ae99db4287b2188a1a584d62f96a1e226b682e6cbe24cfe8c0ec8d9",
    "round3_novelty_verification.md": "ba97dc64ce84140fcec8f71405c4b71aca5268123c29433ff4b817bca94e89a7",
    "round4_novelty_verification.md": "eff8369cacccab8b64c40ca23095054ae1042dbfce8aea27f7c200bea3b10cfc",
    "round5_novelty_verification.md": "a854a009bc60aac633170ac7bc892d1e60fd7ae00123741cb7eb70cce53baa5d",
    "round6_novelty_verification.md": "09fee6b8d6db68c4764384be79a249f842398ce6a4a5a206e31ef950aaa5583d",
}


def repo_inventory() -> dict:
    files = {}
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(ROOT))
        if any(rel.startswith(x) or f"/{x}" in rel for x in INVENTORY_EXCLUDE):
            continue
        files[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return files


# ---------------------------------------------------------------------------
# Deep cross-field validation (shared by G0 and by the mutant tests)
# ---------------------------------------------------------------------------

def deep_validate(m) -> list:
    """Returns list of violations (empty = clean). Assumes Draft-7 already passed
    or is being run on a candidate; every rule here is cross-field semantics that
    Draft-7 cannot express."""
    v = []
    gate_ids = [g.get("id") for g in m.get("gates", [])]
    if sorted(gate_ids) != sorted(CANONICAL_GATES):
        v.append(f"gate id set != canonical 16 (got {sorted(set(gate_ids))}, dupes={len(gate_ids)-len(set(gate_ids))})")
    else:
        # N9-R1: exact per-gate semantics, not just the label set
        for g in m["gates"]:
            spec = CANONICAL_GATE_SPEC[g["id"]]
            if g.get("predicate") != spec["predicate"]:
                v.append(f"gate {g['id']}: predicate {g.get('predicate')} != canonical {spec['predicate']}")
            if set(g.get("depends_on", [])) != spec["depends_on"]:
                v.append(f"gate {g['id']}: depends_on {sorted(g.get('depends_on', []))} != canonical {sorted(spec['depends_on'])}")
            if g.get("evidence_path") != spec["evidence_path"]:
                v.append(f"gate {g['id']}: evidence_path {g.get('evidence_path')} != canonical {spec['evidence_path']}")
    arm_ids = [a.get("id") for a in m.get("arms", [])]
    if sorted(arm_ids) != sorted(CANONICAL_ARMS):
        v.append(f"arm id set != canonical 5: {arm_ids}")
    cop = m.get("estimand", {}).get("contrasts", {}).get("coprimary", [])
    # N9-R1: exact contrast->arm-pair mapping is pinned
    if sorted(cop, key=lambda c: str(c.get("id"))) != CANONICAL_COPRIMARY:
        v.append(f"coprimary contrasts != canonical pinned pairs: {cop}")
    # N9-R5: budget and reporting domain must be finite with sane relations
    import math
    for cap in ("llm_usd", "overflow_eur"):
        val = m.get("budget", {}).get(cap, {}).get("value")
        if not (isinstance(val, (int, float)) and not isinstance(val, bool)
                and math.isfinite(val) and 0 < val < 1e9):
            v.append(f"budget.{cap}.value must be finite in (0, 1e9): {val!r}")
    dom = m.get("score_invariance", {}).get("admissible_domain", {})
    a_max, b_min, b_max = dom.get("a_abs_max"), dom.get("b_min"), dom.get("b_max")
    if not all(isinstance(x, (int, float)) and math.isfinite(x) and x > 0
               for x in (a_max, b_min, b_max)) or not (b_min <= b_max):
        v.append(f"admissible_domain must be finite, positive, b_min<=b_max: {dom}")
    if m.get("estimand", {}).get("decision_rule", {}).get("branches") != CANONICAL_BRANCHES:
        v.append("decision branches != canonical four-way list")
    if m.get("clocks", {}).get("fields") != CANONICAL_CLOCK_FIELDS:
        v.append("clock fields != canonical 15-field list")
    if m.get("placebo_suite", {}).get("components") != CANONICAL_PLACEBO:
        v.append("placebo components != canonical 3-component list")

    def get_path(root, dotted):
        cur = root
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur
    for path, (kind, arg) in FROZEN_TYPES.items():
        node = get_path(m, path)
        if not isinstance(node, dict):
            v.append(f"{path}: missing pending_or_frozen node")
            continue
        if node.get("status") == "FROZEN":
            val = node.get("value")
            if kind == "int_ge" and not (isinstance(val, int) and not isinstance(val, bool) and val >= arg):
                v.append(f"{path}: FROZEN value must be int >= {arg}, got {val!r}")
            if kind == "pos_number" and not (isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0):
                v.append(f"{path}: FROZEN value must be positive number, got {val!r}")
            if kind == "str" and not (isinstance(val, str) and len(val) >= arg):
                v.append(f"{path}: FROZEN value must be str(len>={arg}), got {val!r}")
    return v


def check_g0_manifest():
    ev = {}
    try:
        m, raw = load_manifest(validate=True)
    except ManifestError as e:
        return False, {"schema_violation": str(e)}
    ev["manifest_sha256"] = hashlib.sha256(raw).hexdigest()

    deep = deep_validate(m)
    ev["deep_violations"] = deep
    if deep:
        return False, ev

    if not display_yaml_in_sync():
        ev["display_error"] = "manifest.yaml display file is not parse-equal to manifest.json"
        return False, ev

    from .policy import ARMS
    if sorted(a["id"] for a in m["arms"]) != sorted(ARMS.keys()):
        ev["binding_error"] = "manifest arms != runtime registry"
        return False, ev
    for g in m["gates"]:
        pred = g["predicate"]
        if pred != "evidence_gate" and pred not in PREDICATES:
            ev["binding_error"] = f"gate {g['id']} predicate {pred} not in runtime registry"
            return False, ev
        if pred == "evidence_gate" and "evidence_path" not in g:
            ev["binding_error"] = f"evidence gate {g['id']} lacks evidence_path"
            return False, ev

    offenders = []

    def walk_or(node, path):
        if isinstance(node, str) and " or " in node:
            if not any(t in path for t in ("banned_wording", "note", "failure_note",
                                           "harm_mechanism_note", "equivalence_requires",
                                           "ledger_model", "coprimary_success_rule",
                                           "contract", "magnitude_semantics")):
                offenders.append(path)
        elif isinstance(node, dict):
            for k, vv in node.items():
                walk_or(vv, f"{path}.{k}")
        elif isinstance(node, list):
            for i, vv in enumerate(node):
                walk_or(vv, f"{path}[{i}]")
    walk_or(m, "$")
    ev["or_offenders"] = offenders
    if offenders:
        return False, ev

    text = m["meta"]["identity_en"].lower()
    hits = [w for w in m["meta"]["banned_wording"] if w.split(" (")[0].lower() in text]
    ev["banned_hits"] = hits
    if hits:
        return False, ev

    # mutants must be rejected by (Draft-7 OR deep validation)
    import yaml
    import jsonschema
    schema = json.loads((ROOT / "schema/manifest.schema.json").read_text())
    mutants = sorted((ROOT / "tests/mutants").glob("*.yaml"))
    ev["mutants_checked"] = len(mutants)
    if len(mutants) < 5:
        ev["mutant_error"] = "need >=5 mutant fixtures"
        return False, ev
    for mp in mutants:
        mm = yaml.safe_load(mp.read_text())
        schema_errs = list(jsonschema.Draft7Validator(schema).iter_errors(mm))
        if not schema_errs and not deep_validate(mm):
            ev["mutant_error"] = f"{mp.name} accepted by BOTH schema and deep validation"
            return False, ev
    return True, ev


# ---------------------------------------------------------------------------
# G1 (unchanged oracle logic; adapted to no-utility-parameter API)
# ---------------------------------------------------------------------------

PLANTED = {"m_strong_good": 0.20, "m_weak_good": 0.05, "m_bad": -0.10}


def _analytic_c3_credit(effects, k, y, neutral):
    qf = min(0.99, max(0.01, 0.5 + sum(effects.values())))
    r = dict(effects)
    r[k] = neutral
    qr = min(0.99, max(0.01, 0.5 + sum(r.values())))
    return (qr - qf) * (qr + qf - 2 * y)


def check_g1_estimators():
    from .policy import (NEUTRAL_REPLACEMENT_EFFECT, ToyDeliberation,
                         credit_c3_action, credit_diff_agent, credit_shared_surplus)
    ev = {"cases": []}
    worlds = [("base_y1", PLANTED, 1), ("base_y0", PLANTED, 0),
              ("with_tie", {"a": 0.10, "b": 0.10, "c": -0.05}, 1),
              ("with_zero", {"a": 0.15, "z": 0.0, "c": -0.05}, 0),
              ("clipping", {"a": 0.90, "b": 0.30}, 1)]
    for name, effects, y in worlds:
        est = credit_c3_action(ToyDeliberation(effects, y))
        oracle = {k: _analytic_c3_credit(effects, k, y, NEUTRAL_REPLACEMENT_EFFECT)
                  for k in effects}
        max_err = max(abs(est[k] - oracle[k]) for k in effects)
        ev["cases"].append({"case": name, "max_abs_err": max_err})
        if max_err > 1e-12:
            return False, ev
    diff = credit_diff_agent(ToyDeliberation(PLANTED, 1))
    c3 = credit_c3_action(ToyDeliberation(PLANTED, 1))
    ev["diff_neq_c3"] = any(abs(diff[k] - c3[k]) > 1e-9 for k in PLANTED)
    if not ev["diff_neq_c3"]:
        return False, ev
    shared = credit_shared_surplus(ToyDeliberation(PLANTED, 1))
    ev["shared_uniform"] = len(set(shared.values())) == 1
    return ev["shared_uniform"], ev


# ---------------------------------------------------------------------------
# G2: score-convention independence BY CONSTRUCTION (r8 finding #2)
# ---------------------------------------------------------------------------

def check_g2_invariance():
    """The r8 in-domain cancellation counterexample required injecting a
    transformed utility into the update path. v5.2 removes that path entirely:
    (a) no Arm/credit signature accepts a utility callable;
    (b) memory hashes are computed before/without any reporting transform, and
        applying published_score() afterwards cannot change them (verified);
    (c) the r8 crafted near-tie world is retained as a determinism regression."""
    import inspect
    from .policy import (ARMS, Arm, MemoryState, ToyDeliberation, published_score)
    ev = {}
    sig = inspect.signature(Arm.update)
    ev["update_signature"] = list(sig.parameters)
    if any(p in sig.parameters for p in ("util", "utility", "score_fn")):
        return False, ev
    for fn_name in ("credit_shared_surplus", "credit_diff_agent", "credit_c3_action"):
        from . import policy as _p
        params = list(inspect.signature(getattr(_p, fn_name)).parameters)
        if any(p in params for p in ("util", "utility", "score_fn")):
            ev["leak"] = f"{fn_name} accepts a utility parameter"
            return False, ev
    # r8 crafted near-tie world: memory must be a pure function of (world, seed)
    tie_world = {"a": 0.020000010000000002, "b": 0.02}
    for arm_id, arm in ARMS.items():
        shas = set()
        for _ in range(3):
            mem = arm.update(MemoryState(), ToyDeliberation(tie_world, 1),
                             feedback_clock=10.0, batch_id="batch-r8")
            shas.add(mem.sha())
        if len(shas) != 1:
            ev["nondeterministic"] = arm_id
            return False, ev
    # reporting transform provably cannot reach memory (no shared state)
    mem_before = ARMS["c3_action"].update(MemoryState(), ToyDeliberation(PLANTED, 1),
                                          feedback_clock=10.0, batch_id="b")
    _ = published_score(0.21, a=123.456, b=0.001)
    mem_after = ARMS["c3_action"].update(MemoryState(), ToyDeliberation(PLANTED, 1),
                                         feedback_clock=10.0, batch_id="b")
    ev["reporting_isolated"] = mem_before.sha() == mem_after.sha()
    return ev["reporting_isolated"], ev


def check_g3_clocks():
    sys.path.insert(0, str(ROOT))
    from tests.test_clocks import run_all_fixtures
    return run_all_fixtures()


def check_g10_placebos():
    from .policy import (ToyDeliberation, credit_c3_action, credit_c3_sham,
                         sattolo_derangement)
    ev = {}
    for batch in [f"batch-{i:03d}" for i in range(20)]:
        w_real = ToyDeliberation(PLANTED, 1)
        real = credit_c3_action(w_real)
        w_sham = ToyDeliberation(PLANTED, 1)
        sham = credit_c3_sham(w_sham, batch)
        if w_real.receipts != w_sham.receipts:
            ev["receipt_mismatch"] = batch
            return False, ev
        if sorted(real.values()) != sorted(sham.values()):
            ev["multiset_mismatch"] = batch
            return False, ev
        if real == sham:
            ev["identity_permutation"] = batch
            return False, ev
    for n in range(2, 7):
        keys = [f"k{i}" for i in range(n)]
        for seed in range(50):
            mapping = sattolo_derangement(keys, seed)
            if any(mapping[k] == k for k in keys):
                ev["fixed_point"] = {"n": n, "seed": seed}
                return False, ev
    w = ToyDeliberation({"only": 0.2}, 1)
    if credit_c3_sham(w, "batch-single") != {"only": 0.0}:
        return False, {"singleton": "fallback broken"}
    w2 = ToyDeliberation(PLANTED, 1)
    real = credit_c3_action(w2)
    order_real = sorted(real, key=lambda k: -abs(real[k]))
    decoupled = sum(
        sorted((s := credit_c3_sham(ToyDeliberation(PLANTED, 1), f"pb-{i}")),
               key=lambda k: -abs(s[k])) != order_real
        for i in range(10))
    ev["orderings_decoupled"] = f"{decoupled}/10"
    return decoupled >= 5, ev


def check_g9a_search_protocol():
    ev = {}
    doc = ROOT / "docs/search_protocol.md"
    if not doc.exists():
        return False, {"reason": "docs/search_protocol.md missing"}
    text = doc.read_text()
    for s in ["来源与数据库", "查询族", "筛选与核验规则", "比较者登记册", "残余交集", "预注册重跑"]:
        if s not in text:
            return False, {"missing_section": s}
    per_round = re.findall(r"(\d+)\s*篇[)]", text)
    declared = re.search(r"六轮累计\s*(\d+)\s*篇", text)
    if declared:
        total, parts = int(declared.group(1)), [int(x) for x in per_round]
        ev["declared_total"], ev["parts"] = total, parts
        if parts and sum(parts) != total:
            return False, {**ev, "count_error": f"{total} != {sum(parts)}"}
    # pinned evidence: content swap breaks the gate (r8 #9)
    for name, want in G9A_EVIDENCE_PINS.items():
        p = (ROOT / f"../phase_b2/04_special_searches/{name}").resolve()
        if not p.exists():
            return False, {**ev, "evidence_problem": f"{name} missing"}
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        if got != want:
            return False, {**ev, "evidence_problem": f"{name} content hash mismatch"}
    ev["pinned_evidence_files"] = len(G9A_EVIDENCE_PINS)
    return True, ev


# ---------------------------------------------------------------------------
# LOCK / FREEZE
# ---------------------------------------------------------------------------

def verify_lock():
    ev = {"stale": [], "unexpected": [], "external": {}}
    if not LOCK_PATH.exists():
        return False, {"reason": "lock missing; run tools/refresh_lock.py"}
    lock_bytes = LOCK_PATH.read_bytes()
    lock = json.loads(lock_bytes)
    if not TRUSTED_ROOT_PATH.exists():
        return False, {"reason": "trusted root missing outside repo"}
    root = TRUSTED_ROOT_PATH.read_text().strip().split()[0]
    ev["lock_sha256"] = hashlib.sha256(lock_bytes).hexdigest()
    if ev["lock_sha256"] != root:
        return False, {**ev, "reason": "lock does not match out-of-repo trusted root"}
    current = repo_inventory()
    for rel, want in lock["files"].items():
        got = current.pop(rel, None)
        if got is None:
            ev["stale"].append((rel, "missing"))
        elif got != want:
            ev["stale"].append((rel, "hash_mismatch"))
    ev["unexpected"] = sorted(current)
    for name, pin in EXTERNAL_PINS.items():
        p = (ROOT / pin["path"]).resolve()
        got = hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "MISSING"
        ev["external"][name] = got == pin["sha256"]
    ok = not ev["stale"] and not ev["unexpected"] and all(ev["external"].values())
    return ok, ev


def check_lock_artifacts():
    return verify_lock()


def check_freeze_preconditions():
    m, _ = load_manifest(validate=True)
    ev = {"unfrozen": [], "theory_receipt": None}

    def walk(node, path):
        if isinstance(node, dict):
            if node.get("status") == "PENDING":
                ev["unfrozen"].append(path)
            for k, vv in node.items():
                walk(vv, f"{path}.{k}")
        elif isinstance(node, list):
            for i, vv in enumerate(node):
                walk(vv, f"{path}[{i}]")
    walk(m, "$")
    deep = deep_validate(m)          # FROZEN garbage rejected here too
    if deep:
        ev["deep_violations"] = deep
        return False, ev
    doc = ROOT / "docs/theory_h3.md"
    test = ROOT / "tests/test_theory_h3.py"
    if not doc.exists() or doc.stat().st_size < 2000 or not test.exists():
        ev["theory_receipt"] = "theory artifact missing or too small"
        return False, ev
    proc = subprocess.run([sys.executable, "-B", str(test)], capture_output=True,
                          cwd=str(ROOT))
    ev["theory_receipt"] = f"exit={proc.returncode}"
    if proc.returncode != 0:
        return False, ev
    return (not ev["unfrozen"]), ev


PREDICATES = {
    "check_g9a_search_protocol": check_g9a_search_protocol,
    "check_g0_manifest": check_g0_manifest,
    "check_g1_estimators": check_g1_estimators,
    "check_g2_invariance": check_g2_invariance,
    "check_g3_clocks": check_g3_clocks,
    "check_g10_placebos": check_g10_placebos,
    "check_lock_artifacts": check_lock_artifacts,
    "check_freeze_preconditions": check_freeze_preconditions,
}
