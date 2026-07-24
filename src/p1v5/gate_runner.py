"""Gate DAG runner v5.3.

N9-R3: evidence gates validate against per-gate JSON Schemas
(additionalProperties:false, typed, bounded) and the VERDICT IS COMPUTED BY THE
RUNNER from the metrics; an artifact's self-reported verdict must match the
machine-derived one or the gate FAILs.

N9-R2: evidence binds to the INPUT lock (which excludes evidence/), and a
release attestation records input-lock + all evidence hashes + gate results.

N9-R4: readiness runs never write the out-of-repo anchor; only --release does.
Guarantee scope (stated plainly): this chain detects accidental edits and
single-file tampering inside the audited tree. It is NOT third-party provenance:
the producer, the chain, and the anchor share one write privilege. Independent
verification comes from the git history + tags and from auditors snapshotting
the tree, per the SLSA producer/verifier trust-boundary model.
"""

import datetime
import hashlib
import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from p1v5.analysis import MIN_FAMILIES  # noqa: E402
from p1v5.checks import (ATTESTATION_ANCHOR_PATH, CANONICAL_ARMS, EXTERNAL_PINS,  # noqa: E402
                         LOCK_PATH, PREDICATES, load_manifest, manifest_sha256)


def _strict_json(path):
    """r13 P0-13-8: SOURCE artifacts get the same strict parse as evidence —
    RFC 8259 forbids NaN/Infinity; Python's default loads() does not."""
    doc = json.loads(path.read_text(),
                     parse_constant=lambda n: (_ for _ in ()).throw(ValueError(n)))
    _assert_evidence_finite(doc)
    return doc

_HEX64 = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_NONNEG_INT = {"type": "integer", "minimum": 0}
_POS_INT = {"type": "integer", "minimum": 1}
_UNIT = {"type": "number", "minimum": 0, "maximum": 1}
_POS_NUM = {"type": "number", "exclusiveMinimum": 0}

G7A_SOURCE_PATH = ROOT / "evidence_src/micro_pilot_live.json"
G7A_PRICING_PATH = ROOT / "evidence_src/pricing_v1.json"

# R14-6: a transcript bundle is a TYPED artifact, not "any JSON with receipts".
# The G7a gate validates every persisted bundle against this schema and then
# cross-checks internal identity (arm / question_id) against the map key.
TRANSCRIPT_BUNDLE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["schema_version", "question_id", "meta", "messages", "votes",
                 "final_q", "failure_class", "prompt_shas", "receipts"],
    "properties": {
        "schema_version": {"const": "transcript_bundle_v1"},
        "question_id": {"type": "string", "minLength": 1},
        "meta": {"type": "object", "required": ["arm", "epistemic_status"]},
        "messages": {"type": "array"},
        "votes": {"type": "object"},
        "final_q": {"type": ["string", "null"]},
        "failure_class": {"type": ["string", "null"]},
        "prompt_shas": {"type": "array", "minItems": 1,
                        "items": {"type": "string", "pattern": "^[0-9a-f]{64}$"}},
        "receipts": {"type": "array", "minItems": 1, "items": {
            "type": "object", "additionalProperties": False,
            "required": ["backend", "model", "purpose", "prompt_sha", "output_sha",
                         "prompt_chars", "output_chars", "latency_ms",
                         "prompt_tokens", "completion_tokens", "provider",
                         "failure_class"],
            "properties": {
                "backend": {"type": "string", "minLength": 1},
                "model": {"type": "string", "minLength": 1},
                "purpose": {"enum": ["round1", "round2", "c3_rollout"]},
                "prompt_sha": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "output_sha": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "prompt_chars": {"type": "integer", "minimum": 0},
                "output_chars": {"type": "integer", "minimum": 0},
                "latency_ms": {"type": "integer", "minimum": 0},
                "prompt_tokens": {"type": "integer", "minimum": 0},
                "completion_tokens": {"type": "integer", "minimum": 0},
                "provider": {"type": "string"},
                "failure_class": {"type": "string"},
            }}},
    },
}


def _evidence_schema(metric_props: dict, required_metrics: list) -> dict:
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "additionalProperties": False,
        "required": ["produced_by", "produced_at_utc", "inputs", "metrics", "verdict"],
        "properties": {
            "produced_by": {"type": "string", "minLength": 3},
            "produced_at_utc": {"type": "string", "minLength": 20},
            "inputs": {
                "type": "object", "additionalProperties": False,
                "required": ["manifest_sha256", "input_lock_sha256"],
                "properties": {"manifest_sha256": _HEX64, "input_lock_sha256": _HEX64},
            },
            "metrics": {"type": "object", "additionalProperties": False,
                        "required": required_metrics, "properties": metric_props},
            "verdict": {"enum": ["PASS", "FAIL"]},
        },
    }


EVIDENCE_SCHEMAS = {
    "G8": _evidence_schema({"n_fields_analyzed": _POS_INT, "n_allow": _NONNEG_INT,
                            "n_restrict": _NONNEG_INT, "terms_sha256": _HEX64},
                           ["n_fields_analyzed", "n_allow", "n_restrict", "terms_sha256"]),
    "G4": _evidence_schema({"route_chosen": {"enum": ["pre_outcome_branches", "frozen_local_replay"]},
                            "replay_fidelity": _UNIT, "n_replayed": _POS_INT},
                           ["route_chosen", "replay_fidelity", "n_replayed"]),
    "G7a": _evidence_schema({"cost_usd_estimate": _POS_NUM, "cost_error_pct": {"type": "number", "minimum": 0, "maximum": 100},
                             "n_dry_run_events": _POS_INT,
                             "source_report_sha256": _HEX64,
                             "pricing_table_sha256": _HEX64,
                             "receipt_bundle_sha256": _HEX64},
                            ["cost_usd_estimate", "cost_error_pct", "n_dry_run_events",
                             "source_report_sha256", "pricing_table_sha256",
                             "receipt_bundle_sha256"]),
    # shadow r3 + r13 P0-13-3: G5a evidence must CARRY its batch lineage AND
    # name the actual files — the runner OPENS batch manifest, registry and
    # panel, re-hashes them, re-derives allowed_use, and RECOMPUTES the
    # transition count; a sha with no verified referent can never support PASS
    "G5a": _evidence_schema({"independent_family_transitions": _NONNEG_INT, "required_by_g6": _POS_INT,
                             "batch_allowed_use": {"const": "g5a_candidate"},
                             "batch_manifest_sha256": _HEX64,
                             "registry_sha256": _HEX64,
                             "topics_sha256": _HEX64,
                             "panel_sha256": _HEX64,
                             "batch_manifest_path": {"type": "string", "minLength": 1},
                             "registry_path": {"type": "string", "minLength": 1},
                             "topics_path": {"type": "string", "minLength": 1},
                             "panel_path": {"type": "string", "minLength": 1}},
                            ["independent_family_transitions", "required_by_g6",
                             "batch_allowed_use", "batch_manifest_sha256", "registry_sha256",
                             "topics_sha256", "panel_sha256", "batch_manifest_path",
                             "registry_path", "topics_path", "panel_path"]),
    # R14-5: G6 evidence must NAME its simulator, the production analysis code,
    # its DGP, its seed schedule and its raw per-replicate results — the runner
    # recomputes the code shas, opens the rows, re-derives the summary stats
    # with the pinned formula and re-executes replicate 0 as a genesis check
    "G6": _evidence_schema({"type1_ucb": _UNIT, "power_lcb": _UNIT, "n_sims": _POS_INT,
                            "delta_frozen_sha256": _HEX64,
                            "simulator_sha256": _HEX64,
                            "analysis_code_sha256": _HEX64,
                            "raw_results_path": {"type": "string", "minLength": 1},
                            "raw_results_sha256": _HEX64,
                            "dgp": {"type": "object"},
                            "seed_schedule": {"type": "string", "minLength": 30}},
                           ["type1_ucb", "power_lcb", "n_sims", "delta_frozen_sha256",
                            "simulator_sha256", "analysis_code_sha256",
                            "raw_results_path", "raw_results_sha256", "dgp",
                            "seed_schedule"]),
    "G5b": _evidence_schema({"weeks_required": _POS_NUM, "calendar_ok": {"type": "boolean"}},
                            ["weeks_required", "calendar_ok"]),
    "G7b": _evidence_schema({"total_cost_usd": {"type": "number", "minimum": 0},
                             "within_hard_cap": {"type": "boolean"}},
                            ["total_cost_usd", "within_hard_cap"]),
    "G9b": _evidence_schema({"new_hits": _NONNEG_INT, "intersection_touched": {"type": "boolean"},
                             "search_log_sha256": _HEX64},
                            ["new_hits", "intersection_touched", "search_log_sha256"]),
}

# provisional machine thresholds (frozen values may tighten at preregistration,
# never loosen; every rule returns True only if the gate's scientific condition holds)
PINNED_TERMS_SHA = "27828b629e92eef373a9d2d91a29c349053f8a5b4cd102995a1396d3de04efd0"


def _verdict_rules(manifest):
    """T10-R2: cross-field relations included; thresholds come from the manifest
    where the manifest defines them (alpha), never from a looser hard-code."""
    llm_cap = manifest["budget"]["llm_usd"]["value"]
    alpha = manifest["estimand"]["contrasts"]["alpha"]
    return {
        "G8": lambda x: (x["terms_sha256"] == PINNED_TERMS_SHA
                         and x["n_fields_analyzed"] >= 10
                         and x["n_allow"] + x["n_restrict"] == x["n_fields_analyzed"]),
        "G4": lambda x: x["replay_fidelity"] >= 0.90 and x["n_replayed"] >= 10,
        "G7a": lambda x: (x["cost_error_pct"] <= 20 and x["n_dry_run_events"] >= 5
                          and x["cost_usd_estimate"] <= llm_cap),
        # r13: required_by_g6 may not undercut the frozen small-cluster floor —
        # "1 >= 1" style self-attestation is structurally impossible
        "G5a": lambda x: (x["independent_family_transitions"] >= x["required_by_g6"]
                          and x["required_by_g6"] >= MIN_FAMILIES
                          and x["batch_allowed_use"] == "g5a_candidate"),
        "G6": lambda x: (x["type1_ucb"] <= alpha and x["power_lcb"] >= 0.80
                         and x["n_sims"] >= 1000),
        "G5b": lambda x: x["calendar_ok"] is True and x["weeks_required"] <= 52,
        "G7b": lambda x: x["within_hard_cap"] is True and x["total_cost_usd"] <= llm_cap,
        "G9b": lambda x: x["intersection_touched"] is False,
    }


# T10-R2 #5: metric hashes that must be RECOMPUTED against a content-addressed
# target file; a hash with no recomputable referent can never support PASS.
HASH_BINDINGS = {
    "G6": ("delta_frozen_sha256", "docs/delta_decision.md"),
    "G9b": ("search_log_sha256", "evidence/g9b_search_log.jsonl"),
}


def _assert_evidence_finite(node, path="$"):
    import math
    if isinstance(node, float) and not math.isfinite(node):
        raise ValueError(f"non-finite number at {path}")
    if isinstance(node, bool):
        return
    if isinstance(node, dict):
        for k, v in node.items():
            _assert_evidence_finite(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _assert_evidence_finite(v, f"{path}[{i}]")


def _parse_utc(ts: str):
    """Strict timezone-aware UTC (N9-R3): calendar-valid, tz-aware, offset zero."""
    try:
        dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None or dt.utcoffset() != datetime.timedelta(0):
        return None
    return dt


def toposort(gates):
    by_id = {g["id"]: g for g in gates}
    order, done, marks = [], set(), {}

    def visit(gid):
        if gid in done:
            return
        if marks.get(gid) == "temp":
            raise RuntimeError(f"CYCLE detected at gate {gid}")
        marks[gid] = "temp"
        for dep in by_id[gid]["depends_on"]:
            visit(dep)
        marks[gid] = "perm"
        done.add(gid)
        order.append(gid)

    for g in gates:
        visit(g["id"])
    return order, by_id


def eval_evidence_gate(gate, current_manifest_sha, current_lock_sha, manifest=None):
    import jsonschema
    if manifest is None:
        manifest, _ = load_manifest(validate=False)
    p = ROOT / gate["evidence_path"]
    if not p.exists():
        return {"status": "PENDING", "reason": f"evidence artifact absent: {gate['evidence_path']}"}
    try:
        e = json.loads(p.read_text(), parse_constant=lambda n: (_ for _ in ()).throw(ValueError(n)))
        _assert_evidence_finite(e)          # T10-R2 #1: 1e999-style overflow refused
    except Exception as exc:
        return {"status": "FAIL", "reason": f"evidence unreadable/non-strict/non-finite: {exc}"}
    schema = EVIDENCE_SCHEMAS.get(gate["id"])
    if schema is None:
        return {"status": "FAIL", "reason": f"no evidence schema registered for {gate['id']}"}
    errs = list(jsonschema.Draft7Validator(schema).iter_errors(e))
    if errs:
        return {"status": "FAIL",
                "reason": f"evidence schema violations: {[er.message for er in errs[:3]]}"}
    if _parse_utc(e["produced_at_utc"]) is None:
        return {"status": "FAIL", "reason": "produced_at_utc is not a valid timezone-aware UTC instant"}
    if e["inputs"]["manifest_sha256"] != current_manifest_sha:
        return {"status": "FAIL", "reason": "evidence not bound to CURRENT manifest hash"}
    if e["inputs"]["input_lock_sha256"] != current_lock_sha:
        return {"status": "FAIL", "reason": "evidence not bound to CURRENT input lock hash"}
    if gate["id"] == "G7a":
        # R12 (P0-12-8): full recomputation chain — pricing PARSED and USED,
        # cap checked against SOURCE numbers, evidence estimate must equal source,
        # receipts (transcript bundle shas) bound into the evidence.
        src = G7A_SOURCE_PATH
        prc = G7A_PRICING_PATH
        for p_, key in ((src, "source_report_sha256"), (prc, "pricing_table_sha256")):
            if not p_.exists():
                return {"status": "FAIL", "reason": f"G7a source artifact missing: {p_.name}"}
            got = hashlib.sha256(p_.read_bytes()).hexdigest()
            if e["metrics"][key] != got:
                return {"status": "FAIL", "reason": f"G7a {key} != recomputed sha of {p_.name}"}
        try:
            rep = _strict_json(src)
            pricing = _strict_json(prc)
        except Exception as exc:
            return {"status": "FAIL",
                    "reason": f"G7a source/pricing not strict RFC-8259 JSON: {exc}"}
        model_p = pricing.get(rep.get("model"))
        if not isinstance(model_p, dict) or "in_per_mtok" not in model_p:
            return {"status": "FAIL", "reason": f"G7a pricing table has no entry for {rep.get('model')}"}
        bp = rep.get("receipt_reported_prompt_tokens")
        bc = rep.get("receipt_reported_completion_tokens")
        est_r, act_r = rep.get("est_total_cost_usd"), rep.get("receipt_reported_cost_usd")
        if not all(isinstance(x, (int, float)) for x in (bp, bc, est_r, act_r)):
            return {"status": "FAIL",
                    "reason": "G7a source report lacks receipt_reported tokens/costs "
                              "(R14-6: 'billed' naming retired — these are receipt-derived)"}
        act_recomputed = bp / 1e6 * model_p["in_per_mtok"] + bc / 1e6 * model_p["out_per_mtok"]
        if abs(act_recomputed - act_r) > 0.01:
            return {"status": "FAIL",
                    "reason": f"G7a billed cost {act_r} != recomputed from tokens x pricing {act_recomputed:.4f}"}
        llm_cap_ = manifest["budget"]["llm_usd"]["value"]
        if est_r > llm_cap_ or act_r > llm_cap_:
            return {"status": "FAIL",
                    "reason": f"G7a SOURCE cost exceeds hard cap: est={est_r} billed={act_r} cap={llm_cap_}"}
        if abs(e["metrics"]["cost_usd_estimate"] - est_r) > 1e-9:
            return {"status": "FAIL", "reason": "G7a evidence estimate != source est_total_cost_usd"}
        recomputed_err = abs(est_r - act_r) / act_r * 100
        if abs(recomputed_err - e["metrics"]["cost_error_pct"]) > 0.05:
            return {"status": "FAIL",
                    "reason": f"G7a cost_error_pct {e['metrics']['cost_error_pct']} != recomputed {recomputed_err:.2f}"}
        if rep.get("n_questions") != e["metrics"]["n_dry_run_events"]:
            return {"status": "FAIL", "reason": "G7a n_dry_run_events != source report"}
        bundles = rep.get("transcript_bundles")
        if not bundles:
            return {"status": "FAIL", "reason": "G7a source report lacks transcript_bundles (receipts)"}
        rb = hashlib.sha256(json.dumps(sorted(bundles.values())).encode()).hexdigest()
        if e["metrics"]["receipt_bundle_sha256"] != rb:
            return {"status": "FAIL", "reason": "G7a receipt_bundle_sha256 != recomputed from source bundles"}
        # r13 P0-13-8: self-reported bundle shas prove nothing — OPEN every
        # persisted bundle, re-hash it, check arm x question cardinality, and
        # re-sum billed tokens from the per-call receipts inside the bundles
        td_rel = rep.get("transcript_dir")
        if not td_rel:
            return {"status": "FAIL",
                    "reason": "G7a source lacks transcript_dir (bundle files unlocatable)"}
        td = ROOT / td_rel
        qids_per_arm, sum_pt, sum_ct = {}, 0, 0
        _seen_receipt_arrays = {}
        for key in sorted(bundles):
            arm, _, qid = key.partition("/")
            bpath = td / f"{arm}_{qid}.json"
            if not bpath.exists():
                return {"status": "FAIL", "reason": f"G7a bundle file missing on disk: {bpath.name}"}
            if hashlib.sha256(bpath.read_bytes()).hexdigest() != bundles[key]:
                return {"status": "FAIL", "reason": f"G7a bundle sha mismatch for {key}"}
            try:
                bdoc = _strict_json(bpath)
            except Exception as exc:
                return {"status": "FAIL", "reason": f"G7a bundle {key} not strict JSON: {exc}"}
            # R14-6: the bundle must BE a transcript (typed schema), and its
            # internal identity must match the map key it is filed under
            errs_ = list(jsonschema.Draft7Validator(TRANSCRIPT_BUNDLE_SCHEMA).iter_errors(bdoc))
            if errs_:
                return {"status": "FAIL",
                        "reason": f"G7a bundle {key} violates transcript schema: "
                                  f"{errs_[0].message[:120]}"}
            if bdoc["question_id"] != qid or bdoc["meta"].get("arm") != arm:
                return {"status": "FAIL",
                        "reason": f"G7a bundle {key} internal identity mismatch "
                                  f"(question_id={bdoc['question_id']!r}, "
                                  f"meta.arm={bdoc['meta'].get('arm')!r})"}
            qids_per_arm.setdefault(arm, set()).add(qid)
            # r5-F4: two QUESTIONS of one arm can never honestly share an
            # identical receipts array (prompts embed the question text) —
            # identity-relabeled content clones die here
            ser_ = json.dumps(bdoc["receipts"], sort_keys=True)
            dup_key = (arm, ser_)
            if dup_key in _seen_receipt_arrays:
                return {"status": "FAIL",
                        "reason": f"G7a arm {arm}: identical receipts array across two "
                                  f"questions ({_seen_receipt_arrays[dup_key]} vs {qid}) — "
                                  f"content clone (r5-F4)"}
            _seen_receipt_arrays[dup_key] = qid
            for rcp in bdoc["receipts"]:
                sum_pt += rcp["prompt_tokens"]
                sum_ct += rcp["completion_tokens"]
        if set(qids_per_arm) != set(CANONICAL_ARMS):
            return {"status": "FAIL",
                    "reason": f"G7a arms {sorted(qids_per_arm)} != canonical five"}
        qsets = list(qids_per_arm.values())
        if any(qs != qsets[0] for qs in qsets) or len(qsets[0]) != rep.get("n_questions"):
            return {"status": "FAIL",
                    "reason": "G7a arms do not share ONE identical question-id set of "
                              "size n_questions (R14-6: per-arm counts are not enough)"}
        if sum_pt != bp or sum_ct != bc:
            return {"status": "FAIL",
                    "reason": f"G7a billed tokens {bp}/{bc} != receipts sum {sum_pt}/{sum_ct}"}
    if gate["id"] == "G5a":
        # r13 P0-13-3: the yield chain has REFERENTS — open batch manifest,
        # registry and panel; re-hash each; re-derive allowed_use from channel
        # completeness; verify the lineage links; recompute the transition count
        m_ = e["metrics"]
        bmp, rgp, pnp = (ROOT / m_["batch_manifest_path"], ROOT / m_["registry_path"],
                         ROOT / m_["panel_path"])
        tpp = ROOT / m_["topics_path"]
        for p_, key in ((bmp, "batch_manifest_sha256"), (rgp, "registry_sha256"),
                        (tpp, "topics_sha256"), (pnp, "panel_sha256")):
            if not p_.exists():
                return {"status": "FAIL", "reason": f"G5a referent missing: {p_}"}
            if hashlib.sha256(p_.read_bytes()).hexdigest() != m_[key]:
                return {"status": "FAIL", "reason": f"G5a {key} != recomputed sha of {p_.name}"}
        try:
            bm_ = _strict_json(bmp)
            pn_ = _strict_json(pnp)
        except Exception as exc:
            return {"status": "FAIL", "reason": f"G5a referent not strict JSON: {exc}"}
        cc_ = bm_.get("channel_complete")
        if not isinstance(cc_, dict) or cc_.get("incomplete_reasons") or cc_.get("overrides"):
            return {"status": "FAIL",
                    "reason": "G5a batch is not machine-complete (incomplete_reasons/overrides "
                              "non-empty); allowed_use=g5a_candidate cannot be derived"}
        if bm_.get("allowed_use") != "g5a_candidate":
            return {"status": "FAIL", "reason": "G5a batch manifest allowed_use != g5a_candidate"}
        try:
            first = json.loads(rgp.read_text().splitlines()[0])
            lin_ = first["_lineage"]
        except Exception:
            return {"status": "FAIL", "reason": "G5a registry lacks a parseable _lineage header"}
        if lin_.get("batch_manifest_sha256") != m_["batch_manifest_sha256"] \
                or lin_.get("allowed_use") != "g5a_candidate":
            return {"status": "FAIL",
                    "reason": "G5a registry lineage does not link to THIS g5a_candidate batch"}
        pn_lin = (pn_.get("summary") or {}).get("lineage") or {}
        if pn_lin.get("registry_sha256") != m_["registry_sha256"] \
                or pn_lin.get("batch_manifest_sha256") != m_["batch_manifest_sha256"]:
            return {"status": "FAIL",
                    "reason": "G5a panel lineage does not link to THIS registry/batch"}
        # shadow r4 P0: the TOPICS layer joins the chain — the gate opens the
        # label file, requires its mandatory lineage header, links it to THIS
        # registry AND to the panel's recorded topics sha, then opens the call
        # RECEIPTS file: every label must trace to a receipted LLM call
        if pn_lin.get("topics_sha256") != m_["topics_sha256"]:
            return {"status": "FAIL",
                    "reason": "G5a panel lineage topics_sha256 != evidence topics_sha256"}
        try:
            t_first = json.loads(tpp.read_text().splitlines()[0])
            t_lin = t_first["_lineage"]
        except Exception:
            return {"status": "FAIL", "reason": "G5a topics file lacks a parseable _lineage header"}
        if t_lin.get("registry_sha256") != m_["registry_sha256"]:
            return {"status": "FAIL",
                    "reason": "G5a topics lineage does not link to THIS registry"}
        # R14-1: labels are DERIVED, never audited by aggregate counts — the
        # gate recomputes the frozen parser's sha, opens the persisted raw
        # call outputs, RE-RUNS the parser, and requires every topics row to
        # equal its derivation (unparsed rows must be underivable), with the
        # row set a exact partition of the opened registry's events.
        parser_ref = ROOT / "src/p1v5/topic_parser.py"
        if t_lin.get("parser_sha256") != hashlib.sha256(parser_ref.read_bytes()).hexdigest():
            return {"status": "FAIL",
                    "reason": "G5a topics parser_sha256 != recomputed sha of frozen topic_parser.py"}
        rc_name, rc_sha = t_lin.get("calls_file"), t_lin.get("calls_sha256")
        n_calls, n_labeled = t_lin.get("n_llm_calls"), t_lin.get("n_labeled")
        if not rc_name or not rc_sha or not isinstance(n_calls, int) \
                or not isinstance(n_labeled, int):
            return {"status": "FAIL",
                    "reason": "G5a topics lineage lacks raw-calls binding "
                              "(calls_file/calls_sha256/n_llm_calls/n_labeled)"}
        rcp = tpp.parent / rc_name
        if not rcp.exists():
            return {"status": "FAIL", "reason": f"G5a raw calls file missing: {rc_name}"}
        if hashlib.sha256(rcp.read_bytes()).hexdigest() != rc_sha:
            return {"status": "FAIL", "reason": "G5a calls_sha256 != recomputed sha of calls file"}
        from p1v5.topic_parser import parse_reply as _frozen_parse
        call_rows_ = [json.loads(ln) for ln in rcp.read_text().splitlines() if ln.strip()]
        if len(call_rows_) != n_calls or n_calls < 1:
            return {"status": "FAIL",
                    "reason": f"G5a calls file rows {len(call_rows_)} != declared {n_calls}"}
        derived_ = {}
        for cr in call_rows_:
            raw_ = cr.get("raw_text")
            if not isinstance(raw_, str) or hashlib.sha256(raw_.encode()).hexdigest() != cr.get("output_sha"):
                return {"status": "FAIL",
                        "reason": f"G5a call {cr.get('call_id')} raw_text does not hash to output_sha"}
            idxs_ = {i for i, _e in cr.get("items", [])}
            parsed_ = _frozen_parse(raw_, idxs_)
            for i_, eid_ in cr.get("items", []):
                if i_ in parsed_:
                    derived_[eid_] = (parsed_[i_], cr.get("call_id"), cr.get("output_sha"))
        t_rows = [json.loads(ln) for ln in tpp.read_text().splitlines()[1:] if ln.strip()]
        reg_all = [json.loads(ln) for ln in rgp.read_text().splitlines() if ln.strip()]
        reg_events_ = {r_["event_id"] for r_ in reg_all[1:]}
        seen_ev, n_lab_rows = set(), 0
        for tr in t_rows:
            eid_ = tr.get("event_id")
            if eid_ in seen_ev:
                return {"status": "FAIL", "reason": f"G5a duplicate topics row for event {eid_}"}
            seen_ev.add(eid_)
            if tr.get("topic_llm") == "unparsed":
                if eid_ in derived_:
                    return {"status": "FAIL",
                            "reason": f"G5a event {eid_} marked unparsed but the frozen parser "
                                      f"derives {derived_[eid_][0]!r}"}
                continue
            n_lab_rows += 1
            if eid_ not in derived_:
                return {"status": "FAIL",
                        "reason": f"G5a label for {eid_} has no derivable source in raw outputs"}
            cat_, cid_, osha_ = derived_[eid_]
            if (tr.get("topic_llm") != cat_ or tr.get("call_id") != cid_
                    or tr.get("output_sha") != osha_):
                return {"status": "FAIL",
                        "reason": f"G5a label for {eid_} does not re-derive from its bound "
                                  f"raw output (row says {tr.get('topic_llm')!r}, parser "
                                  f"derives {cat_!r})"}
        if seen_ev != reg_events_:
            return {"status": "FAIL",
                    "reason": f"G5a topics rows are not an exact partition of the registry "
                              f"({len(seen_ev)} rows vs {len(reg_events_)} events)"}
        if n_lab_rows != n_labeled:
            return {"status": "FAIL",
                    "reason": f"G5a n_labeled {n_labeled} != labeled rows {n_lab_rows}"}
        recomputed_tr = sum(max(0, int(s.get("n_instances", 0)) - 1)
                            for s in pn_.get("panel", []))
        if recomputed_tr != m_["independent_family_transitions"]:
            return {"status": "FAIL",
                    "reason": f"G5a independent_family_transitions {m_['independent_family_transitions']} "
                              f"!= recomputed from panel ({recomputed_tr})"}
    if gate["id"] == "G6":
        # R14-5: no simulator referent, no PASS — fabricated summary numbers
        # were previously accepted on schema shape alone
        m_ = e["metrics"]
        for ref_path, key in ((ROOT / "tools/g6_simulation.py", "simulator_sha256"),
                              (ROOT / "src/p1v5/analysis.py", "analysis_code_sha256")):
            if hashlib.sha256(ref_path.read_bytes()).hexdigest() != m_[key]:
                return {"status": "FAIL",
                        "reason": f"G6 {key} != recomputed sha of {ref_path.name}"}
        rp = ROOT / m_["raw_results_path"]
        if not rp.exists():
            return {"status": "FAIL", "reason": f"G6 raw results missing: {m_['raw_results_path']}"}
        if hashlib.sha256(rp.read_bytes()).hexdigest() != m_["raw_results_sha256"]:
            return {"status": "FAIL", "reason": "G6 raw_results_sha256 != recomputed sha"}
        rows_ = [json.loads(ln) for ln in rp.read_text().splitlines() if ln.strip()]
        n_ = m_["n_sims"]
        null_n = sum(1 for r_ in rows_ if r_.get("scenario") == "null")
        eff_n = sum(1 for r_ in rows_ if r_.get("scenario") == "effect")
        if null_n != n_ or eff_n != n_:
            return {"status": "FAIL",
                    "reason": f"G6 raw rows {null_n}/{eff_n} per scenario != n_sims {n_}"}
        sys.path.insert(0, str(ROOT / "tools"))
        import g6_simulation as _g6
        s_ = _g6.summarize(rows_, n_)
        if abs(s_["type1_ucb"] - m_["type1_ucb"]) > 1e-6 \
                or abs(s_["power_lcb"] - m_["power_lcb"]) > 1e-6:
            return {"status": "FAIL",
                    "reason": f"G6 summary stats do not recompute from raw rows "
                              f"(type1_ucb {m_['type1_ucb']} vs {s_['type1_ucb']}, "
                              f"power_lcb {m_['power_lcb']} vs {s_['power_lcb']})"}
        dgp_ = m_["dgp"]
        need = {"root_prefix", "n_fam", "k_per_arm", "fam_sd", "noise_sd",
                "delta", "alpha", "n_boot"}
        if not need.issubset(dgp_):
            return {"status": "FAIL", "reason": f"G6 dgp lacks frozen keys {sorted(need - set(dgp_))}"}
        if dgp_["alpha"] != manifest["estimand"]["contrasts"]["alpha"] \
                or dgp_["n_boot"] != manifest["estimand"]["contrasts"]["n_boot"]:
            return {"status": "FAIL",
                    "reason": "G6 dgp alpha/n_boot != manifest-frozen production values"}
        # genesis spot-check (r5-F3 hardened): re-execute replicate 0 PLUS a
        # set of replicates whose indices derive from the raw file's OWN sha —
        # a fabricator cannot know which rows will be re-run without changing
        # the file and re-rolling the indices. Honest boundary, stated plainly:
        # this bounds fabrication effort statistically; the full-re-execution
        # proof happens once at FREEZE, outside the per-run gate budget.
        n_spot = min(n_, max(4, n_ // 100))
        by_key = {(r_.get("scenario"), r_.get("replicate")): r_ for r_ in rows_}
        for scen in ("null", "effect"):
            idxs = {0} | {int(hashlib.sha256(
                f"{m_['raw_results_sha256']}|spot|{scen}|{j}".encode()).hexdigest()[:8], 16) % n_
                for j in range(n_spot)}
            for i_ in sorted(idxs):
                recorded = by_key.get((scen, i_))
                if recorded is None:
                    return {"status": "FAIL", "reason": f"G6 raw rows lack {scen} replicate {i_}"}
                rerun = _g6.run_replicate(dgp_, scen, i_)
                if rerun != recorded:
                    return {"status": "FAIL",
                            "reason": f"G6 {scen} replicate {i_} does not re-execute to the "
                                      f"recorded row (genesis check failed)"}
    binding = HASH_BINDINGS.get(gate["id"])
    if binding is not None:
        key, target_rel = binding
        target = ROOT / target_rel
        if not target.exists():
            return {"status": "FAIL",
                    "reason": f"hash metric {key} has no recomputable target ({target_rel} missing)"}
        got = hashlib.sha256(target.read_bytes()).hexdigest()
        if e["metrics"][key] != got:
            return {"status": "FAIL",
                    "reason": f"{key} does not match recomputed hash of {target_rel}"}
    computed = "PASS" if _verdict_rules(manifest)[gate["id"]](e["metrics"]) else "FAIL"
    if e["verdict"] != computed:
        return {"status": "FAIL",
                "reason": f"self-reported verdict {e['verdict']} != machine-derived {computed}"}
    if computed != "PASS":
        return {"status": "FAIL", "reason": "machine-derived verdict is FAIL"}
    return {"status": "PASS",
            "evidence": {"path": gate["evidence_path"],
                         "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                         "produced_by": e["produced_by"], "machine_verdict": computed}}


def _body_hash(body) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def _evidence_hashes() -> dict:
    ev_dir = ROOT / "evidence"
    out = {}
    if ev_dir.exists():
        for p in sorted(ev_dir.glob("*.json")):
            out[f"evidence/{p.name}"] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def run(release: bool = False):
    m, _ = load_manifest(validate=True)
    order, by_id = toposort(m["gates"])
    cur_manifest = manifest_sha256()
    cur_lock = (hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()
                if LOCK_PATH.exists() else "NO_LOCK")
    status = {}
    for gid in order:
        gate = by_id[gid]
        blocked = [d for d in gate["depends_on"] if status[d]["status"] != "PASS"]
        if blocked:
            status[gid] = {"status": "PENDING", "reason": f"blocked_by={blocked}"}
            continue
        if gate["predicate"] == "evidence_gate":
            status[gid] = eval_evidence_gate(gate, cur_manifest, cur_lock, m)
            continue
        try:
            ok, ev = PREDICATES[gate["predicate"]]()
            status[gid] = {"status": "PASS" if ok else "FAIL", "evidence": ev}
        except Exception as exc:
            status[gid] = {"status": "FAIL", "error": f"{type(exc).__name__}: {exc}"}

    env_lock = ROOT / "locks/environment.lock"
    envelope = {
        "run_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "mode": "release" if release else "readiness",
        "manifest_sha256": cur_manifest,
        "input_lock_sha256": cur_lock,
        "environment_lock_sha256": (hashlib.sha256(env_lock.read_bytes()).hexdigest()
                                    if env_lock.exists() else "NO_ENV_LOCK"),
        "python": platform.python_version(),
        "optimize_flag": sys.flags.optimize,
    }
    envelope["run_id"] = hashlib.sha256(json.dumps(envelope, sort_keys=True).encode()).hexdigest()[:16]

    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    chain_path = build / "attestation_chain.log"
    prev = "GENESIS"
    if chain_path.exists():
        lines = chain_path.read_text().strip().splitlines()
        if lines:
            prev = lines[-1].split("body=")[-1].strip()
    body = {"attestation": envelope, "prev_body_sha256": prev,
            "topological_order": order, "gates": status}
    bh = _body_hash(body)
    (build / "gate_status.json").write_text(
        json.dumps({"body": body, "body_sha256": bh}, indent=2, default=str))
    with open(chain_path, "a") as f:
        f.write(f"{envelope['run_utc']} run_id={envelope['run_id']} prev={prev} body={bh}\n")

    n = {"PASS": 0, "FAIL": 0, "PENDING": 0}
    for s in status.values():
        n[s["status"]] += 1

    if release:
        # N9-R2 release attestation: input lock + ALL evidence + results + env
        success = (n["FAIL"] == 0 and n["PENDING"] == 0)
        attestation = {
            "attestation_kind": "p1v5_release_attestation_v1",
            "envelope": envelope,
            "success": success,
            "input_lock_sha256": cur_lock,
            "external_pins": {k: v["sha256"] for k, v in EXTERNAL_PINS.items()},
            "evidence_sha256": _evidence_hashes(),
            "gate_body_sha256": bh,
            "counts": n,
        }
        att_hash = _body_hash(attestation)
        att_doc = json.dumps({"body": attestation, "body_sha256": att_hash}, indent=2)
        attempts_dir = build / "release_attempts"
        attempts_dir.mkdir(exist_ok=True)
        (attempts_dir / f"{att_hash}.json").write_text(att_doc)   # content-addressed, immutable
        (build / "release_attestation.json").write_text(att_doc)
        if success:
            import tempfile as _tf
            with _tf.NamedTemporaryFile("w", dir=str(build), delete=False) as tf:
                tf.write(att_doc)
            __import__("pathlib").Path(tf.name).replace(build / "latest_successful_release.json")
        with open(build / "release_attempts.log", "a") as f:
            f.write(f"{envelope['run_utc']} run_id={envelope['run_id']} "
                    f"success={success} attestation={att_hash}\n")
        # T10 P1: a FAILED release attempt must never overwrite the
        # latest-success anchor; only a fully green release publishes it.
        if success:
            ATTESTATION_ANCHOR_PATH.write_text(
                att_hash + "  p1_v5 latest SUCCESSFUL release attestation\n")

    print(f"gate_runner[{'RELEASE' if release else 'readiness'}] "
          f"run_id={envelope['run_id']} PASS={n['PASS']} FAIL={n['FAIL']} PENDING={n['PENDING']}")
    for gid in order:
        print(f"  {gid:7s} {status[gid]['status']:7s} {status[gid].get('reason', '')}")
    if release:
        return 0 if (n["FAIL"] == 0 and n["PENDING"] == 0) else 2
    return 1 if n["FAIL"] else 0


def verify_status_file() -> bool:
    """Read-only (N9-R4). Detects: body edits, rehash-without-chain, chain-link
    breaks. Honest scope: producer-privilege rewrites of chain+status together
    are NOT detectable here — that is what git history and auditor snapshots
    are for."""
    p = ROOT / "build/gate_status.json"
    chain_path = ROOT / "build/attestation_chain.log"
    if not p.exists() or not chain_path.exists():
        return False
    doc = json.loads(p.read_text())
    if _body_hash(doc["body"]) != doc["body_sha256"]:
        return False
    lines = chain_path.read_text().strip().splitlines()
    if not lines:
        return False
    tip = lines[-1].split("body=")[-1].strip()
    if tip != doc["body_sha256"]:
        return False
    prev = "GENESIS"
    for line in lines:
        got_prev = line.split("prev=")[-1].split(" body=")[0].strip()
        if got_prev != prev:
            return False
        prev = line.split("body=")[-1].strip()
    return True


def verify_release_attestation() -> bool:
    """Read-only verifier: reads the durable latest_successful_release.json
    (R11-10), immune to later failed attempts overwriting the working file."""
    p = ROOT / "build/latest_successful_release.json"
    if not p.exists() or not ATTESTATION_ANCHOR_PATH.exists():
        return False
    doc = json.loads(p.read_text())
    if _body_hash(doc["body"]) != doc["body_sha256"]:
        return False
    if doc["body"].get("success") is not True:
        return False
    return ATTESTATION_ANCHOR_PATH.read_text().split()[0] == doc["body_sha256"]


RUNNER_PREDICATES = dict(PREDICATES)

if __name__ == "__main__":
    raise SystemExit(run(release="--release" in sys.argv))
