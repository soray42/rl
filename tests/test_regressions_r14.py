"""Round-14 counterexamples reversed (phase_b1/19_p1_v552_fourteenth_delta_audit/).

R14-2: confirmatory analysis consumes a content-addressed bundle; y derives
       from opened market receipts; q derives from opened transcript bundles;
       family derives from the frozen rule; provenance distinguishes worlds.
R14-3: the frozen cutoff PARTICIPATES; late-settling markets must be censored.
R14-4: alpha/delta/n_boot come from the manifest — the confirmatory signature
       has no statistical parameters at all; boot seed derives from a schedule.
R14-1: classifier checkpoint resume keeps receipts (P1-14-1).
R14-5: G6 needs opened simulator/raw-results referents + genesis re-execution.
R14-6: the audit's 25-identical-receipt-files fixture must now FAIL.
P1-14-4: settlement yield follows the UMA clock across an ISO-week boundary.
"""

import datetime
import hashlib
import inspect
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT / "tools"), str(ROOT), str(ROOT / "tests")):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5 import confirmatory  # noqa: E402
from p1v5.analysis import MIN_FAMILIES, MIN_TRAJ_PER_ARM, assign_trajectories  # noqa: E402
from p1v5.checks import CANONICAL_ARMS  # noqa: E402
from p1v5.confirmatory import ConfirmatoryError, analyze_confirmatory  # noqa: E402

FIXED_ROOT = "f" * 64
CUTOFF = "2026-08-01T00:00:00+00:00"
EPOCH_JUL1 = 1782864000          # 2026-07-01 00:00:00 UTC (pre-cutoff)
EPOCH_SEP15 = 1789430400         # 2026-09-15 00:00:00 UTC (post-cutoff)


def _frozen_manifest():
    m, _ = confirmatory.load_manifest.__wrapped__() if hasattr(
        confirmatory.load_manifest, "__wrapped__") else (None, None)
    return m


def fixture_manifest(cutoff_status="FROZEN", delta_status="FROZEN", n_boot=200):
    m = json.loads((ROOT / "manifest.json").read_text())
    m["estimand"]["contrasts"]["smallest_worthwhile_effect"] = {
        "status": delta_status, "value": 0.01 if delta_status == "FROZEN" else None,
        "freeze_procedure": "test fixture"}
    m["clocks"]["follow_up_cutoff_utc"] = {
        "status": cutoff_status, "value": CUTOFF if cutoff_status == "FROZEN" else None,
        "freeze_procedure": "test fixture"}
    m["estimand"]["contrasts"]["n_boot"] = n_boot     # fixture speed only
    return m


def _patched(manifest):
    """Patch confirmatory's manifest/root loading (test injection lives in the
    test harness, never on the runtime API — that asymmetry is the point)."""
    return (mock.patch.object(confirmatory, "load_manifest",
                              lambda validate=False: (manifest, None)),
            mock.patch.object(confirmatory, "manifest_sha256", lambda: FIXED_ROOT))


def mk_bundle(tmp, y_outcome="yes", root=FIXED_ROOT, fam_relabel=False,
              late_market=False, censor_late=False, n_fam=MIN_FAMILIES,
              k_per_arm=MIN_TRAJ_PER_ARM):
    """A complete, internally honest analysis bundle."""
    bdir = Path(tmp) / "bundle"
    (bdir / "transcripts").mkdir(parents=True)
    ledger = assign_trajectories(root, k_per_arm)
    fams = [f"EV{j}" for j in range(n_fam)]
    markets = [(f"{fam}-m{k}", fam) for fam in fams for k in range(2)]
    if late_market:
        markets.append(("LATE-m", "EVLATE"))
        fams.append("EVLATE")

    receipts, enrollment, registry_rows, censoring = [], [], [], []
    for mid, fam in markets:
        late = mid.startswith("LATE")
        receipts.append({"market_id": mid, "uma_status": "resolved",
                         "outcome_gamma_coarse": y_outcome,
                         "uma_end": EPOCH_SEP15 if late else EPOCH_JUL1,
                         "event_ids": [fam],
                         "raw_archive_sha256": "0" * 64})
        enrollment.append({"market_id": mid,
                           "family_id": ("FAKE-" + fam) if fam_relabel else fam})
        if late and censor_late:
            censoring.append({"market_id": mid, "reason": "unresolved_at_cutoff",
                              "cutoff_utc": CUTOFF})
    for fam in fams:
        registry_rows.append({"event_id": fam, "title": f"event {fam}"})

    fore_rows = []
    for e in ledger:
        for mid, fam in markets:
            if mid.startswith("LATE"):
                continue                     # censored markets have no rows
            q = 0.3 if e["arm"] == "diff_agent_credit" else 0.35
            # r5-F1/F2: one transcript per trajectory (meta names it) and the
            # q must be DERIVABLE: round-2 message -> parse -> median == final_q
            tb = {"schema_version": "transcript_bundle_v1", "question_id": mid,
                  "meta": {"arm": e["arm"], "trajectory_id": e["trajectory_id"],
                           "epistemic_status": "DEV_NONCAUSAL"},
                  "messages": [["agent-0", 2, f"reasoning stub\nFINAL: {q}"]],
                  "votes": {"agent-0": repr(q)}, "final_q": repr(q),
                  "failure_class": None, "prompt_shas": ["a" * 64],
                  "receipts": [{"backend": "stub", "model": "m", "purpose": "round2",
                                "prompt_sha": "a" * 64, "output_sha": "b" * 64,
                                "prompt_chars": 1, "output_chars": 1, "latency_ms": 0,
                                "prompt_tokens": 1, "completion_tokens": 1,
                                "provider": "x", "failure_class": ""}]}
            bb = json.dumps(tb, sort_keys=True).encode()
            tsha = hashlib.sha256(bb).hexdigest()
            (bdir / "transcripts" / f"{tsha}.json").write_bytes(bb)
            fore_rows.append({"trajectory_id": e["trajectory_id"], "arm": e["arm"],
                              "market_id": mid,
                              "family_id": enrollment[[m for m, _ in markets].index(mid)]["family_id"],
                              "transcript_bundle_sha256": tsha})

    def w(name, rows, header=None):
        with open(bdir / name, "w") as f:
            if header is not None:
                f.write(json.dumps(header) + "\n")
            for r in rows:
                f.write(json.dumps(r) + "\n")

    w("assignment.jsonl", ledger)
    w("enrollment.jsonl", enrollment)
    w("market_receipts.jsonl", receipts)
    w("forecasts.jsonl", fore_rows)
    w("censoring.jsonl", censoring)
    w("registry.jsonl", registry_rows,
      header={"_lineage": {"batch_id": "b", "batch_manifest_sha256": "0" * 64,
                           "allowed_use": "g5a_candidate",
                           "source_markets": "m", "source_events": "e"}})
    files = {n: hashlib.sha256((bdir / n).read_bytes()).hexdigest()
             for n in confirmatory.BUNDLE_FILES}
    (bdir / "bundle_manifest.json").write_text(json.dumps(
        {"schema_version": "analysis_bundle_v1", "prereg_root_hash": root,
         "files": files}))
    return bdir


class TestConfirmatoryBundle(unittest.TestCase):
    """R14-2: derivation, not agreement."""

    def test_signature_has_no_statistical_or_trust_parameters(self):
        # R14-4: nothing on the confirmatory API can override the manifest
        params = list(inspect.signature(analyze_confirmatory).parameters)
        self.assertEqual(params, ["bundle_dir"])

    def test_happy_path_full_provenance(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp)
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            out = analyze_confirmatory(b)
        pv = out["_provenance"]
        self.assertEqual(pv["epistemic_status"], "CONFIRMATORY")
        self.assertEqual(sorted(pv["ledger_sha256"]), sorted(confirmatory.BUNDLE_FILES))
        for key in ("analysis_code_sha256", "confirmatory_code_sha256",
                    "bootstrap_seed", "alpha", "delta", "n_boot",
                    "follow_up_cutoff_utc", "inputs_digest_sha256"):
            self.assertIn(key, pv)
        self.assertEqual(pv["alpha"], 0.05)
        self.assertEqual(pv["follow_up_cutoff_utc"], CUTOFF)

    def test_y_flip_worlds_are_distinguishable(self):
        # the audit's core counterexample: flipped outcomes MUST differ in
        # provenance now (the receipts file sha is part of it)
        t1, t2 = tempfile.mkdtemp(), tempfile.mkdtemp()
        b1, b2 = mk_bundle(t1, y_outcome="yes"), mk_bundle(t2, y_outcome="no")
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            o1, o2 = analyze_confirmatory(b1), analyze_confirmatory(b2)
        self.assertNotEqual(o1["_provenance"]["ledger_sha256"]["market_receipts.jsonl"],
                            o2["_provenance"]["ledger_sha256"]["market_receipts.jsonl"])
        self.assertNotEqual(o1["_provenance"]["inputs_digest_sha256"],
                            o2["_provenance"]["inputs_digest_sha256"])
        self.assertNotEqual(o1["_provenance"]["bootstrap_seed"],
                            o2["_provenance"]["bootstrap_seed"])

    def test_receipt_tamper_without_manifest_fails(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp)
        rows = (b / "market_receipts.jsonl").read_text().replace('"yes"', '"no"')
        (b / "market_receipts.jsonl").write_text(rows)
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            with self.assertRaises(ConfirmatoryError):
                analyze_confirmatory(b)

    def test_transcript_tamper_fails(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp)
        victim = sorted((b / "transcripts").glob("*.json"))[0]
        doc = json.loads(victim.read_text())
        doc["final_q"] = "0.99"
        victim.write_text(json.dumps(doc, sort_keys=True))
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            with self.assertRaises(ConfirmatoryError):
                analyze_confirmatory(b)

    def test_family_relabel_fails_frozen_rule(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp, fam_relabel=True)
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            with self.assertRaises(ConfirmatoryError) as cm:
                analyze_confirmatory(b)
        self.assertIn("family relabel", str(cm.exception))

    def test_wrong_root_fails(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp, root="e" * 64)     # ledger honest for THIS root
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:                          # frozen root is FIXED_ROOT
            with self.assertRaises(ConfirmatoryError):
                analyze_confirmatory(b)


class TestCutoffParticipates(unittest.TestCase):
    """R14-3: the audit's late-settlement counterexample."""

    def test_refuses_while_cutoff_pending(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp)
        p1, p2 = _patched(fixture_manifest(cutoff_status="PENDING"))
        with p1, p2:
            with self.assertRaises(ConfirmatoryError) as cm:
                analyze_confirmatory(b)
        self.assertIn("R14-3", str(cm.exception))

    def test_refuses_while_delta_pending(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp)
        p1, p2 = _patched(fixture_manifest(delta_status="PENDING"))
        with p1, p2:
            with self.assertRaises(ConfirmatoryError) as cm:
                analyze_confirmatory(b)
        self.assertIn("R14-4", str(cm.exception))

    def test_real_repo_manifest_currently_refuses(self):
        # honest state today: delta and cutoff are PENDING in the repo manifest,
        # so the confirmatory entry refuses to produce ANY result
        with self.assertRaises(ConfirmatoryError):
            analyze_confirmatory(tempfile.mkdtemp())

    def test_late_settlement_without_censor_fails(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp, late_market=True, censor_late=False)
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            with self.assertRaises(ConfirmatoryError) as cm:
                analyze_confirmatory(b)
        self.assertIn("R14-3", str(cm.exception))

    def test_late_settlement_with_censor_runs_and_excludes(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp, late_market=True, censor_late=True)
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            out = analyze_confirmatory(b)
        self.assertEqual(out["_provenance"]["n_eligible_markets"],
                         2 * MIN_FAMILIES)      # LATE-m excluded


class TestClassifierCheckpointResume(unittest.TestCase):
    """P1-14-1: resumed labels keep their receipts; zero re-calls."""

    def test_full_cache_resume_preserves_provenance(self):
        import classify_events
        calls = {"n": 0}

        class StubClassifier:
            def __init__(self, *a, **k):
                pass
            def complete(self, prompt, seed, purpose, max_tokens=None):
                from p1v5.deliberation import CallReceipt
                calls["n"] += 1
                text = "0:c\n1:h"
                rec = CallReceipt("stub", "m", purpose,
                                  hashlib.sha256(prompt.encode()).hexdigest(),
                                  hashlib.sha256(text.encode()).hexdigest(),
                                  len(prompt), len(text), 0, 100, 50, "stub")
                return text, rec

        tmp = Path(tempfile.mkdtemp())
        reg = tmp / "reg.jsonl"
        reg.write_text(json.dumps({"_lineage": {"batch_id": "b",
                                                "batch_manifest_sha256": "a" * 64,
                                                "allowed_use": "dev_lower_bound",
                                                "source_markets": "m", "source_events": "e"}}) + "\n"
                       + json.dumps({"event_id": "E1", "title": "War in X?",
                                     "topic": "unclassified", "series_key": "k",
                                     "n_settled": 1}) + "\n"
                       + json.dumps({"event_id": "E2", "title": "NBA winner?",
                                     "topic": "excluded", "series_key": "k2",
                                     "n_settled": 1}) + "\n")
        env = {"P1V5_REGISTRY": str(reg)}
        with mock.patch.object(classify_events, "VIEWS", tmp), \
             mock.patch.object(classify_events, "OpenRouterBackend", StubClassifier), \
             mock.patch.dict(os.environ, env):
            s1 = classify_events.main()
            first_calls = calls["n"]
            s2 = classify_events.main()       # full-cache resume
        self.assertGreaterEqual(first_calls, 1)
        self.assertEqual(calls["n"], first_calls)      # ZERO new backend calls
        self.assertEqual(s2["n_labeled"], 2)
        self.assertEqual(s2["llm_calls"], s1["llm_calls"])   # receipts preserved
        top = sorted(tmp.glob("llm_topics_2*.jsonl"))[-1]
        lin = json.loads(open(top).readline())["_lineage"]
        self.assertEqual(lin["n_llm_calls"], s1["llm_calls"])   # never 0


class TestG6ReferentChain(unittest.TestCase):
    """R14-5: the audit's fabricated-summary evidence must die; a real chain
    is accepted up to the (honestly failing) power verdict."""

    def _eval(self, doc_metrics):
        from p1v5.config import manifest_sha256
        from p1v5.checks import LOCK_PATH
        from p1v5.gate_runner import eval_evidence_gate
        m_sha = manifest_sha256()
        l_sha = hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()
        tmp = Path(tempfile.mkdtemp())
        doc = {"produced_by": "r14-test", "produced_at_utc": "2026-07-24T00:00:00+00:00",
               "inputs": {"manifest_sha256": m_sha, "input_lock_sha256": l_sha},
               "metrics": doc_metrics, "verdict": "FAIL"}
        ep = tmp / "g6.json"
        ep.write_text(json.dumps(doc))
        return eval_evidence_gate({"id": "G6", "evidence_path": str(ep)}, m_sha, l_sha)

    def test_fabricated_summary_only_evidence_fails_schema(self):
        delta_sha = hashlib.sha256((ROOT / "docs/delta_decision.md").read_bytes()).hexdigest()
        r = self._eval({"type1_ucb": 0.0, "power_lcb": 1.0, "n_sims": 1000,
                        "delta_frozen_sha256": delta_sha})
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("schema", r["reason"])

    def test_real_chain_verifies_and_genesis_check_bites(self):
        import g6_simulation as g6
        import json as _j
        manifest = _j.loads((ROOT / "manifest.json").read_text())
        dgp = {"root_prefix": "r14-test", "n_fam": MIN_FAMILIES,
               "k_per_arm": MIN_TRAJ_PER_ARM, "fam_sd": 0.02, "noise_sd": 0.01,
               "delta": 0.01, "alpha": manifest["estimand"]["contrasts"]["alpha"],
               "n_boot": manifest["estimand"]["contrasts"]["n_boot"]}
        # r5-F3: the gate now spot-checks sha-derived indices too, so every
        # row in this tiny fixture must be genuinely computed
        rows = [g6.run_replicate(dgp, s, i)
                for s in ("null", "effect") for i in (0, 1)]
        n_sims = 2
        tmp = Path(tempfile.mkdtemp())
        rp = tmp / "raw.jsonl"
        rp.write_text("".join(json.dumps(r) + "\n" for r in rows))
        s = g6.summarize(rows, n_sims)
        delta_sha = hashlib.sha256((ROOT / "docs/delta_decision.md").read_bytes()).hexdigest()
        metrics = {"type1_ucb": s["type1_ucb"], "power_lcb": max(0.0, s["power_lcb"]),
                   "n_sims": n_sims, "delta_frozen_sha256": delta_sha,
                   "simulator_sha256": hashlib.sha256(
                       (ROOT / "tools/g6_simulation.py").read_bytes()).hexdigest(),
                   "analysis_code_sha256": hashlib.sha256(
                       (ROOT / "src/p1v5/analysis.py").read_bytes()).hexdigest(),
                   "raw_results_path": str(rp),
                   "raw_results_sha256": hashlib.sha256(rp.read_bytes()).hexdigest(),
                   "dgp": dgp,
                   "seed_schedule": "seed=int(sha256(root_prefix|g6|scenario|i)[:16],16)"}
        r = self._eval(metrics)
        # chain fully verified; verdict honestly FAIL (n_sims 2 < 1000)
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("machine-derived verdict is FAIL", r["reason"])
        # genesis check: tamper replicate-0's tau (decisions untouched, so the
        # summary still recomputes) and re-hash legally -> genesis must bite
        rows[0]["tau_C1"] = 0.123456789
        rp.write_text("".join(json.dumps(x) + "\n" for x in rows))
        metrics2 = dict(metrics,
                        raw_results_sha256=hashlib.sha256(rp.read_bytes()).hexdigest())
        r2 = self._eval(metrics2)
        self.assertEqual(r2["status"], "FAIL")
        self.assertIn("genesis", r2["reason"])


class TestG7aIdenticalBundlesDie(unittest.TestCase):
    """R14-6: the audit's 25-identical-token-files shape must FAIL."""

    def test_identical_receipt_only_files_fail(self):
        sys.path.insert(0, str(ROOT / "tests"))
        from test_regressions_r11 import TestG7aSourceBinding
        t = TestG7aSourceBinding("test_correct_binding_passes")
        src, rep = t._mk_source()
        td = Path(rep["transcript_dir"])
        blob = json.dumps({"receipts": [{"purpose": "round1", "prompt_tokens": 4000,
                                         "completion_tokens": 2000}]}).encode()
        sha = hashlib.sha256(blob).hexdigest()
        for key in rep["transcript_bundles"]:
            arm, _, qid = key.partition("/")
            (td / f"{arm}_{qid}.json").write_bytes(blob)
            rep["transcript_bundles"][key] = sha
        src.write_text(json.dumps(rep))
        from p1v5 import gate_runner
        from p1v5.gate_runner import eval_evidence_gate
        import uuid
        prc = ROOT / "evidence_src/pricing_v1.json"
        rb = hashlib.sha256(json.dumps(sorted(rep["transcript_bundles"].values())).encode()).hexdigest()
        metrics = {"cost_usd_estimate": rep["est_total_cost_usd"],
                   "cost_error_pct": 1.67, "n_dry_run_events": rep["n_questions"],
                   "source_report_sha256": hashlib.sha256(src.read_bytes()).hexdigest(),
                   "pricing_table_sha256": hashlib.sha256(prc.read_bytes()).hexdigest(),
                   "receipt_bundle_sha256": rb}
        doc = {"produced_by": "r14-test", "produced_at_utc": "2026-07-24T00:00:00+00:00",
               "inputs": {"manifest_sha256": "b" * 64, "input_lock_sha256": "c" * 64},
               "metrics": metrics, "verdict": "PASS"}
        p = ROOT / "build" / f"tmp_r14_{uuid.uuid4().hex}.json"
        p.write_text(json.dumps(doc))
        gate_runner.G7A_SOURCE_PATH = src
        try:
            r = eval_evidence_gate({"id": "G7a", "evidence_path": str(p.relative_to(ROOT))},
                                   "b" * 64, "c" * 64)
        finally:
            p.unlink()
            src.unlink()
            gate_runner.G7A_SOURCE_PATH = gate_runner.ROOT / "evidence_src/micro_pilot_live.json"
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("schema", r["reason"])


class TestYieldClockCrossWeek(unittest.TestCase):
    """P1-14-4: close in W26, UMA resolution in W27 — yield counts W27."""

    def test_cross_week_boundary(self):
        import build_panel
        sys.path.insert(0, str(ROOT / "tests"))
        from test_regressions_shadow3 import TestPanelLineage
        helper = TestPanelLineage("test_panel_propagates_lineage")
        tmp = Path(tempfile.mkdtemp())
        reg, top = helper._mk_inputs(tmp)
        close_w26 = int(datetime.datetime(2026, 6, 26, 12,
                                          tzinfo=datetime.timezone.utc).timestamp())
        uma_w27 = int(datetime.datetime(2026, 7, 1, 12,
                                        tzinfo=datetime.timezone.utc).timestamp())
        lines = reg.read_text().splitlines()
        row = json.loads(lines[1])
        row["last_close"], row["last_uma_end_binary"] = close_w26, uma_w27
        reg.write_text(lines[0] + "\n" + json.dumps(row) + "\n")
        # topics lineage must re-link to the edited registry
        tlines = top.read_text().splitlines()
        tlin = json.loads(tlines[0])
        tlin["_lineage"]["registry_sha256"] = hashlib.sha256(reg.read_bytes()).hexdigest()
        top.write_text(json.dumps(tlin) + "\n" + "\n".join(tlines[1:]) + "\n")
        env = {"P1V5_REGISTRY": str(reg), "P1V5_TOPICS": str(top)}
        with mock.patch.object(build_panel, "VIEWS", tmp), \
             mock.patch.dict(os.environ, env):
            s = build_panel.main()
        weeks = s["settlement_yield_recent_weeks_uma_end_clock"]
        self.assertIn("2026-W27", weeks)
        self.assertNotIn("2026-W26", weeks)


if __name__ == "__main__":
    unittest.main(verbosity=2)
