"""Round-13 counterexamples reversed (phase_b1/18_p1_v55_thirteenth_delta_audit/).

P0-13-1 keyset four false-positive shapes -> all INCOMPLETE now.
P0-13-2 allowed_use is machine-derived; contradictory manifests refused.
P0-13-3 G5a referent chain: batch/registry/panel opened, re-hashed, recomputed.
P0-13-4 caller-supplied loss forbidden; the audit's harm->benefit flip raises.
P0-13-5 analyze_coprimary REQUIRES the frozen root (no optional bypass).
P0-13-6 censoring enum/UTC/single-cutoff + settlement-XOR-censoring closure.
P0-13-8 G7a NaN strict-parse + bundle files opened and re-summed.
P0-13-9 message:null is a typed BackendFailure; failure receipts carry class.
"""

import hashlib
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

from p1v5.analysis import (AnalysisError, analyze_coprimary,  # noqa: E402
                           assign_trajectories, reconcile_ledgers)

RESOLVED = "2026-07-01T00:00:00+00:00"


def _world():
    """One wave, one family, one market; ledger from the frozen schedule."""
    root = "r13-root"
    led = assign_trajectories(root, 1)
    enr = [{"market_id": "m0", "family_id": "f0"}]
    stl = [{"market_id": "m0", "y": 1, "resolved_at_utc": RESOLVED}]
    recs = [{"trajectory_id": e["trajectory_id"], "arm": e["arm"],
             "family_id": "f0", "market_id": "m0", "q": 0.5} for e in led]
    return root, led, enr, stl, recs


class TestKeysetFailClosed(unittest.TestCase):
    """P0-13-1: the audit's four reproduced complete=True shapes."""

    def _probe(self, body):
        import full_pull
        with mock.patch.object(full_pull, "_get", return_value=("u", body)), \
             mock.patch.object(full_pull, "_archive", lambda *a, **k: None), \
             mock.patch.object(full_pull, "DATA", Path(tempfile.mkdtemp())):
            return full_pull.fetch_keyset("/markets", {}, "probe", max_pages=3)

    def test_empty_page_with_cursor_incomplete(self):
        recs, complete = self._probe(b'{"markets": [], "next_cursor": "abc"}')
        self.assertFalse(complete)

    def test_wrong_endpoint_key_incomplete(self):
        recs, complete = self._probe(b'{"events": [{"id": "E1"}], "next_cursor": null}')
        self.assertFalse(complete)

    def test_intrapage_duplicate_ids_incomplete(self):
        recs, complete = self._probe(
            b'{"markets": [{"id": "1"}, {"id": "1"}], "next_cursor": null}')
        self.assertFalse(complete)

    def test_missing_ids_incomplete(self):
        recs, complete = self._probe(
            b'{"markets": [{"x": 1}, {"y": 2}], "next_cursor": null}')
        self.assertFalse(complete)

    def test_clean_final_page_still_completes(self):
        recs, complete = self._probe(
            b'{"markets": [{"id": "1"}, {"id": "2"}], "next_cursor": null}')
        self.assertTrue(complete)
        self.assertEqual(len(recs), 2)


class TestAllowedUseMachineDerived(unittest.TestCase):
    """P0-13-2: a g5a_candidate label over an incomplete channel is refused."""

    def test_contradictory_label_refused(self):
        import event_registry
        tmp = Path(tempfile.mkdtemp())
        views = tmp / "views"
        views.mkdir()
        (views / "full_x_markets.jsonl").write_text(
            json.dumps({"market_id": "m1", "event_ids": ["E1"], "question": "q",
                        "uma_status": "resolved", "outcome_gamma_coarse": "yes",
                        "closed_time": 1750000000}) + "\n")
        (views / "full_x_events.jsonl").write_text(
            json.dumps({"event_id": "E1", "title": "t", "tags": [], "neg_risk": False,
                        "volume": 1}) + "\n")
        bm = {"batch_id": "b", "allowed_use": "g5a_candidate",     # LIE
              "channel_complete": {"incomplete_reasons": ["closed-keyset-incomplete"]},
              "files": {k: hashlib.sha256((views / k).read_bytes()).hexdigest()
                        for k in ("full_x_markets.jsonl", "full_x_events.jsonl")}}
        bmp = tmp / "bm.json"
        bmp.write_text(json.dumps(bm))
        env = {"P1V5_BATCH_MANIFEST": str(bmp), "P1V5_ALLOW_SMALL_PULL": "1"}
        with mock.patch.object(event_registry, "VIEWS", views), \
             mock.patch.dict(os.environ, env):
            with self.assertRaises(SystemExit):
                event_registry.main()


class TestLossRecomputed(unittest.TestCase):
    """P0-13-4: the audit's direction-flip — q=0 vs y=1 self-reported as loss=0."""

    def test_self_reported_loss_flip_rejected(self):
        root, led, enr, stl, recs = _world()
        for r in recs:
            if r["arm"] == "diff_agent_credit":
                r["q"] = 0.0
                r["loss"] = 0.0        # true Brier vs y=1 is 1.0 — the flip
        with self.assertRaises(AnalysisError) as cm:
            reconcile_ledgers(recs, led, enr, prereg_root_hash=root, settlement=stl)
        self.assertIn("self-reported loss", str(cm.exception))

    def test_record_without_q_rejected(self):
        root, led, enr, stl, recs = _world()
        del recs[0]["q"]
        with self.assertRaises(AnalysisError):
            reconcile_ledgers(recs, led, enr, prereg_root_hash=root, settlement=stl)

    def test_settlement_ledger_required(self):
        root, led, enr, stl, recs = _world()
        with self.assertRaises(AnalysisError):
            reconcile_ledgers(recs, led, enr, prereg_root_hash=root)

    def test_derived_loss_is_brier(self):
        root, led, enr, stl, recs = _world()
        out = reconcile_ledgers(recs, led, enr, prereg_root_hash=root, settlement=stl)
        for r in out["records"]:
            self.assertAlmostEqual(r["loss"], 0.25)     # (0.5 - 1)^2


class TestConfirmatoryApiHardRequirements(unittest.TestCase):
    """P0-13-5/13-6: root and lineage are REQUIRED, not optional."""

    def _full(self, **overrides):
        from test_analysis import synth_records
        recs, led, enr, stl = synth_records(0.0, 0.0, n_fam=10, k_per_arm=6,
                                            with_ledgers=True)
        kw = dict(assignment_ledger=led, enrollment=enr, settlement=stl,
                  prereg_root_hash="root" * 16,
                  enrollment_lineage={"registry_sha256": "0" * 64})
        kw.update(overrides)
        return recs, kw

    def test_missing_root_rejected(self):
        recs, kw = self._full(prereg_root_hash=None)
        with self.assertRaises(AnalysisError):
            analyze_coprimary(recs, delta=0.05, n_boot=100, seed=1, **kw)

    def test_missing_settlement_rejected(self):
        recs, kw = self._full(settlement=None)
        with self.assertRaises(AnalysisError):
            analyze_coprimary(recs, delta=0.05, n_boot=100, seed=1, **kw)

    def test_missing_lineage_rejected(self):
        recs, kw = self._full(enrollment_lineage=None)
        with self.assertRaises(AnalysisError):
            analyze_coprimary(recs, delta=0.05, n_boot=100, seed=1, **kw)

    def test_full_bundle_passes_and_carries_provenance(self):
        recs, kw = self._full()
        out = analyze_coprimary(recs, delta=0.05, n_boot=200, seed=1, **kw)
        self.assertEqual(out["_provenance"]["prereg_root_hash"], "root" * 16)
        self.assertEqual(out["_provenance"]["enrollment_registry_sha256"], "0" * 64)


class TestCensoringSemantics(unittest.TestCase):
    """P0-13-6: the audit's empty-reason/null-cutoff row and its cousins."""

    def _base(self):
        root, led, enr, stl, recs = _world()
        enr = enr + [{"market_id": "m1", "family_id": "f0"}]
        return root, led, enr, stl, recs

    def test_empty_reason_rejected(self):
        root, led, enr, stl, recs = self._base()
        cen = [{"market_id": "m1", "reason": "", "cutoff_utc": None}]   # audit verbatim
        with self.assertRaises(AnalysisError):
            reconcile_ledgers(recs, led, enr, cen, prereg_root_hash=root, settlement=stl)

    def test_invalid_cutoff_rejected(self):
        root, led, enr, stl, recs = self._base()
        cen = [{"market_id": "m1", "reason": "unresolved_at_cutoff", "cutoff_utc": "yesterday"}]
        with self.assertRaises(AnalysisError):
            reconcile_ledgers(recs, led, enr, cen, prereg_root_hash=root, settlement=stl)

    def test_two_cutoffs_rejected(self):
        root, led, enr, stl, recs = self._base()
        enr.append({"market_id": "m2", "family_id": "f0"})
        cen = [{"market_id": "m1", "reason": "unresolved_at_cutoff",
                "cutoff_utc": "2026-08-01T00:00:00+00:00"},
               {"market_id": "m2", "reason": "unresolved_at_cutoff",
                "cutoff_utc": "2026-08-02T00:00:00+00:00"}]
        with self.assertRaises(AnalysisError):
            reconcile_ledgers(recs, led, enr, cen, prereg_root_hash=root, settlement=stl)

    def test_settled_and_censored_conflict_rejected(self):
        root, led, enr, stl, recs = _world()
        cen = [{"market_id": "m0", "reason": "unresolved_at_cutoff",
                "cutoff_utc": "2026-08-01T00:00:00+00:00"}]
        with self.assertRaises(AnalysisError):
            reconcile_ledgers(recs, led, enr, cen, prereg_root_hash=root, settlement=stl)

    def test_unaccounted_enrolled_market_rejected(self):
        root, led, enr, stl, recs = self._base()   # m1 enrolled, unsettled, uncensored
        with self.assertRaises(AnalysisError):
            reconcile_ledgers(recs, led, enr, prereg_root_hash=root, settlement=stl)

    def test_valid_censoring_accepted(self):
        root, led, enr, stl, recs = self._base()
        cen = [{"market_id": "m1", "reason": "unresolved_at_cutoff",
                "cutoff_utc": "2026-08-01T00:00:00+00:00"}]
        out = reconcile_ledgers(recs, led, enr, cen, prereg_root_hash=root, settlement=stl)
        self.assertEqual(out["eligible"], ["m0"])


class TestG5aReferentChain(unittest.TestCase):
    """P0-13-3: G5a evidence PASSes only over real, linked, recomputable files."""

    def _mk_referents(self, tmp, allowed="g5a_candidate", reasons=(), n_series=(4, 7)):
        bm = {"batch_id": "b", "allowed_use": allowed,
              "channel_complete": {"incomplete_reasons": list(reasons), "overrides": []},
              "files": {}}
        bmp = tmp / "bm.json"
        bmp.write_text(json.dumps(bm))
        bm_sha = hashlib.sha256(bmp.read_bytes()).hexdigest()
        reg = tmp / "reg.jsonl"
        reg.write_text(json.dumps({"_lineage": {"batch_id": "b",
                                                "batch_manifest_sha256": bm_sha,
                                                "allowed_use": allowed,
                                                "source_markets": "m",
                                                "source_events": "e"}}) + "\n")
        reg_sha = hashlib.sha256(reg.read_bytes()).hexdigest()
        panel = {"summary": {"lineage": {"batch_manifest_sha256": bm_sha,
                                         "batch_allowed_use": allowed,
                                         "registry_sha256": reg_sha,
                                         "topics_sha256": "0" * 64}},
                 "panel": [{"series_key": f"s{i}", "n_instances": n} for i, n in enumerate(n_series)]}
        pnp = tmp / "panel.json"
        pnp.write_text(json.dumps(panel))
        return bmp, reg, pnp, bm_sha, reg_sha

    def _eval(self, metrics_patch=None, allowed="g5a_candidate", reasons=()):
        from p1v5.config import manifest_sha256
        from p1v5.checks import LOCK_PATH
        from p1v5.gate_runner import eval_evidence_gate
        tmp = Path(tempfile.mkdtemp())
        bmp, reg, pnp, bm_sha, reg_sha = self._mk_referents(tmp, allowed, reasons)
        transitions = sum(n - 1 for n in (4, 7))       # 9
        m_sha = manifest_sha256()
        l_sha = hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()
        metrics = {"independent_family_transitions": transitions, "required_by_g6": 8,
                   "batch_allowed_use": "g5a_candidate",
                   "batch_manifest_sha256": bm_sha, "registry_sha256": reg_sha,
                   "panel_sha256": hashlib.sha256(pnp.read_bytes()).hexdigest(),
                   "batch_manifest_path": str(bmp), "registry_path": str(reg),
                   "panel_path": str(pnp)}
        metrics.update(metrics_patch or {})
        doc = {"produced_by": "r13-test", "produced_at_utc": "2026-07-23T00:00:00+00:00",
               "inputs": {"manifest_sha256": m_sha, "input_lock_sha256": l_sha},
               "metrics": metrics, "verdict": "PASS"}
        ep = tmp / "ev.json"
        ep.write_text(json.dumps(doc))
        return eval_evidence_gate({"id": "G5a", "evidence_path": str(ep)}, m_sha, l_sha)

    def test_real_linked_chain_passes(self):
        self.assertEqual(self._eval()["status"], "PASS")

    def test_dev_batch_fails(self):
        r = self._eval(allowed="dev_lower_bound",
                       reasons=("closed-keyset-incomplete",))
        self.assertEqual(r["status"], "FAIL")

    def test_candidate_label_over_incomplete_channel_fails(self):
        # batch FILE says g5a_candidate but reasons non-empty: derivation wins
        r = self._eval(allowed="g5a_candidate", reasons=("closed-keyset-incomplete",))
        self.assertEqual(r["status"], "FAIL")

    def test_tampered_transition_count_fails(self):
        r = self._eval({"independent_family_transitions": 999})
        self.assertEqual(r["status"], "FAIL")

    def test_missing_referent_fails(self):
        r = self._eval({"panel_path": "/nonexistent/panel.json"})
        self.assertEqual(r["status"], "FAIL")


class TestG7aStrictAndReceipted(unittest.TestCase):
    """P0-13-8: NaN bypass closed; bundle files must exist and re-sum."""

    def _eval_with(self, source_mutator=None):
        sys.path.insert(0, str(ROOT / "tests"))
        from test_regressions_r11 import TestG7aSourceBinding
        t = TestG7aSourceBinding("test_correct_binding_passes")
        src, rep = t._mk_source()
        if source_mutator:
            rep = source_mutator(rep)
            src.write_text(json.dumps(rep).replace('"__NAN__"', "NaN"))
        from p1v5 import gate_runner
        from p1v5.gate_runner import eval_evidence_gate
        import uuid
        prc = ROOT / "evidence_src/pricing_v1.json"
        est = rep["est_total_cost_usd"]
        act = rep["billed_cost_usd"]
        try:
            err = abs(est - act) / act * 100
        except TypeError:
            err = 1.0
        rb = hashlib.sha256(json.dumps(sorted(rep["transcript_bundles"].values())).encode()).hexdigest()
        metrics = {"cost_usd_estimate": est if isinstance(est, (int, float)) else 1.0,
                   "cost_error_pct": round(err, 2) if isinstance(err, float) else 1.0,
                   "n_dry_run_events": rep["n_questions"],
                   "source_report_sha256": hashlib.sha256(src.read_bytes()).hexdigest(),
                   "pricing_table_sha256": hashlib.sha256(prc.read_bytes()).hexdigest(),
                   "receipt_bundle_sha256": rb}
        doc = {"produced_by": "r13-test", "produced_at_utc": "2026-07-23T00:00:00+00:00",
               "inputs": {"manifest_sha256": "b" * 64, "input_lock_sha256": "c" * 64},
               "metrics": metrics, "verdict": "PASS"}
        p = ROOT / "build" / f"tmp_r13_{uuid.uuid4().hex}.json"
        p.write_text(json.dumps(doc))
        gate_runner.G7A_SOURCE_PATH = src
        try:
            return eval_evidence_gate({"id": "G7a", "evidence_path": str(p.relative_to(ROOT))},
                                      "b" * 64, "c" * 64)
        finally:
            p.unlink()
            src.unlink()
            gate_runner.G7A_SOURCE_PATH = gate_runner.ROOT / "evidence_src/micro_pilot_live.json"

    def test_nan_source_fails_strict_parse(self):
        def poison(rep):
            rep["est_total_cost_usd"] = "__NAN__"
            return rep
        r = self._eval_with(poison)
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("strict", r["reason"])

    def test_missing_bundle_file_fails(self):
        def drop_file(rep):
            td = Path(rep["transcript_dir"])
            victim = sorted(td.glob("c3_action_*.json"))[0]
            victim.unlink()
            return rep
        r = self._eval_with(drop_file)
        self.assertEqual(r["status"], "FAIL")

    def test_token_sum_mismatch_fails(self):
        def inflate(rep):
            rep["billed_prompt_tokens"] = 999999
            rep["billed_cost_usd"] = round(999999/1e6*0.09 + 50000/1e6*0.18, 4)
            rep["est_total_cost_usd"] = rep["billed_cost_usd"]
            return rep
        r = self._eval_with(inflate)
        self.assertEqual(r["status"], "FAIL")


class TestTypedFailureClosure(unittest.TestCase):
    """P0-13-9: message:null is typed; failure receipts carry failure_class."""

    def test_null_message_is_typed_backend_failure(self):
        from p1v5.deliberation import BackendFailure, OpenRouterBackend

        class FakeResp:
            def __init__(self, body):
                self.body = body
            def read(self):
                return self.body
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        body = json.dumps({"choices": [{"message": None}]}).encode()
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}):
            be = OpenRouterBackend("m", provider_pin=None)
            with mock.patch("urllib.request.urlopen", return_value=FakeResp(body)):
                with self.assertRaises(BackendFailure):
                    be.complete("p", seed=1, purpose="round1")

    def test_failure_receipt_carries_class(self):
        from p1v5.deliberation import (BackendFailure, StubBackend, TeamDeliberation,
                                       credit_c3_action_t)
        from p1v5.policy import MemoryState

        class Flaky(StubBackend):
            calls = 0
            def complete(self, prompt, seed, purpose, model="stub-1"):
                Flaky.calls += 1
                if purpose == "c3_rollout" and Flaky.calls % 4 == 0:
                    raise BackendFailure("timeout")
                return super().complete(prompt, seed, purpose, model)

        team = TeamDeliberation(Flaky(), 3)
        q = {"question_id": "q", "question": "x?"}
        t = team.run(q, ["a", "b", "c"], MemoryState(), seed=1)
        credit_c3_action_t(team, q, ["a", "b", "c"], MemoryState(), t, 1, seed=5)
        failed = [r for r in t.receipts if r.backend == "failed"]
        self.assertTrue(failed)
        self.assertTrue(all(r.failure_class == "timeout" for r in failed))
        # bundle-level distinguishability: same shape with a different class
        # must change the persisted receipt dict
        self.assertIn("failure_class", failed[0].__dict__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
