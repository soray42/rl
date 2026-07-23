"""Round-12 counterexamples reversed (phase_b1/17_p1_v55_twelfth_delta_audit/)."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT / "tools"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.analysis import (AnalysisError, analyze_coprimary,  # noqa: E402
                           assign_trajectories, reconcile_ledgers)


def _mk(n_fam=10, k=6):
    sys.path.insert(0, str(ROOT / "tests"))
    from test_analysis import synth_records
    return synth_records(0.0, 0.0, n_fam=n_fam, k_per_arm=k, with_ledgers=True)


class TestLedgerSemantics(unittest.TestCase):
    """P0-12-4: ledgers carry science, not just shapes."""

    def test_assignment_missing_wave_rejected(self):
        recs, led, enr = _mk()
        for e in led:
            e.pop("wave", None)
        with self.assertRaises(AnalysisError):
            analyze_coprimary(recs, delta=0.02, n_boot=200, seed=1,
                              assignment_ledger=led, enrollment=enr)

    def test_duplicate_assignment_id_rejected(self):
        recs, led, enr = _mk()
        led[1] = dict(led[0])                      # duplicate trajectory_id
        with self.assertRaises(AnalysisError):
            analyze_coprimary(recs, delta=0.02, n_boot=200, seed=1,
                              assignment_ledger=led, enrollment=enr)

    def test_failure_row_with_wrong_loss_rejected(self):
        recs, led, enr = _mk()
        recs[0] = dict(recs[0], failure_class="timeout", loss=0.0)
        with self.assertRaises(AnalysisError):
            analyze_coprimary(recs, delta=0.02, n_boot=200, seed=1,
                              assignment_ledger=led, enrollment=enr)

    def test_unreceipted_censoring_rejected(self):
        recs, led, enr = _mk()
        with self.assertRaises(AnalysisError):
            analyze_coprimary(recs, delta=0.02, n_boot=200, seed=1,
                              assignment_ledger=led, enrollment=enr,
                              censoring=["fam-0-m0"])       # bare string, no receipt

    def test_family_relabel_rejected(self):
        """P0-12-5: family identity is fixed by enrollment, not by result rows."""
        recs, led, enr = _mk()
        recs[0] = dict(recs[0], family_id="fam-invented")
        with self.assertRaises(AnalysisError):
            analyze_coprimary(recs, delta=0.02, n_boot=200, seed=1,
                              assignment_ledger=led, enrollment=enr)


class TestBlockedInference(unittest.TestCase):
    def test_estimator_requires_waves(self):
        from p1v5.analysis import contrast_tau
        recs, led, enr = _mk()
        with self.assertRaises(AnalysisError):
            contrast_tau(recs, "diff_agent_credit", "shared_surplus")   # no waves

    def test_analyze_still_works_with_typed_ledgers(self):
        recs, led, enr = _mk()
        out = analyze_coprimary(recs, delta=0.05, n_boot=300, seed=2,
                                assignment_ledger=led, enrollment=enr)
        for cid in ("C1", "C2"):
            self.assertIn("ci_level_nominal", out[cid])
            self.assertEqual(out[cid]["multiplicity"], "bonferroni_nominal_pending_g6")


class TestMicroPilotBundleOrdering(unittest.TestCase):
    """P0-12-6: persisted bundle contains counterfactual rollout receipts."""

    def test_bundle_receipts_include_rollouts(self):
        import micro_pilot
        import importlib
        importlib.reload(micro_pilot)
        rep = micro_pilot.run_pilot(mode="dry", n_questions=2, n_agents=3)
        self.assertEqual(rep["epistemic_status"], "DEV_NONCAUSAL")
        tdirs = sorted((ROOT / "data/transcripts").glob("*"))
        self.assertTrue(tdirs)
        c3_files = list(tdirs[-1].glob("c3_action_*.json"))
        self.assertTrue(c3_files)
        bundle = json.loads(c3_files[0].read_text())
        purposes = [r["purpose"] for r in bundle["receipts"]]
        self.assertIn("c3_rollout", purposes,
                      "bundle persisted BEFORE rollouts — r12 P0-12-6 regressed")
        # report sha equals persisted bytes sha
        import hashlib
        key = f"c3_action/{bundle['question_id']}"
        self.assertEqual(rep["transcript_bundles"][key],
                         hashlib.sha256(c3_files[0].read_bytes()).hexdigest())
        sham_files = list(tdirs[-1].glob("c3_compute_matched_sham_*.json"))
        sham_bundle = json.loads(sham_files[0].read_text())
        self.assertIsNotNone(sham_bundle["meta"]["sham_mapping"])


class TestC3TypedFailure(unittest.TestCase):
    """P0-12-7: a backend failure inside C3 rollouts must not kill the trajectory."""

    def test_c3_failure_typed(self):
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
        credits = credit_c3_action_t(team, q, ["a", "b", "c"], MemoryState(), t, 1, seed=5)
        self.assertEqual(set(credits), set(t.votes))    # trajectory survived


if __name__ == "__main__":
    unittest.main(verbosity=2)
