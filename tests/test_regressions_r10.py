"""Round-10 counterexamples reversed (phase_b1/15_p1_v5_tenth_audit/).
Covers the audit's four v5.3.1 acceptance items plus the P1 anchor rule."""

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.clocks import Ledger  # noqa: E402
from p1v5.gate_runner import (ATTESTATION_ANCHOR_PATH, PINNED_TERMS_SHA,  # noqa: E402
                              eval_evidence_gate)

CUR_M, CUR_L = "b" * 64, "c" * 64


def _eval(gate_id, metrics, raw_patch=None, evidence_path_override=None):
    doc = {"produced_by": "t-tool", "produced_at_utc": "2026-07-13T12:00:00+00:00",
           "inputs": {"manifest_sha256": CUR_M, "input_lock_sha256": CUR_L},
           "metrics": metrics, "verdict": "PASS"}
    text = json.dumps(doc)
    if raw_patch:
        text = text.replace(*raw_patch)
    import uuid
    p = ROOT / "build" / f"tmp_r10_{uuid.uuid4().hex}.json"
    p.parent.mkdir(exist_ok=True)
    p.write_text(text)
    try:
        gate = {"id": gate_id,
                "evidence_path": evidence_path_override or str(p.relative_to(ROOT))}
        return eval_evidence_gate(gate, CUR_M, CUR_L)
    finally:
        p.unlink()


class TestEvidenceSemanticsR10(unittest.TestCase):
    """Acceptance item 2: 1e999 / count contradiction / UCB>alpha / unbound hash."""

    def test_overflow_infinity_in_evidence_fails(self):
        res = _eval("G7a", {"cost_usd_estimate": "__INF__", "cost_error_pct": 0,
                            "n_dry_run_events": 5},
                    raw_patch=('"__INF__"', "1e999"))
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("finite", res["reason"])

    def test_g8_count_contradiction_fails(self):
        res = _eval("G8", {"n_fields_analyzed": 10, "n_allow": 0, "n_restrict": 0,
                           "terms_sha256": PINNED_TERMS_SHA})
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("machine-derived", res["reason"])

    def test_g6_ucb_above_manifest_alpha_fails(self):
        # manifest alpha = 0.05; the old hard-coded 0.06 gate must be gone
        res = _eval("G6", {"type1_ucb": 0.06, "power_lcb": 0.80, "n_sims": 1000,
                           "delta_frozen_sha256": "d" * 64})
        self.assertEqual(res["status"], "FAIL")

    def test_g6_unbound_delta_hash_fails(self):
        # a hash with no valid referent must FAIL. r14 strengthened this gate:
        # summary-only evidence now dies at the SCHEMA (simulator / analysis
        # code / raw results are required referents) — earlier and stricter
        # than the original "recomputable target" path, same property
        res = _eval("G6", {"type1_ucb": 0.01, "power_lcb": 0.90, "n_sims": 2000,
                           "delta_frozen_sha256": "d" * 64})
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue("recomputable target" in res["reason"]
                        or "recomputed" in res["reason"]
                        or "required property" in res["reason"], res["reason"])

    def test_g9b_wrong_search_log_hash_fails(self):
        log = ROOT / "evidence/g9b_search_log.jsonl"
        log.parent.mkdir(exist_ok=True)
        existed = log.exists()
        if not existed:
            log.write_text('{"query": "fixture"}\n')
        try:
            res = _eval("G9b", {"new_hits": 0, "intersection_touched": False,
                                "search_log_sha256": "e" * 64})
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("recomputed", res["reason"])
            good = hashlib.sha256(log.read_bytes()).hexdigest()
            res2 = _eval("G9b", {"new_hits": 0, "intersection_touched": False,
                                 "search_log_sha256": good})
            self.assertEqual(res2["status"], "PASS")
        finally:
            if not existed:
                log.unlink()

    def test_g7a_estimate_above_cap_fails(self):
        res = _eval("G7a", {"cost_usd_estimate": 9999.0, "cost_error_pct": 0,
                            "n_dry_run_events": 5})
        self.assertEqual(res["status"], "FAIL")


class TestDVMPathsR10(unittest.TestCase):
    """Acceptance item 3 (also fixtures F16/F17)."""

    def _ing(self, led, qid, seq):
        for m in seq:
            m = dict(m)
            m.setdefault("msg_id", f"{qid}-{m['kind']}-{m['t']}")
            m.setdefault("source", "s")
            m["question_id"] = qid
            led.ingest(m)

    def test_first_challenge_dvm_quarantined(self):
        led = Ledger()
        self._ing(led, "Q", [
            {"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0},
            {"kind": "proposal", "round": 1, "t": 51.0},
            {"kind": "challenge", "round": 1, "t": 52.0},
            {"kind": "dvm", "t": 53.0},
            {"kind": "finalize", "outcome": "yes", "t": 90.0},
            {"kind": "observe", "t": 91.0},
            {"kind": "apply_queue", "t": 92.0}])
        q = led.state("Q")
        self.assertTrue(q.quarantined)
        self.assertFalse(q.endpoint_eligible())
        self.assertFalse(Ledger.feedback_eligible(q, 95.0, 96.0))

    def test_second_challenge_reset_quarantined(self):
        led = Ledger()
        self._ing(led, "Q", [
            {"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0},
            {"kind": "proposal", "round": 1, "t": 51.0},
            {"kind": "challenge", "round": 1, "t": 52.0},
            {"kind": "dispute_reset", "t": 52.5},
            {"kind": "proposal", "round": 2, "t": 60.0},
            {"kind": "challenge", "round": 2, "t": 61.0},
            {"kind": "dispute_reset", "t": 61.5}])
        self.assertTrue(led.state("Q").quarantined)

    def test_nonfinite_admissibility_args_fail_closed(self):
        led = Ledger()
        self._ing(led, "Q", [{"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0}])
        q = led.state("Q")
        self.assertFalse(Ledger.forecast_admissible(q, float("-inf"), 1.0))
        self.assertFalse(Ledger.feedback_eligible(q, 1.0, float("inf")))


class TestAnchorDiscipline(unittest.TestCase):
    """T10 P1: a failed release attempt never publishes/overwrites the anchor."""

    def test_failed_release_does_not_write_anchor(self):
        from p1v5 import gate_runner
        before = (ATTESTATION_ANCHOR_PATH.read_text()
                  if ATTESTATION_ANCHOR_PATH.exists() else None)
        rc = gate_runner.run(release=True)      # current tree: PENDING gates
        self.assertEqual(rc, 2)
        after = (ATTESTATION_ANCHOR_PATH.read_text()
                 if ATTESTATION_ANCHOR_PATH.exists() else None)
        self.assertEqual(before, after, "failed release must not touch the anchor")
        attempts = (ROOT / "build/release_attempts.log").read_text()
        self.assertIn("success=False", attempts)
        gate_runner.run(release=False)          # restore readiness status file


class TestFullEvidencePresenceE2E(unittest.TestCase):
    """Acceptance item 1: with ALL canonical evidence paths occupied, the whole
    suite still runs (no canonical-path landmines)."""

    CANONICAL = ["g8_rights_matrix.json", "g4_replay_route.json",
                 "g7a_cost_micropilot.json", "g5a_yield_audit.json",
                 "g6_power_type1_sim.json", "g5b_calendar_feasibility.json",
                 "g7b_full_budget_bom.json", "g9b_final_search.json"]

    def test_suite_green_with_all_canonical_evidence_present(self):
        if os.environ.get("P1V5_E2E_CHILD") == "1":
            self.skipTest("child run")
        ev_dir = ROOT / "evidence"
        ev_dir.mkdir(exist_ok=True)
        created = []
        for name in self.CANONICAL:
            p = ev_dir / name
            if not p.exists():
                p.write_text("{}")          # presence is the point; content may be garbage
                created.append(p)
        try:
            env = dict(os.environ, P1V5_E2E_CHILD="1",
                       PYTHONPATH=str(ROOT / "src"))
            proc = subprocess.run(
                [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests"],
                cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=300)
            self.assertEqual(proc.returncode, 0,
                             f"suite failed with canonical evidence present:\n"
                             f"{proc.stderr[-2000:]}")
        finally:
            for p in created:
                p.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
