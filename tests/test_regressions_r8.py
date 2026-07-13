"""Round-8 counterexamples reversed into permanent regressions (E0 discipline).
Every test encodes an attack from phase_b1/13_p1_v5_eighth_audit/ that succeeded
against v5.1 and must now fail."""

import json
import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.checks import deep_validate  # noqa: E402
from p1v5.clocks import Ledger  # noqa: E402
from p1v5.config import load_manifest  # noqa: E402
from p1v5.scoring import ScoringError, score_stream  # noqa: E402

SRC = "collector-a"


def _ev(qid, kind, t, **kw):
    d = {"msg_id": f"{qid}-{kind}-{t}", "source": SRC, "question_id": qid,
         "kind": kind, "t": t}
    d.update(kw)
    return d


class TestNaNTotality(unittest.TestCase):
    def test_nan_timestamp_dead_lettered(self):
        led = Ledger()
        self.assertFalse(led.ingest(_ev("Q", "enroll", float("nan"),
                                        prediction_cutoff=49.0)))
        self.assertFalse(led.ingest(_ev("Q", "proposal", float("inf"), round=1)))
        self.assertEqual(len(led.dead_letter), 2)

    def test_nan_cutoff_dead_lettered(self):
        led = Ledger()
        self.assertFalse(led.ingest(_ev("Q", "enroll", 0.0,
                                        prediction_cutoff=float("nan"))))


class TestNegriskSingleStateAPI(unittest.TestCase):
    def test_state_api_cannot_bypass_group_quarantine(self):
        led = Ledger()
        for qid in ("Ga", "Gb"):
            led.ingest({"msg_id": f"{qid}-enroll", "source": SRC, "question_id": qid,
                        "kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0,
                        "group_id": "NRX"})
            led.ingest(_ev(qid, "proposal", 51.0, round=1))
            led.ingest(_ev(qid, "finalize", 53.0, outcome="yes"))
            led.ingest(_ev(qid, "observe", 54.0))
            led.ingest(_ev(qid, "apply_queue", 55.0))
        for qid in ("Ga", "Gb"):
            q = led.state(qid)                      # the r8 bypass path
            self.assertTrue(q.quarantined)
            self.assertFalse(q.endpoint_eligible())
            self.assertFalse(Ledger.feedback_eligible(q, 60.0, 61.0))


class TestMaliciousManifestShapes(unittest.TestCase):
    def _base(self):
        m, _ = load_manifest(validate=False)
        return json.loads(json.dumps(m))     # deep copy

    def test_duplicate_gates_rejected(self):
        m = self._base()
        for g in m["gates"]:
            g["id"] = "G9a"
            g["depends_on"] = []
        self.assertTrue(any("gate id set" in x for x in deep_validate(m)))

    def test_duplicate_contrasts_and_ghost_arms_rejected(self):
        m = self._base()
        m["estimand"]["contrasts"]["coprimary"] = [
            {"id": "C1", "arm_a": "ghost_x", "arm_b": "ghost_y"},
            {"id": "C1", "arm_a": "ghost_x", "arm_b": "ghost_x"}]
        v = deep_validate(m)
        self.assertTrue(any("coprimary" in x for x in v), v)

    def test_degenerate_branches_and_fields_rejected(self):
        m = self._base()
        m["estimand"]["decision_rule"]["branches"] = ["inconclusive"] * 4
        m["clocks"]["fields"] = ["x"] * 15
        m["placebo_suite"]["components"] = ["x"] * 3
        v = deep_validate(m)
        self.assertTrue(any("branches" in x for x in v))
        self.assertTrue(any("clock fields" in x for x in v))
        self.assertTrue(any("placebo" in x for x in v))

    def test_frozen_garbage_rejected(self):
        m = self._base()
        node = m["estimand"]["assignment"]["trajectories_per_arm_K"]
        node["status"], node["value"] = "FROZEN", "garbage"
        self.assertTrue(any("trajectories_per_arm_K" in x for x in deep_validate(m)))


class TestEvidenceShell(unittest.TestCase):
    def test_five_key_shell_fails(self):
        import tempfile
        from p1v5.gate_runner import eval_evidence_gate
        with tempfile.NamedTemporaryFile("w", suffix=".json", dir=str(ROOT / "build"),
                                         delete=False) as f:
            json.dump({"produced_by": None, "produced_at_utc": 0,
                       "inputs": None, "metrics": None, "verdict": "PASS"}, f)
            path = Path(f.name)
        try:
            gate = {"id": "G8", "evidence_path": str(path.relative_to(ROOT))}
            res = eval_evidence_gate(gate, "manifest_sha", "lock_sha")
            self.assertEqual(res["status"], "FAIL")
        finally:
            path.unlink()

    def test_unbound_evidence_fails(self):
        import tempfile
        from p1v5.gate_runner import PINNED_TERMS_SHA, eval_evidence_gate
        stale = "a" * 64
        with tempfile.NamedTemporaryFile("w", suffix=".json", dir=str(ROOT / "build"),
                                         delete=False) as f:
            json.dump({"produced_by": "tool-x", "produced_at_utc": "2026-07-13T00:00:00+00:00",
                       "inputs": {"manifest_sha256": stale, "input_lock_sha256": stale},
                       "metrics": {"n_fields_analyzed": 12, "n_allow": 5,
                                   "n_restrict": 7, "terms_sha256": PINNED_TERMS_SHA},
                       "verdict": "PASS"}, f)
            path = Path(f.name)
        try:
            gate = {"id": "G8", "evidence_path": str(path.relative_to(ROOT))}
            res = eval_evidence_gate(gate, "b" * 64, "c" * 64)
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("CURRENT manifest", res["reason"])
        finally:
            path.unlink()


class TestScoringR8(unittest.TestCase):
    def test_no_free_failure_loss_parameter(self):
        import inspect
        params = inspect.signature(score_stream).parameters
        self.assertNotIn("failure_loss", params)
        with self.assertRaises(ScoringError):
            score_stream({"m1": None}, {"m1": 1}, ["m1"], mode="free_lunch")

    def test_all_censored_is_error_not_zerodivision(self):
        with self.assertRaises(ScoringError):
            score_stream({}, {}, ["m1", "m2"])

    def test_duplicate_enrollment_rejected(self):
        with self.assertRaises(ScoringError):
            score_stream({"m1": 0.5}, {"m1": 1}, ["m1", "m1"])

    def test_sensitivity_mode_is_declared(self):
        out = score_stream({"m1": None}, {"m1": 1}, ["m1"], mode="sensitivity_025")
        self.assertAlmostEqual(out["mean_brier"], 0.25)
        self.assertEqual(out["mode"], "sensitivity_025")


class TestAttestationRehash(unittest.TestCase):
    def test_rehash_attack_detected(self):
        from p1v5 import gate_runner
        gate_runner.run(release=False)
        p = ROOT / "build/gate_status.json"
        self.assertTrue(gate_runner.verify_status_file())
        doc = json.loads(p.read_text())
        # the r8 attack: mutate statuses AND recompute the self-checksum
        for gid, s in doc["body"]["gates"].items():
            s["status"] = "FAIL" if s["status"] == "PASS" else "PASS"
        doc["body_sha256"] = gate_runner._body_hash(doc["body"])
        p.write_text(json.dumps(doc, indent=2, default=str))
        self.assertFalse(gate_runner.verify_status_file())   # chain+anchor mismatch
        gate_runner.run(release=False)                        # restore honest state
        self.assertTrue(gate_runner.verify_status_file())


class TestCIPipefail(unittest.TestCase):
    def test_ci_uses_strict_shell_and_no_swallowing_pipe(self):
        text = (ROOT / "ci.sh").read_text()
        self.assertIn("set -euo pipefail", text)
        self.assertNotIn("unittest discover -s tests -v 2>&1 | tail", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
