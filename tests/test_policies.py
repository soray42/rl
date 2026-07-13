"""Policy/scoring tests v5.2 (unittest, -O safe)."""

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.checks import (check_g1_estimators, check_g2_invariance,  # noqa: E402
                         check_g10_placebos)
from p1v5.policy import ARMS, MemoryState, ToyDeliberation  # noqa: E402
from p1v5.scoring import ScoringError, score_stream  # noqa: E402

PLANTED = {"m_strong_good": 0.20, "m_weak_good": 0.05, "m_bad": -0.10}


class TestPolicies(unittest.TestCase):
    def _mem(self, arm_id, batch="batch-001"):
        return ARMS[arm_id].update(MemoryState(), ToyDeliberation(PLANTED, 1),
                                   feedback_clock=10.0, batch_id=batch)

    def test_byte_identical_across_runs(self):
        for arm_id in ARMS:
            shas = {self._mem(arm_id).sha() for _ in range(3)}
            self.assertEqual(len(shas), 1, arm_id)

    def test_exactly_once_retry(self):
        m1 = self._mem("shared_surplus")
        m2 = ARMS["shared_surplus"].update(m1, ToyDeliberation(PLANTED, 1),
                                           feedback_clock=10.0, batch_id="batch-001")
        self.assertEqual(m1.sha(), m2.sha())

    def test_required_arm_distinctions(self):
        h = {a: self._mem(a).sha() for a in ARMS}
        self.assertNotEqual(h["shared_surplus"], h["diff_agent_credit"])
        self.assertNotEqual(h["c3_action"], h["c3_compute_matched_sham"])
        self.assertNotEqual(h["no_update"], h["shared_surplus"])

    def test_magnitude_enters_memory(self):
        # r8 identity finding: quantized ratio must be stored and drive retrieval
        mem = self._mem("diff_agent_credit")
        self.assertTrue(all(hasattr(i, "ratio") for i in mem.items))
        got = mem.retrieve()
        ratios = [abs(i.ratio) for i in got]
        self.assertEqual(ratios, sorted(ratios, reverse=True))

    def test_gate_predicates(self):
        for name, fn in [("G1", check_g1_estimators), ("G2", check_g2_invariance),
                         ("G10", check_g10_placebos)]:
            ok, ev = fn()
            self.assertTrue(ok, f"{name}: {ev}")


class TestScoring(unittest.TestCase):
    def test_strategic_missingness_never_profits(self):
        honest = score_stream({"m1": 0.9}, {"m1": 0}, ["m1"])
        dodge = score_stream({"m1": None}, {"m1": 0}, ["m1"])
        self.assertAlmostEqual(honest["mean_brier"], 0.81)
        self.assertAlmostEqual(dodge["mean_brier"], 1.0)
        self.assertGreater(dodge["mean_brier"], honest["mean_brier"])

    def test_typed_failures_and_classes(self):
        out = score_stream({"m1": "0.7"}, {"m1": 1}, ["m1"])
        self.assertEqual(out["ledger"][0]["failure_class"], "invalid_parse")
        out2 = score_stream({"m1": None}, {"m1": 1}, ["m1"],
                            failures={"m1": "timeout"})
        self.assertEqual(out2["ledger"][0]["failure_class"], "timeout")
        with self.assertRaises(ScoringError):
            score_stream({"m1": None}, {"m1": 1}, ["m1"], failures={"m1": "lazy"})

    def test_invalid_outcome_rejected(self):
        with self.assertRaises(ScoringError):
            score_stream({"m1": 0.5}, {"m1": 2}, ["m1"])

    def test_empty_enrollment_is_error(self):
        with self.assertRaises(ScoringError):
            score_stream({}, {}, [])

    def test_unenrolled_outcome_rejected(self):
        with self.assertRaises(ScoringError):
            score_stream({"mX": 0.5}, {"mX": 1}, ["m1"])

    def test_censoring_ledgered(self):
        out = score_stream({"m1": 0.6}, {"m1": 1}, ["m1", "m2"])
        self.assertEqual(out["censored"], ["m2"])


class TestOptimizeGuard(unittest.TestCase):
    def test_refuses_python_O(self):
        proc = subprocess.run([sys.executable, "-O", "-c", "import p1v5.config"],
                              capture_output=True, cwd=str(ROOT),
                              env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"})
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
