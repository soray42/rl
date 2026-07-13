"""Round-7 counterexamples reversed into permanent regressions (E0).
Every test here encodes an attack from phase_b1/12_p1_v5_engineering_acceptance/
that succeeded against v5.0 and must now fail."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.clocks import ClockError, Ledger  # noqa: E402

SRC = "collector-a"


def _ev(qid, kind, t, **kw):
    d = {"msg_id": f"{qid}-{kind}-{t}", "source": SRC, "question_id": qid,
         "kind": kind, "t": t}
    d.update(kw)
    return d


class TestClockAttacksReversed(unittest.TestCase):
    def test_reversed_proposal_challenge_consistent(self):
        # r7: arrival order proposal/challenge vs challenge/proposal gave different states
        msgs = [_ev("Q", "enroll", 0.0, prediction_cutoff=49.0),
                _ev("Q", "proposal", 51.0, round=1),
                _ev("Q", "challenge", 52.0, round=1)]
        a, b = Ledger(), Ledger()
        for m in msgs:
            a.ingest(m)
        for m in reversed(msgs):
            b.ingest(m)
        self.assertEqual(a.state("Q"), b.state("Q"))
        self.assertEqual(a.state("Q").oracle_status, "challenged")

    def test_finalize_without_proposal_fails_closed(self):
        led = Ledger()
        led.ingest(_ev("Q", "enroll", 0.0, prediction_cutoff=49.0))
        led.ingest(_ev("Q", "finalize", 53.0, outcome="yes"))
        led.ingest(_ev("Q", "observe", 54.0))
        led.ingest(_ev("Q", "apply_queue", 55.0))
        q = led.state("Q")
        self.assertTrue(q.quarantined)
        self.assertFalse(q.is_final())
        self.assertFalse(Ledger.feedback_eligible(q, 60.0, 61.0))

    def test_clarification_before_enroll_fails_closed(self):
        led = Ledger()
        led.ingest(_ev("Q", "clarification", 5.0, rules_version=2))
        q = led.state("Q")
        self.assertTrue(q.quarantined)
        self.assertFalse(Ledger.forecast_admissible(q, 6.0, 7.0))

    def test_invalid_outcome_dead_letter_key_not_consumed(self):
        led = Ledger()
        led.ingest(_ev("Q", "enroll", 0.0, prediction_cutoff=49.0))
        led.ingest(_ev("Q", "proposal", 51.0, round=1))
        bad = {"msg_id": "fix-me", "source": SRC, "question_id": "Q",
               "kind": "finalize", "t": 53.0, "outcome": "banana"}
        self.assertFalse(led.ingest(bad))
        self.assertEqual(len(led.dead_letter), 1)
        good = dict(bad, outcome="yes")           # corrected event, SAME msg_id
        self.assertTrue(led.ingest(good))
        self.assertTrue(led.state("Q").is_final())

    def test_rules_version_changes_prompt_hash(self):
        def build(with_clar):
            led = Ledger()
            for m in [_ev("Q", "enroll", 0.0, prediction_cutoff=49.0),
                      _ev("Q", "proposal", 51.0, round=1),
                      _ev("Q", "finalize", 53.0, outcome="yes"),
                      _ev("Q", "observe", 54.0),
                      _ev("Q", "apply_queue", 55.0)]:
                led.ingest(m)
            if with_clar:
                led.ingest(_ev("Q", "clarification", 40.0, rules_version=2))
            return led.freeze_prompt("fc", 60.0, 61.0)
        self.assertNotEqual(build(False), build(True))

    def test_prompt_hash_injection_resistant(self):
        # r7: repr-based hashing allowed crafted question_ids to collide
        evil = 'QA", "outcome": "yes", "X'
        def build(qid, outcome):
            led = Ledger()
            for m in [_ev(qid, "enroll", 0.0, prediction_cutoff=49.0),
                      _ev(qid, "proposal", 51.0, round=1),
                      _ev(qid, "finalize", 53.0, outcome=outcome),
                      _ev(qid, "observe", 54.0),
                      _ev(qid, "apply_queue", 55.0)]:
                led.ingest(m)
            return led.freeze_prompt("fc", 60.0, 61.0)
        self.assertNotEqual(build(evil, "yes"), build("QA", "yes"))
        self.assertNotEqual(build("QB", "yes"), build("QB", "no"))

    def test_backdated_late_message_cannot_rewrite_commitment(self):
        led = Ledger()
        for m in [_ev("Q", "enroll", 0.0, prediction_cutoff=49.0),
                  _ev("Q", "proposal", 51.0, round=1),
                  _ev("Q", "finalize", 53.0, outcome="yes")]:
            led.ingest(m)
        h = led.freeze_prompt("fc-x", 60.0, 61.0)   # not eligible yet: no observe/apply
        led.ingest(_ev("Q", "observe", 54.0))
        led.ingest(_ev("Q", "apply_queue", 55.0))
        with self.assertRaises(ClockError):
            led.freeze_prompt("fc-x", 60.0, 61.0)   # write-once: rebind refused
        self.assertEqual(led.commitments["fc-x"]["hash"], h)


class TestStatusFileTamper(unittest.TestCase):
    def test_hand_edited_gate_status_detected(self):
        from p1v5 import gate_runner
        gate_runner.run(release=False)
        p = ROOT / "build/gate_status.json"
        self.assertTrue(gate_runner.verify_status_file())
        doc = json.loads(p.read_text())
        # r8 future-liveness fix: FLIP each status so the edit is a guaranteed
        # change even on an all-PASS tree (the old set-all-PASS version would
        # wrongly fail a legitimate all-green release)
        for gid, s in doc["body"]["gates"].items():
            s["status"] = "FAIL" if s["status"] == "PASS" else "PASS"
        p.write_text(json.dumps(doc, indent=2, default=str))
        self.assertFalse(gate_runner.verify_status_file())
        gate_runner.run(release=False)                        # restore honest state
        self.assertTrue(gate_runner.verify_status_file())


class TestLockTamper(unittest.TestCase):
    def test_verify_lock_refuses_unknown_and_modified_files(self):
        from p1v5.checks import LOCK_PATH, TRUSTED_ROOT_PATH, verify_lock
        if not LOCK_PATH.exists() or not TRUSTED_ROOT_PATH.exists():
            self.skipTest("lock not yet refreshed (pre-release tree)")
        ok, ev = verify_lock()
        if not ok:
            self.skipTest("tree differs from lock (development state)")
        rogue = ROOT / "rogue_file_should_fail.py"
        rogue.write_text("# planted by regression test\n")
        try:
            ok2, ev2 = verify_lock()
            self.assertFalse(ok2)
            self.assertIn("rogue_file_should_fail.py", ev2["unexpected"])
        finally:
            rogue.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
