"""Shadow-audit round-1 counterexamples reversed (shadow_audit/round1/)."""

import statistics
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.analysis import crossed_bootstrap_taus  # noqa: E402
from p1v5.deliberation import parse_probability  # noqa: E402


class TestParseLastFinal(unittest.TestCase):
    def test_revision_wins(self):
        text = "Tentatively FINAL: 0.2\nOn reflection though...\nFINAL: 0.8"
        self.assertEqual(parse_probability(text), 0.8)


class TestBootstrapTrajectoryWeight(unittest.TestCase):
    def test_trajectory_resampling_moves_tau(self):
        # trajectory-dominant DGP: identical families, spread trajectory means.
        # v5.4 bug: dict-collapse discarded traj weights -> tau variance ~= 0.
        records = []
        # within-wave contrasts VARY across waves so wave-resampling has variance
        means = {"diff_agent_credit": [0.10, 0.30, 0.12, 0.40, 0.15, 0.50],
                 "shared_surplus":    [0.14, 0.16, 0.34, 0.20, 0.46, 0.22]}
        for arm, ms in means.items():
            for ti, m in enumerate(ms):
                for f in range(8):
                    for k in range(2):
                        records.append({"trajectory_id": f"{arm}-t{ti}",
                                        "arm": arm, "family_id": f"fam-{f}",
                                        "market_id": f"fam-{f}-m{k}", "loss": m})
        waves = {i: {"diff_agent_credit": f"diff_agent_credit-t{i}",
                     "shared_surplus": f"shared_surplus-t{i}"} for i in range(6)}
        taus = crossed_bootstrap_taus(records, "diff_agent_credit", "shared_surplus",
                                      n_boot=300, seed=5, waves=waves)
        self.assertGreater(statistics.pstdev(taus), 0.01,
                           "trajectory resample weights must contribute variance")


class TestPilotQuestionDedup(unittest.TestCase):
    def test_one_market_per_event(self):
        # P1-13-1: hermetic — synthetic view with sibling markets from ONE
        # event; the dedup property is a commit property, not a data property
        sys.path.insert(0, str(ROOT / "tools"))
        import json
        import tempfile
        from unittest import mock
        import micro_pilot
        tmp = Path(tempfile.mkdtemp())
        rows = [{"market_id": "m1", "question": "q1?", "uma_status": "resolved",
                 "outcome_gamma_coarse": "yes", "neg_risk": False,
                 "event_ids": ["EV_SHARED"], "closed_time": 100},
                {"market_id": "m2", "question": "q2?", "uma_status": "resolved",
                 "outcome_gamma_coarse": "no", "neg_risk": False,
                 "event_ids": ["EV_SHARED"], "closed_time": 200},   # sibling — must drop
                {"market_id": "m3", "question": "q3?", "uma_status": "resolved",
                 "outcome_gamma_coarse": "no", "neg_risk": False,
                 "event_ids": ["EV_OTHER"], "closed_time": 300}]
        (tmp / "two_clock_view_fixture.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows))
        with mock.patch.object(micro_pilot, "VIEWS_DIR", tmp):
            qs = micro_pilot.load_questions(6)
        self.assertEqual([q["question_id"] for q in qs], ["m1", "m3"],
                         "sibling market from one event leaked into pilot set")


if __name__ == "__main__":
    unittest.main(verbosity=2)
