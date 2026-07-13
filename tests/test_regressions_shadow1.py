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
        means = {"diff_agent_credit": [0.10, 0.20, 0.30, 0.40],
                 "shared_surplus": [0.15, 0.25, 0.35, 0.45]}
        for arm, ms in means.items():
            for ti, m in enumerate(ms):
                for f in range(5):
                    for k in range(2):
                        records.append({"trajectory_id": f"{arm}-t{ti}",
                                        "arm": arm, "family_id": f"fam-{f}",
                                        "market_id": f"fam-{f}-m{k}", "loss": m})
        taus = crossed_bootstrap_taus(records, "diff_agent_credit", "shared_surplus",
                                      n_boot=300, seed=5)
        self.assertGreater(statistics.pstdev(taus), 0.01,
                           "trajectory resample weights must contribute variance")


class TestPilotQuestionDedup(unittest.TestCase):
    def test_one_market_per_event(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import json
        from micro_pilot import load_questions
        views = sorted((ROOT / "data/views").glob("two_clock_view_*.jsonl"))
        if not views:
            self.skipTest("no collected data")
        qs = load_questions(6)
        by_event = {}
        for line in views[-1].read_text().splitlines():
            v = json.loads(line)
            by_event[v["market_id"]] = tuple(sorted(v["event_ids"] or []))
        events = [by_event.get(q["question_id"]) for q in qs]
        self.assertEqual(len(events), len(set(events)),
                         f"sibling markets from one event in pilot set: {events}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
