"""E4 deliberation pipeline tests (StubBackend only; zero network)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.deliberation import (StubBackend, TeamDeliberation,  # noqa: E402
                               credit_c3_action_t, credit_c3_sham_t,
                               credit_diff_agent_t, credit_shared_surplus_t,
                               parse_probability, update_memory_from_credits)
from p1v5.policy import MemoryState  # noqa: E402

Q = {"question_id": "mkt-test-1", "question": "Will X happen by 2027?"}
SLICES = ["SIGNAL_YES strong private evidence", "neutral background info", "SIGNAL_NO contrarian data"]


def _run(seed=42):
    team = TeamDeliberation(StubBackend(), n_agents=3)
    t = team.run(Q, SLICES, MemoryState(), seed=seed)
    return team, t


class TestDeliberation(unittest.TestCase):
    def test_deterministic_transcript(self):
        _, t1 = _run()
        _, t2 = _run()
        self.assertEqual(t1.sha(), t2.sha())
        self.assertIsNotNone(t1.final_q)
        self.assertEqual(len(t1.receipts), 6)          # 3 agents x 2 rounds
        self.assertEqual(len(t1.prompt_shas), 6)       # materialized prompt bytes hashed

    def test_seed_changes_transcript(self):
        _, t1 = _run(seed=42)
        _, t2 = _run(seed=43)
        self.assertNotEqual(t1.sha(), t2.sha())

    def test_parse_probability_strict(self):
        self.assertEqual(parse_probability("blah\nFINAL: 0.75"), 0.75)
        self.assertEqual(parse_probability("FINAL: 1"), 1.0)
        self.assertIsNone(parse_probability("FINAL: 1.5"))
        self.assertIsNone(parse_probability("probability is 0.7"))
        self.assertIsNone(parse_probability(""))
        self.assertIsNone(parse_probability("FINAL: -0.2"))

    def test_credits_have_expected_structure(self):
        team, t = _run()
        y = 1
        shared = credit_shared_surplus_t(t, y)
        diff = credit_diff_agent_t(t, y)
        self.assertEqual(len(set(shared.values())), 1)          # participant-uninformative
        self.assertEqual(set(diff), set(t.votes))
        c3 = credit_c3_action_t(team, Q, SLICES, MemoryState(), t, y, seed=7)
        self.assertEqual(set(c3), set(t.votes))

    def test_c3_and_sham_receipts_match_on_real_pipeline(self):
        team_a, t_a = _run()
        n_before = len(t_a.receipts)
        _ = credit_c3_action_t(team_a, Q, SLICES, MemoryState(), t_a, 1, seed=7)
        real_pattern = [(r.purpose, r.model) for r in t_a.receipts[n_before:]]

        team_b, t_b = _run()
        n_before_b = len(t_b.receipts)
        sham = credit_c3_sham_t(team_b, Q, SLICES, MemoryState(), t_b, 1,
                                seed=7, batch_id="batch-x")
        sham_pattern = [(r.purpose, r.model) for r in t_b.receipts[n_before_b:]]
        self.assertEqual(real_pattern, sham_pattern)            # compute parity (A20/D5)
        real = credit_c3_action_t(team_b, Q, SLICES, MemoryState(), t_b, 1, seed=7)
        self.assertEqual(sorted(real.values()), sorted(sham.values()))
        self.assertNotEqual(real, sham)                         # attribution decoupled

    def test_memory_update_from_real_transcript(self):
        team, t = _run()
        credits = credit_diff_agent_t(t, 1)
        mem = update_memory_from_credits(MemoryState(), credits, 10.0, "b-1",
                                         texts={a: f"experience about {a}" for a in credits})
        self.assertEqual(mem.sha(),
                         update_memory_from_credits(MemoryState(), credits, 10.0, "b-1",
                                                    texts={a: f"experience about {a}" for a in credits}).sha())
        # memory feeds back into the NEXT materialized prompt (end-to-end path)
        t2 = team.run(Q, SLICES, mem, seed=99)
        t2_empty = TeamDeliberation(StubBackend(), 3).run(Q, SLICES, MemoryState(), seed=99)
        if mem.items:
            self.assertNotEqual(t2.sha(), t2_empty.sha(),
                                "retrieved memory must change materialized prompts")

    def test_all_invalid_votes_is_typed_failure(self):
        class BrokenBackend(StubBackend):
            def complete(self, prompt, seed, purpose, model="stub-1"):
                text, rec = super().complete(prompt, seed, purpose, model)
                return text.replace("FINAL:", "GUESS:"), rec
        t = TeamDeliberation(BrokenBackend(), 3).run(Q, SLICES, MemoryState(), seed=1)
        self.assertIsNone(t.final_q)
        self.assertEqual(t.failure_class, "invalid_parse")


if __name__ == "__main__":
    unittest.main(verbosity=2)
