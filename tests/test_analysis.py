"""E3 analysis module tests: assignment determinism/balance, ITT guards,
crossed bootstrap, Bonferroni-nominal CIs + four-way decisions on planted
synthetic worlds. r13: records carry committed forecasts q; losses are DERIVED
by the analyzer from the settlement ledger (y=1 worlds: Brier = (q-1)^2)."""

import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.analysis import (AnalysisError, analyze_coprimary,  # noqa: E402
                           assign_trajectories, contrast_tau, four_way)
from p1v5.checks import CANONICAL_ARMS  # noqa: E402

ROOT_HASH = "root" * 16
LINEAGE = {"registry_sha256": "0" * 64}     # referent verified at gate layer
RESOLVED_AT = "2026-07-01T00:00:00+00:00"


def full_kwargs(led, enr, stl):
    """r13 confirmatory-API bundle: all four ledgers + frozen root + lineage."""
    return dict(assignment_ledger=led, enrollment=enr, settlement=stl,
                prereg_root_hash=ROOT_HASH, enrollment_lineage=LINEAGE)


def synth_records(effect_c1: float, effect_c2: float, n_fam: int = 12,
                  k_per_arm: int = 6, seed: int = 7, fam_sd: float = 0.02,
                  noise_sd: float = 0.01, with_ledgers: bool = False):
    """Planted DGP with family common shocks (round-8 A14 style) and arm effects
    expressed on diff/c3 relative to their contrast partners. All markets settle
    y=1 and records commit q = 1 - sqrt(planted_loss), so the analyzer's derived
    Brier (q-1)^2 reproduces the planted loss surface exactly."""
    rng = random.Random(seed)
    base = {arm: 0.20 for arm in CANONICAL_ARMS}
    base["diff_agent_credit"] += effect_c1     # tau_C1 = effect_c1 (negative = better)
    base["c3_action"] += effect_c2
    fam_shock = {f"fam-{i}": rng.gauss(0, fam_sd) for i in range(n_fam)}
    records = []
    ledger = assign_trajectories(ROOT_HASH, k_per_arm)
    for entry in ledger:
        t_noise = rng.gauss(0, noise_sd)
        for fam, shock in fam_shock.items():
            for mkt in range(2):
                loss = max(0.0, min(1.0, base[entry["arm"]] + shock + t_noise
                                    + rng.gauss(0, noise_sd)))
                records.append({"trajectory_id": entry["trajectory_id"],
                                "arm": entry["arm"], "family_id": fam,
                                "market_id": f"{fam}-m{mkt}",
                                "q": 1.0 - loss ** 0.5})
    if with_ledgers:
        enrollment = [{"market_id": f"fam-{i}-m{k}", "family_id": f"fam-{i}"}
                      for i in range(n_fam) for k in range(2)]
        settlement = [{"market_id": e["market_id"], "y": 1,
                       "resolved_at_utc": RESOLVED_AT} for e in enrollment]
        return records, ledger, enrollment, settlement
    return records


class TestAssignment(unittest.TestCase):
    def test_deterministic_and_balanced(self):
        a = assign_trajectories("root" * 16, 4)
        b = assign_trajectories("root" * 16, 4)
        self.assertEqual(a, b)
        counts = {}
        for e in a:
            counts[e["arm"]] = counts.get(e["arm"], 0) + 1
        self.assertEqual(set(counts.values()), {4})
        self.assertEqual(len(a), 20)

    def test_different_root_different_assignment(self):
        a = assign_trajectories("root" * 16, 4)
        b = assign_trajectories("toor" * 16, 4)
        self.assertNotEqual([e["arm"] for e in a], [e["arm"] for e in b])


class TestEstimator(unittest.TestCase):
    def test_itt_violation_rejected(self):
        recs = [{"trajectory_id": "t1", "arm": "no_update", "family_id": "f",
                 "market_id": "m", "loss": 0.2},
                {"trajectory_id": "t1", "arm": "shared_surplus", "family_id": "f",
                 "market_id": "m2", "loss": 0.2}]
        with self.assertRaises(AnalysisError):
            contrast_tau(recs, "no_update", "shared_surplus", waves={0: {}})

    def test_four_way_regions(self):
        self.assertEqual(four_way(-0.10, -0.05, 0.02), "meaningful_benefit")
        self.assertEqual(four_way(0.05, 0.10, 0.02), "meaningful_harm")
        self.assertEqual(four_way(-0.01, 0.01, 0.02), "practical_equivalence")
        self.assertEqual(four_way(-0.05, 0.01, 0.02), "inconclusive")
        with self.assertRaises(AnalysisError):
            four_way(-0.1, 0.1, 0.0)


class TestPlantedDecisions(unittest.TestCase):
    def test_planted_benefit_detected(self):
        recs, led, enr, stl = synth_records(effect_c1=-0.06, effect_c2=0.0, with_ledgers=True)
        out = analyze_coprimary(recs, delta=0.02, n_boot=400, seed=11, **full_kwargs(led, enr, stl))
        self.assertEqual(out["C1"]["decision"], "meaningful_benefit", out["C1"])
        self.assertLess(out["C1"]["tau_hat"], -0.04)

    def test_planted_null_with_generous_delta_is_equivalence(self):
        recs, led, enr, stl = synth_records(effect_c1=0.0, effect_c2=0.0, n_fam=16, k_per_arm=8, with_ledgers=True)
        out = analyze_coprimary(recs, delta=0.05, n_boot=400, seed=12, **full_kwargs(led, enr, stl))
        self.assertEqual(out["C1"]["decision"], "practical_equivalence", out["C1"])
        self.assertEqual(out["C2"]["decision"], "practical_equivalence", out["C2"])

    def test_small_cluster_regime_refused_not_fabricated(self):
        # with 2 traj/arm + heavy noise the bootstrap turned noise into
        # "significant" directions (observed live) — the guard must REFUSE
        recs, led, enr, stl = synth_records(effect_c1=0.0, effect_c2=0.0, n_fam=3, k_per_arm=2,
                             fam_sd=0.06, noise_sd=0.04, with_ledgers=True)
        with self.assertRaises(AnalysisError):
            analyze_coprimary(recs, delta=0.005, n_boot=400, seed=13, **full_kwargs(led, enr, stl))

    def test_null_with_tiny_delta_is_inconclusive(self):
        recs, led, enr, stl = synth_records(effect_c1=0.0, effect_c2=0.0, n_fam=10, k_per_arm=6,
                             fam_sd=0.03, noise_sd=0.02, with_ledgers=True)
        out = analyze_coprimary(recs, delta=0.0005, n_boot=400, seed=13, **full_kwargs(led, enr, stl))
        self.assertIn(out["C1"]["decision"], ("inconclusive",), out["C1"])

    def test_itt_deletion_raises(self):
        # r11 reproduce case: deleting a randomized trajectory's rows must RAISE
        recs, led, enr, stl = synth_records(effect_c1=0.0, effect_c2=0.0, n_fam=10,
                                            k_per_arm=6, with_ledgers=True)
        victim = next(e["trajectory_id"] for e in led if e["arm"] == "diff_agent_credit")
        pruned = [r for r in recs if r["trajectory_id"] != victim]
        with self.assertRaises(AnalysisError):
            analyze_coprimary(pruned, delta=0.02, n_boot=200, seed=9, **full_kwargs(led, enr, stl))
        # deleting a single market row must also raise
        one_gone = recs[1:]
        with self.assertRaises(AnalysisError):
            analyze_coprimary(one_gone, delta=0.02, n_boot=200, seed=9, **full_kwargs(led, enr, stl))

    def test_directional_claims_use_bonferroni_nominal(self):
        recs, led, enr, stl = synth_records(effect_c1=-0.015, effect_c2=0.015, n_fam=10,
                             k_per_arm=6, fam_sd=0.04, noise_sd=0.03, with_ledgers=True)
        out = analyze_coprimary(recs, delta=0.001, n_boot=400, seed=14, **full_kwargs(led, enr, stl))
        for cid in ("C1", "C2"):
            self.assertEqual(out[cid]["multiplicity"], "bonferroni_nominal_pending_g6")
            self.assertAlmostEqual(out[cid]["ci_level_nominal"], 0.975)


if __name__ == "__main__":
    unittest.main(verbosity=2)
