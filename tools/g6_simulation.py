"""G6 power/Type-I simulation harness over the PRODUCTION engine (R14-5).

Every replicate runs the EXACT production code path (analysis.analyze_coprimary
with manifest-frozen alpha/n_boot and the frozen delta): scenario "null" plants
zero effect (Type-I material), scenario "effect" plants tau_C1 = -delta
(power material). Replicate seeds derive from a frozen schedule — no ambient
randomness. Raw per-replicate rows are the gate's referent: the G6 gate
re-hashes this module and analysis.py, opens the rows, recomputes the
summary statistics with a pinned formula, and re-executes replicate 0 of each
scenario as a genesis spot-check.

Usage: python3 tools/g6_simulation.py <n_sims> <out.jsonl>   (dev/dry runs)
The real G6 run happens after G5a fixes the design point (n_fam, k_per_arm).
"""

import hashlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p1v5.analysis import analyze_coprimary, assign_trajectories  # noqa: E402
from p1v5.checks import CANONICAL_ARMS  # noqa: E402

SCENARIOS = ("null", "effect")


def rep_seed(root_prefix: str, scenario: str, i: int) -> int:
    """Frozen replicate schedule: domain-separated, 64-bit truncation."""
    return int(hashlib.sha256(f"{root_prefix}|g6|{scenario}|{i}".encode()).hexdigest()[:16], 16)


def run_replicate(dgp: dict, scenario: str, i: int) -> dict:
    """One full production-path replicate. dgp freezes every parameter:
    root_prefix, n_fam, k_per_arm, fam_sd, noise_sd, delta, alpha, n_boot."""
    seed = rep_seed(dgp["root_prefix"], scenario, i)
    rng = random.Random(seed)
    effect = -dgp["delta"] if scenario == "effect" else 0.0
    base = {arm: 0.20 for arm in CANONICAL_ARMS}
    base["diff_agent_credit"] += effect          # benefit orientation on C1
    fam_shock = {f"fam-{j}": rng.gauss(0, dgp["fam_sd"]) for j in range(dgp["n_fam"])}
    root = f"{dgp['root_prefix']}|{scenario}|{i}"
    ledger = assign_trajectories(root, dgp["k_per_arm"])
    records = []
    for entry in ledger:
        t_noise = rng.gauss(0, dgp["noise_sd"])
        for fam, shock in fam_shock.items():
            for mkt in range(2):
                loss = max(0.0, min(1.0, base[entry["arm"]] + shock + t_noise
                                    + rng.gauss(0, dgp["noise_sd"])))
                records.append({"trajectory_id": entry["trajectory_id"],
                                "arm": entry["arm"], "family_id": fam,
                                "market_id": f"{fam}-m{mkt}",
                                "q": 1.0 - loss ** 0.5})
    enrollment = [{"market_id": f"fam-{j}-m{k}", "family_id": f"fam-{j}"}
                  for j in range(dgp["n_fam"]) for k in range(2)]
    settlement = [{"market_id": e["market_id"], "y": 1,
                   "resolved_at_utc": "2026-07-01T00:00:00+00:00"} for e in enrollment]
    out = analyze_coprimary(records, delta=dgp["delta"], alpha=dgp["alpha"],
                            n_boot=dgp["n_boot"], seed=seed,
                            assignment_ledger=ledger, enrollment=enrollment,
                            settlement=settlement, prereg_root_hash=root,
                            enrollment_lineage={"registry_sha256": "0" * 64})
    return {"scenario": scenario, "replicate": i, "seed": seed,
            "tau_C1": round(out["C1"]["tau_hat"], 10),
            "tau_C2": round(out["C2"]["tau_hat"], 10),
            "decision_C1": out["C1"]["decision"],
            "decision_C2": out["C2"]["decision"]}


def summarize(rows: list, n_sims: int) -> dict:
    """PINNED summary formulas (the gate recomputes these exactly):
    type1_event = any directional decision under null;
    power_event = C1 meaningful_benefit under effect;
    ucb/lcb = normal approximation at z=1.96."""
    directional = ("meaningful_benefit", "meaningful_harm")
    null_rows = [r for r in rows if r["scenario"] == "null"]
    eff_rows = [r for r in rows if r["scenario"] == "effect"]
    t = sum(1 for r in null_rows
            if r["decision_C1"] in directional or r["decision_C2"] in directional) / n_sims
    p = sum(1 for r in eff_rows if r["decision_C1"] == "meaningful_benefit") / n_sims
    z = 1.96
    return {"type1_hat": t, "power_hat": p,
            "type1_ucb": round(t + z * (t * (1 - t) / n_sims) ** 0.5, 6),
            "power_lcb": round(p - z * (p * (1 - p) / n_sims) ** 0.5, 6),
            "mc_se_type1": round((t * (1 - t) / n_sims) ** 0.5, 6),
            "mc_se_power": round((p * (1 - p) / n_sims) ** 0.5, 6)}


def run(dgp: dict, n_sims: int, out_path) -> dict:
    rows = []
    for scenario in SCENARIOS:
        for i in range(n_sims):
            rows.append(run_replicate(dgp, scenario, i))
            if i % 50 == 0:
                print(f"  {scenario} replicate {i}/{n_sims}", flush=True)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    s = summarize(rows, n_sims)
    print(json.dumps(s, indent=2))
    return s


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    out = sys.argv[2] if len(sys.argv) > 2 else str(ROOT / "build/g6_dry_results.jsonl")
    # dev dry-run DGP; the REAL G6 dgp is frozen from the G5a design point and
    # must use manifest alpha/n_boot and the frozen delta
    dgp = {"root_prefix": "g6-dev", "n_fam": 10, "k_per_arm": 6,
           "fam_sd": 0.02, "noise_sd": 0.01, "delta": 0.01,
           "alpha": 0.05, "n_boot": 200}
    run(dgp, n, out)
