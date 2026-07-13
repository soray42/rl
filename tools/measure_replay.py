"""G4 route-selection measurement (D10 discipline: feasibility metrics only,
never arm performance).

Measures API-level replay determinism on the candidate model: N distinct
prompts, each called twice with identical (prompt, seed, temperature=0).
Reports:
- sha_identical_rate: byte-exact output reproduction (bit-level replay);
- vote_agreement_rate: |q1 - q2| <= TOL (decision-level replay);
- provider distribution.

Route rule (preregistered in this file BEFORE running):
- if sha_identical_rate >= 0.90 -> frozen API replay is viable ("frozen_local_replay"
  naming kept for the manifest enum; here it means deterministic re-execution);
- else -> "pre_outcome_branches": ALL counterfactual rollouts are executed at
  forecast time (before outcome) and archived; settlement only scores archives.
Output: build/replay_measurement.json
"""

import datetime
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p1v5.deliberation import OpenRouterBackend, parse_probability  # noqa: E402

TOL = 0.05
MODEL = "deepseek/deepseek-v4-flash"


def main(n: int = 12) -> dict:
    import hashlib
    views = sorted((ROOT / "data/views").glob("two_clock_view_*.jsonl"))
    view_sha = hashlib.sha256(views[-1].read_bytes()).hexdigest()
    questions = []
    for line in views[-1].read_text().splitlines():
        v = json.loads(line)
        if v["question"] and v["uma_status"] == "resolved":
            questions.append((v["market_id"], v["question"]))
        if len(questions) >= n:
            break
    b = OpenRouterBackend(MODEL)
    rows = []
    for i, (mid, q) in enumerate(questions):
        prompt = (f"You are a forecaster. QUESTION: {q}\nReason briefly, then output "
                  f"exactly one line 'FINAL: <probability between 0 and 1>'.")
        text1, r1 = b.complete(prompt, seed=555, purpose="replay_a")
        text2, r2 = b.complete(prompt, seed=555, purpose="replay_b")
        v1, v2 = parse_probability(text1), parse_probability(text2)
        rows.append({"i": i, "market_id": mid,
                     "sha_equal": r1.output_sha == r2.output_sha,
                     "v1": v1, "v2": v2,
                     "vote_agree": (v1 is not None and v2 is not None
                                    and abs(v1 - v2) <= TOL),
                     "providers": [r1.provider, r2.provider]})
    n_ok = len(rows)
    report = {
        "model": MODEL, "n_replayed": n_ok, "tolerance": TOL,
        "source_view_sha256": view_sha,
        "sha_identical_rate": sum(r["sha_equal"] for r in rows) / n_ok,
        "vote_agreement_rate": sum(r["vote_agree"] for r in rows) / n_ok,
        "parse_failures": sum(1 for r in rows if r["v1"] is None or r["v2"] is None),
        "providers": sorted({p for r in rows for p in r["providers"]}),
        "rows": rows,
        "produced_at_utc": datetime.datetime.now(datetime.timezone.utc)
                           .isoformat(timespec="seconds"),
    }
    report["route_chosen"] = ("frozen_local_replay"
                              if report["sha_identical_rate"] >= 0.90
                              else "pre_outcome_branches")
    out = ROOT / "build/replay_measurement.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    return report


if __name__ == "__main__":
    r = main()
    print(json.dumps({k: v for k, v in r.items() if k != "rows"}, indent=2))
