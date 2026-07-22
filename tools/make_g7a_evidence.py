"""G7a evidence: cost dry-run metrics from the clean live micro-pilot, bound to
current manifest + input lock. Machine verdict must match runner's rules."""
import datetime, hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from p1v5.checks import LOCK_PATH
from p1v5.config import manifest_sha256

SRC = ROOT / "evidence_src/micro_pilot_live.json"
PRC = ROOT / "evidence_src/pricing_v1.json"
r = json.load(open(SRC))
est, act = r["est_total_cost_usd"], r["billed_cost_usd"]
err_pct = abs(est - act) / act * 100
evidence = {
    "produced_by": f"tools/make_g7a_evidence.py over build/micro_pilot_live.json "
                   f"(sha {hashlib.sha256(json.dumps(r, sort_keys=True).encode()).hexdigest()[:16]}); "
                   f"model={r['model']} pinned-provider run {r['produced_at_utc']}",
    "produced_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "inputs": {"manifest_sha256": manifest_sha256(),
               "input_lock_sha256": hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()},
    "metrics": {"cost_usd_estimate": est, "cost_error_pct": round(err_pct, 2),
                "n_dry_run_events": r["n_questions"],
                "source_report_sha256": hashlib.sha256(SRC.read_bytes()).hexdigest(),
                "pricing_table_sha256": hashlib.sha256(PRC.read_bytes()).hexdigest()},
    "verdict": "PASS" if (err_pct <= 20 and r["n_questions"] >= 5) else "FAIL",
}
out = ROOT / "evidence/g7a_cost_micropilot.json"
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps(evidence, indent=2))
print(f"G7a evidence: err={err_pct:.1f}% n={r['n_questions']} verdict={evidence['verdict']}")
