"""G7a evidence: cost dry-run metrics from the clean live micro-pilot, bound to
current manifest + input lock. Machine verdict must match runner's rules.

Import-safe (shadow r3 R3-NEW-1): ALL work lives in main(); importing this
module must never read sources, write evidence, or exit."""
import datetime
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SRC = ROOT / "evidence_src/micro_pilot_live.json"
PRC = ROOT / "evidence_src/pricing_v1.json"


def main() -> int:
    from p1v5.checks import LOCK_PATH
    from p1v5.config import manifest_sha256
    r = json.load(open(SRC))
    if not r.get("transcript_bundles"):
        print("G7a source lacks transcript_bundles (receipts); run a fresh live micro-pilot "
              "under the bundle-persisting pipeline before emitting G7a evidence. NOT emitting.")
        return 2
    # r13 P0-13-8: mirror the runner — bundle FILES must exist and re-hash to
    # the recorded shas before evidence is even emitted
    if not r.get("transcript_dir"):
        print("G7a source lacks transcript_dir; bundles unlocatable. NOT emitting.")
        return 2
    td = ROOT / r["transcript_dir"]
    for key, sha in sorted(r["transcript_bundles"].items()):
        arm, _, qid = key.partition("/")
        bpath = td / f"{arm}_{qid}.json"
        if not bpath.exists() or hashlib.sha256(bpath.read_bytes()).hexdigest() != sha:
            print(f"G7a bundle missing or sha-mismatched on disk: {key}. NOT emitting.")
            return 2
    rb = hashlib.sha256(json.dumps(sorted(r["transcript_bundles"].values())).encode()).hexdigest()
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
                    "pricing_table_sha256": hashlib.sha256(PRC.read_bytes()).hexdigest(),
                    "receipt_bundle_sha256": rb},
        "verdict": "PASS" if (err_pct <= 20 and r["n_questions"] >= 5) else "FAIL",
    }
    out = ROOT / "evidence/g7a_cost_micropilot.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2))
    print(f"G7a evidence: err={err_pct:.1f}% n={r['n_questions']} verdict={evidence['verdict']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
