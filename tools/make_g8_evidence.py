"""G8 evidence producer: machine summary of docs/g8_rights_matrix.md, bound to
the CURRENT manifest + input lock. Run AFTER any lock refresh."""

import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p1v5.checks import LOCK_PATH  # noqa: E402
from p1v5.config import manifest_sha256  # noqa: E402
from p1v5.gate_runner import PINNED_TERMS_SHA  # noqa: E402


def main() -> int:
    matrix = (ROOT / "docs/g8_rights_matrix.md").read_text()
    rows = re.findall(r"^\|\s*\d+\s*\|.*\*\*(ALLOW|RESTRICT)\*\*", matrix, re.MULTILINE)
    n_allow = sum(1 for r in rows if r == "ALLOW")
    n_restrict = sum(1 for r in rows if r == "RESTRICT")
    if not LOCK_PATH.exists():
        print("input lock missing; refresh first")
        return 1
    evidence = {
        "produced_by": f"tools/make_g8_evidence.py over docs/g8_rights_matrix.md "
                       f"(sha {hashlib.sha256(matrix.encode()).hexdigest()[:16]})",
        "produced_at_utc": datetime.datetime.now(datetime.timezone.utc)
                           .isoformat(timespec="seconds"),
        "inputs": {"manifest_sha256": manifest_sha256(),
                   "input_lock_sha256": hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()},
        "metrics": {"n_fields_analyzed": len(rows), "n_allow": n_allow,
                    "n_restrict": n_restrict, "terms_sha256": PINNED_TERMS_SHA},
        "verdict": "PASS" if (len(rows) >= 10 and n_allow + n_restrict == len(rows)) else "FAIL",
    }
    out = ROOT / "evidence/g8_rights_matrix.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False))
    print(f"g8 evidence: fields={len(rows)} allow={n_allow} restrict={n_restrict} "
          f"verdict={evidence['verdict']} -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
