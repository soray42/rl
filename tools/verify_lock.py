"""Read-only lock verification (E1). Never writes anything."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p1v5.checks import verify_lock  # noqa: E402

if __name__ == "__main__":
    ok, ev = verify_lock()
    print(f"verify_lock: {'OK' if ok else 'FAIL'}")
    if not ok:
        print(json.dumps(ev, indent=2, default=str)[:2000])
    sys.exit(0 if ok else 1)
