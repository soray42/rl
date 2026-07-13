"""EXPLICIT release action (E1): refresh the detached lock + out-of-repo trusted root.
Requires P1V5_REFRESH_INTENT=yes. CI never calls this; verify_lock.py is read-only."""

import hashlib
import json
import os
import platform
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p1v5.checks import EXTERNAL_PINS, LOCK_PATH, TRUSTED_ROOT_PATH, repo_inventory  # noqa: E402


def main() -> int:
    if os.environ.get("P1V5_REFRESH_INTENT") != "yes":
        print("refusing: set P1V5_REFRESH_INTENT=yes to authorize a lock refresh (release action)")
        return 3
    external = {}
    for name, pin in EXTERNAL_PINS.items():
        p = (ROOT / pin["path"]).resolve()
        got = hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "MISSING"
        if got != pin["sha256"]:
            print(f"refusing refresh: external pin {name} mismatch ({got[:16]}…)")
            return 4
        external[name] = {"path": pin["path"], "sha256": pin["sha256"]}
    lock = {"files": repo_inventory(), "external": external}
    payload = json.dumps(lock, indent=2, sort_keys=True)
    LOCK_PATH.parent.mkdir(exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=str(LOCK_PATH.parent), delete=False) as tmp:
        tmp.write(payload)
        tmppath = Path(tmp.name)
    tmppath.replace(LOCK_PATH)                       # atomic (P2)
    root = hashlib.sha256(payload.encode()).hexdigest()
    TRUSTED_ROOT_PATH.write_text(root + "  p1_v5 artifact.lock.json trusted root\n")
    import yaml, jsonschema  # noqa: E401
    from importlib.metadata import version
    env = [f"python {platform.python_version()}", f"pyyaml {yaml.__version__}",
           f"jsonschema {version('jsonschema')}"]
    (ROOT / "locks/environment.lock").write_text("\n".join(env) + "\n")
    print(f"lock refreshed: {len(lock['files'])} files; trusted root written OUTSIDE repo:")
    print(f"  {TRUSTED_ROOT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
