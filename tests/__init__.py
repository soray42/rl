import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for p in (str(_ROOT / "src"), str(_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)
