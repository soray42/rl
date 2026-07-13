#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ -n "${PYTHONOPTIMIZE:-}" ]; then echo "refusing: PYTHONOPTIMIZE set (E9)"; exit 5; fi
python3 -B -m unittest discover -s tests
python3 -B tools/verify_lock.py
python3 -B src/p1v5/gate_runner.py --release
