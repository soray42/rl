#!/usr/bin/env bash
# P1 v5.2 readiness CI. Never refreshes the lock. Never hand-writes PASS.
set -euo pipefail
cd "$(dirname "$0")"
if [ -n "${PYTHONOPTIMIZE:-}" ]; then echo "refusing: PYTHONOPTIMIZE set (E9)"; exit 5; fi
echo "== tests (auto-discovered; exit code preserved) =="
python3 -B -m unittest discover -s tests
echo "== lock verify (read-only) =="
python3 -B tools/verify_lock.py || echo "   (lock stale for current tree: LOCK gate stays non-PASS)"
echo "== gate DAG (readiness) =="
python3 -B src/p1v5/gate_runner.py
echo "== readiness CI complete =="
