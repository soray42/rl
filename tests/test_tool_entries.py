"""R12 structural remedy: every tool entry must at least import (the r12 P0-12-1
NameError class can never again hide behind green unit tests)."""

import importlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT / "tools"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

TOOLS = ["full_pull", "event_registry", "classify_events", "build_panel",
         "micro_pilot", "measure_replay", "make_g8_evidence", "make_g7a_evidence"]


class TestToolEntries(unittest.TestCase):
    def test_all_tools_import(self):
        for name in TOOLS:
            mod = importlib.import_module(name)
            importlib.reload(mod)

    def test_full_pull_symbols_exist(self):
        import full_pull
        for sym in ("fetch_all", "fetch_keyset", "week_windows", "day_windows", "main"):
            self.assertTrue(hasattr(full_pull, sym), f"full_pull.{sym} missing")

    def test_keyset_error_body_is_incomplete(self):
        # r12 P0-12-2: an {"error": ...} body must yield complete=False
        import full_pull
        from unittest import mock
        with mock.patch.object(full_pull, "_get",
                               return_value=("u", b'{"error": "temporary"}')):
            recs, complete = full_pull.fetch_keyset("/markets", {}, "x", max_pages=2)
        self.assertEqual(recs, [])
        self.assertFalse(complete)


if __name__ == "__main__":
    unittest.main(verbosity=2)
