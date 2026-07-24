"""Shadow round-4 regressions (出厂检验 on commit 23fc4c0).

New P0: the topics/eligibility layer was disconnected from the G5a referent
chain — a header-less forged label file could relabel excluded events into
eligibility with zero refusal, and the G5a gate never opened the topics file.
New P1: blank-string ids passed the keyset missing-id guard.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT / "tools"), str(ROOT), str(ROOT / "tests")):
    if p not in sys.path:
        sys.path.insert(0, p)


class TestForgedTopicsRefused(unittest.TestCase):
    """The audit's end-to-end laundering repro, reversed."""

    def test_headerless_topics_refused(self):
        import build_panel
        tmp = Path(tempfile.mkdtemp())
        reg = tmp / "reg.jsonl"
        reg.write_text(json.dumps({"_lineage": {"batch_id": "b",
                                                "batch_manifest_sha256": "a" * 64,
                                                "allowed_use": "g5a_candidate",
                                                "source_markets": "m", "source_events": "e"}}) + "\n"
                       + json.dumps({"event_id": "E1", "title": "NBA Finals winner?",
                                     "n_markets": 1, "n_settled": 1, "n_settled_binary": 1,
                                     "structure": "standalone", "topic": "excluded",
                                     "tags": ["sports"], "series_key": "k",
                                     "last_close": 1750000000,
                                     "last_uma_end_binary": 1750000100, "volume": 1}) + "\n")
        top = tmp / "forged_topics.jsonl"           # audit verbatim: no _lineage
        top.write_text(json.dumps({"event_id": "E1", "c": "geopolitics"}) + "\n")
        env = {"P1V5_REGISTRY": str(reg), "P1V5_TOPICS": str(top)}
        with mock.patch.object(build_panel, "VIEWS", tmp), \
             mock.patch.dict(os.environ, env):
            with self.assertRaises(SystemExit):
                build_panel.main()

    def test_g5a_gate_rejects_tampered_topics(self):
        from test_regressions_r13 import TestG5aReferentChain
        t = TestG5aReferentChain("test_real_linked_chain_passes")
        r = t._eval({"topics_sha256": "e" * 64})
        self.assertEqual(r["status"], "FAIL")

    def test_g5a_gate_rejects_receiptless_topics(self):
        # a topics file whose lineage lacks the receipts binding cannot PASS
        from test_regressions_r13 import TestG5aReferentChain
        t = TestG5aReferentChain("test_real_linked_chain_passes")
        tmp = Path(tempfile.mkdtemp())
        bmp, reg, tpp, pnp, bm_sha, reg_sha, top_sha = t._mk_referents(tmp)
        stripped_lin = {"registry_sha256": reg_sha, "model": "m",
                        "taxonomy": ["geopolitics"], "prompt_protocol": "compact_letter_v1"}
        tpp.write_text(json.dumps({"_lineage": stripped_lin}) + "\n"
                       + json.dumps({"event_id": "E1", "c": "geopolitics"}) + "\n")
        new_top_sha = hashlib.sha256(tpp.read_bytes()).hexdigest()
        panel = json.loads(pnp.read_text())
        panel["summary"]["lineage"]["topics_sha256"] = new_top_sha
        pnp.write_text(json.dumps(panel))
        from p1v5.config import manifest_sha256
        from p1v5.checks import LOCK_PATH
        from p1v5.gate_runner import eval_evidence_gate
        m_sha = manifest_sha256()
        l_sha = hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()
        metrics = {"independent_family_transitions": 9, "required_by_g6": 8,
                   "batch_allowed_use": "g5a_candidate",
                   "batch_manifest_sha256": bm_sha, "registry_sha256": reg_sha,
                   "topics_sha256": new_top_sha,
                   "panel_sha256": hashlib.sha256(pnp.read_bytes()).hexdigest(),
                   "batch_manifest_path": str(bmp), "registry_path": str(reg),
                   "topics_path": str(tpp), "panel_path": str(pnp)}
        doc = {"produced_by": "shadow4-test", "produced_at_utc": "2026-07-24T00:00:00+00:00",
               "inputs": {"manifest_sha256": m_sha, "input_lock_sha256": l_sha},
               "metrics": metrics, "verdict": "PASS"}
        ep = tmp / "ev.json"
        ep.write_text(json.dumps(doc))
        r = eval_evidence_gate({"id": "G5a", "evidence_path": str(ep)}, m_sha, l_sha)
        self.assertEqual(r["status"], "FAIL")
        # R14-1 tightened the failure surface: a lineage without the parser /
        # raw-calls binding dies on whichever link is checked first
        self.assertTrue(any(w in r["reason"] for w in ("parser", "calls")), r["reason"])


class TestClassifierReceiptsPipeline(unittest.TestCase):
    """Hermetic run of classify_events.main() with a stub backend: the topics
    artifact must open with a lineage header binding registry sha + receipts."""

    def test_topics_artifact_carries_receipted_lineage(self):
        import classify_events
        tmp = Path(tempfile.mkdtemp())
        reg = tmp / "reg.jsonl"
        reg.write_text(json.dumps({"_lineage": {"batch_id": "b",
                                                "batch_manifest_sha256": "a" * 64,
                                                "allowed_use": "dev_lower_bound",
                                                "source_markets": "m", "source_events": "e"}}) + "\n"
                       + json.dumps({"event_id": "E1", "title": "War in X?",
                                     "topic": "unclassified", "series_key": "k",
                                     "n_settled": 1}) + "\n"
                       + json.dumps({"event_id": "E2", "title": "NBA winner?",
                                     "topic": "excluded", "series_key": "k2",
                                     "n_settled": 1}) + "\n")

        class StubClassifier:
            def __init__(self, *a, **k):
                pass
            def complete(self, prompt, seed, purpose, max_tokens=None):
                from p1v5.deliberation import CallReceipt
                text = "0:c\n1:h"          # E1 geopolitics, E2 sports_esports
                rec = CallReceipt("stub", "m", purpose,
                                  hashlib.sha256(prompt.encode()).hexdigest(),
                                  hashlib.sha256(text.encode()).hexdigest(),
                                  len(prompt), len(text), 0, 100, 50, "stub")
                return text, rec

        env = {"P1V5_REGISTRY": str(reg)}
        with mock.patch.object(classify_events, "VIEWS", tmp), \
             mock.patch.object(classify_events, "OpenRouterBackend", StubClassifier), \
             mock.patch.dict(os.environ, env):
            summary = classify_events.main()
        self.assertEqual(summary["n_labeled"], 2)
        top = sorted(tmp.glob("llm_topics_2*.jsonl"))[-1]
        lines = [json.loads(l) for l in open(top)]
        lin = lines[0]["_lineage"]
        self.assertEqual(lin["registry_sha256"],
                         hashlib.sha256(reg.read_bytes()).hexdigest())
        # R14-1: lineage binds the frozen parser and the raw calls file
        self.assertEqual(lin["parser_sha256"], hashlib.sha256(
            (ROOT / "src/p1v5/topic_parser.py").read_bytes()).hexdigest())
        rcp = tmp / lin["calls_file"]
        self.assertTrue(rcp.exists())
        self.assertEqual(lin["calls_sha256"],
                         hashlib.sha256(rcp.read_bytes()).hexdigest())
        self.assertGreaterEqual(lin["n_llm_calls"], 1)
        self.assertEqual(lin["n_labeled"], 2)
        rows = {o["event_id"]: o for o in lines[1:]}
        self.assertEqual(rows["E1"]["topic_llm"], "geopolitics")
        self.assertEqual(rows["E2"]["topic_llm"], "sports_esports")
        # every derived label names its call / item / output binding
        for eid in ("E1", "E2"):
            self.assertIn("call_id", rows[eid])
            self.assertIn("output_sha", rows[eid])


class TestKeysetBlankId(unittest.TestCase):
    def test_blank_string_id_incomplete(self):
        import full_pull
        body = b'{"markets": [{"id": ""}], "next_cursor": null}'
        with mock.patch.object(full_pull, "_get", return_value=("u", body)), \
             mock.patch.object(full_pull, "_archive", lambda *a, **k: None), \
             mock.patch.object(full_pull, "DATA", Path(tempfile.mkdtemp())):
            recs, complete = full_pull.fetch_keyset("/markets", {}, "x", max_pages=2)
        self.assertFalse(complete)

    def test_whitespace_id_incomplete(self):
        import full_pull
        body = b'{"markets": [{"id": "  "}], "next_cursor": null}'
        with mock.patch.object(full_pull, "_get", return_value=("u", body)), \
             mock.patch.object(full_pull, "_archive", lambda *a, **k: None), \
             mock.patch.object(full_pull, "DATA", Path(tempfile.mkdtemp())):
            recs, complete = full_pull.fetch_keyset("/markets", {}, "x", max_pages=2)
        self.assertFalse(complete)


class TestG7aGeneratorStrict(unittest.TestCase):
    def test_generator_refuses_nan_source(self):
        mod = __import__("make_g7a_evidence")
        tmp = Path(tempfile.mkdtemp())
        src = tmp / "src.json"
        src.write_text('{"est_total_cost_usd": NaN, "transcript_bundles": {"a/1": "x"}}')
        with mock.patch.object(mod, "SRC", src):
            with self.assertRaises(ValueError):
                mod.main()


if __name__ == "__main__":
    unittest.main(verbosity=2)
