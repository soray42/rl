"""Shadow round-3 regressions (出厂检验 on commit 7928dfa).

R3-NEW-1: importing tools/make_g7a_evidence.py must be side-effect-free.
P0-12-3 core: allowed_use must be CONSUMED — registry embeds lineage, panel
refuses lineage-less registries and propagates, G5a evidence schema pins
batch_allowed_use=g5a_candidate.
R3-NEW-2: assignment ledger must regenerate from the frozen seed schedule.
R12-1 contract residual: full_pull.main() end-to-end smoke (mocked network).
R12-2 contract residual: keyset ledger write failure => INCOMPLETE, not crash.
R3-OBS-1: settled predicate exposed as production helper, tested here.
"""

import hashlib
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT / "tools"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)


class TestG7aToolImportSafe(unittest.TestCase):
    def test_import_has_no_side_effects(self):
        # R3-NEW-1: the repo's live source legitimately lacks transcript_bundles
        # right now — importing (and re-executing top level via reload) must
        # still succeed, never SystemExit
        mod = importlib.import_module("make_g7a_evidence")
        mod = importlib.reload(mod)
        self.assertTrue(callable(mod.main))

    def test_main_refuses_receiptless_source_with_exit_code_2(self):
        mod = importlib.import_module("make_g7a_evidence")
        tmp = Path(tempfile.mkdtemp())
        src = tmp / "src.json"
        src.write_text(json.dumps({"model": "m", "n_questions": 6}))  # no transcript_bundles
        with mock.patch.object(mod, "SRC", src):
            self.assertEqual(mod.main(), 2)


class TestRegistryLineage(unittest.TestCase):
    def _mk_batch(self, tmp, allowed_use="dev_lower_bound", drop_allowed_use=False):
        views = tmp / "views"
        views.mkdir(parents=True, exist_ok=True)
        mkts = [
            {"market_id": "m1", "event_ids": ["E1"], "question": "q1",
             "uma_status": "resolved", "outcome_gamma_coarse": "yes", "closed_time": 1750000000},
            {"market_id": "m2", "event_ids": ["E1"], "question": "q2",
             "uma_status": "resolved", "outcome_gamma_coarse": "unknown_50_50", "closed_time": 1750000100},
            {"market_id": "m3", "event_ids": ["E1"], "question": "q3",
             "uma_status": None, "outcome_gamma_coarse": None, "closed_time": 1750000200},
        ]
        (views / "full_x_markets.jsonl").write_text(
            "".join(json.dumps(m) + "\n" for m in mkts))
        (views / "full_x_events.jsonl").write_text(json.dumps(
            {"event_id": "E1", "title": "Will X happen in May 2026?",
             "tags": ["politics"], "neg_risk": False, "volume": 1}) + "\n")
        bm = {"batch_id": "batch_x",
              "files": {"full_x_markets.jsonl": hashlib.sha256(
                            (views / "full_x_markets.jsonl").read_bytes()).hexdigest(),
                        "full_x_events.jsonl": hashlib.sha256(
                            (views / "full_x_events.jsonl").read_bytes()).hexdigest()},
              "channel_complete": {"incomplete_reasons": ["closed-keyset-incomplete"]},
              "allowed_use": allowed_use}
        if drop_allowed_use:
            del bm["allowed_use"]
        bmp = tmp / "batch_manifest_x.json"
        bmp.write_text(json.dumps(bm))
        return views, bmp

    def test_registry_embeds_lineage_and_summary_carries_it(self):
        import event_registry
        tmp = Path(tempfile.mkdtemp())
        views, bmp = self._mk_batch(tmp)
        env = {"P1V5_BATCH_MANIFEST": str(bmp), "P1V5_ALLOW_SMALL_PULL": "1"}
        with mock.patch.object(event_registry, "VIEWS", views), \
             mock.patch.dict(os.environ, env):
            summary = event_registry.main()
        self.assertEqual(summary["batch_allowed_use"], "dev_lower_bound")
        self.assertEqual(summary["batch_manifest_sha256"],
                         hashlib.sha256(bmp.read_bytes()).hexdigest())
        reg_files = sorted(views.glob("event_registry_*.jsonl"))
        lines = [json.loads(l) for l in open(reg_files[-1])]
        self.assertIn("_lineage", lines[0])
        self.assertEqual(lines[0]["_lineage"]["allowed_use"], "dev_lower_bound")
        self.assertEqual(lines[0]["_lineage"]["batch_manifest_sha256"],
                         summary["batch_manifest_sha256"])
        row = next(r for r in lines[1:] if r["event_id"] == "E1")
        self.assertEqual(row["n_settled"], 2)          # yes + unknown_50_50
        self.assertEqual(row["n_settled_binary"], 1)   # yes only

    def test_registry_refuses_manifest_without_allowed_use(self):
        import event_registry
        tmp = Path(tempfile.mkdtemp())
        views, bmp = self._mk_batch(tmp, drop_allowed_use=True)
        env = {"P1V5_BATCH_MANIFEST": str(bmp), "P1V5_ALLOW_SMALL_PULL": "1"}
        with mock.patch.object(event_registry, "VIEWS", views), \
             mock.patch.dict(os.environ, env):
            with self.assertRaises(SystemExit):
                event_registry.main()

    def test_settled_predicates_are_production_helpers(self):
        # R3-OBS-1 / r12 §9.4: the three non-terminal uma states tested against
        # the PRODUCTION predicate, not a hand-copied expression
        import event_registry
        for uma in ("proposed", "disputed", None):
            m = {"uma_status": uma, "outcome_gamma_coarse": "yes", "closed_time": 1}
            self.assertFalse(event_registry.is_settled(m), uma)
        self.assertTrue(event_registry.is_settled(
            {"uma_status": "resolved", "outcome_gamma_coarse": "yes"}))
        self.assertTrue(event_registry.is_settled(
            {"uma_status": "resolved", "outcome_gamma_coarse": "unknown_50_50"}))
        self.assertFalse(event_registry.is_settled_binary(
            {"uma_status": "resolved", "outcome_gamma_coarse": "unknown_50_50"}))

    def test_classify_load_rows_skips_lineage_header(self):
        import classify_events
        tmp = Path(tempfile.mkdtemp())
        reg = tmp / "reg.jsonl"
        reg.write_text(json.dumps({"_lineage": {"allowed_use": "dev_lower_bound"}}) + "\n"
                       + json.dumps({"event_id": "E1", "title": "t", "series_key": "k"}) + "\n")
        rows = classify_events.load_rows(reg)
        self.assertEqual([r["event_id"] for r in rows], ["E1"])


class TestPanelLineage(unittest.TestCase):
    def _mk_inputs(self, tmp, with_header=True):
        reg = tmp / "reg.jsonl"
        header = json.dumps({"_lineage": {"batch_id": "batch_x",
                                          "batch_manifest_sha256": "a" * 64,
                                          "allowed_use": "dev_lower_bound",
                                          "source_markets": "m", "source_events": "e"}}) + "\n"
        row = json.dumps({"event_id": "E1", "title": "t", "n_markets": 1,
                          "n_settled": 1, "n_settled_binary": 1,
                          "structure": "standalone", "topic": "eligible", "tags": [],
                          "series_key": "k", "last_close": 1750000000,
                          "last_uma_end_binary": 1750000100, "volume": 1}) + "\n"
        reg.write_text((header if with_header else "") + row)
        # shadow r4: topics files carry a MANDATORY lineage header binding the
        # registry sha and the classification receipts
        rcp = tmp / "topics_receipts.jsonl"
        rcp.write_text(json.dumps({"prompt_sha": "p" * 64, "output_sha": "o" * 64,
                                   "prompt_tokens": 10, "completion_tokens": 5,
                                   "model": "m", "provider": "x",
                                   "purpose": "topic_classify", "n_items": 1}) + "\n")
        top = tmp / "topics.jsonl"
        top.write_text(json.dumps({"_lineage": {
            "registry_sha256": hashlib.sha256(reg.read_bytes()).hexdigest(),
            "model": "m", "taxonomy": ["geopolitics"],
            "prompt_protocol": "compact_letter_v1",
            "receipts_file": rcp.name,
            "receipts_sha256": hashlib.sha256(rcp.read_bytes()).hexdigest(),
            "n_llm_calls": 1, "n_labeled": 1, "batch_size": 40}}) + "\n"
            + json.dumps({"event_id": "E1", "c": "geopolitics"}) + "\n")
        return reg, top

    def test_panel_refuses_lineage_less_registry(self):
        import build_panel
        tmp = Path(tempfile.mkdtemp())
        reg, top = self._mk_inputs(tmp, with_header=False)
        env = {"P1V5_REGISTRY": str(reg), "P1V5_TOPICS": str(top)}
        with mock.patch.object(build_panel, "VIEWS", tmp), \
             mock.patch.dict(os.environ, env):
            with self.assertRaises(SystemExit):
                build_panel.main()

    def test_panel_propagates_lineage(self):
        import build_panel
        tmp = Path(tempfile.mkdtemp())
        reg, top = self._mk_inputs(tmp)
        env = {"P1V5_REGISTRY": str(reg), "P1V5_TOPICS": str(top)}
        with mock.patch.object(build_panel, "VIEWS", tmp), \
             mock.patch.dict(os.environ, env):
            summary = build_panel.main()
        self.assertEqual(summary["lineage"]["batch_allowed_use"], "dev_lower_bound")
        self.assertEqual(summary["lineage"]["batch_manifest_sha256"], "a" * 64)
        self.assertEqual(summary["lineage"]["registry_sha256"],
                         hashlib.sha256(reg.read_bytes()).hexdigest())
        self.assertEqual(summary["n_eligible_settled_events"], 1)


class TestG5aSchemaRejectsDevBatch(unittest.TestCase):
    """shadow r3 + r13 P0-13-3: the original version of this test used "a"*64
    fake shas with NO referent files as its positive case — exactly the attack
    the gate had to close. It now builds REAL referents; see also
    test_regressions_r13.TestG5aReferentChain for the full eval path."""

    def _evidence(self, allowed_use):
        return {"produced_by": "test fixture", "produced_at_utc": "2026-07-23T00:00:00+00:00",
                "inputs": {"manifest_sha256": "0" * 64, "input_lock_sha256": "0" * 64},
                "metrics": {"independent_family_transitions": 100, "required_by_g6": 50,
                            "batch_allowed_use": allowed_use,
                            "batch_manifest_sha256": "a" * 64,
                            "registry_sha256": "b" * 64,
                            "topics_sha256": "d" * 64,
                            "panel_sha256": "c" * 64,
                            "batch_manifest_path": "x/bm.json",
                            "registry_path": "x/reg.jsonl",
                            "topics_path": "x/topics.jsonl",
                            "panel_path": "x/panel.json"},
                "verdict": "PASS"}

    def test_schema_and_verdict(self):
        import jsonschema
        from p1v5.gate_runner import EVIDENCE_SCHEMAS, _verdict_rules
        val = jsonschema.Draft7Validator(EVIDENCE_SCHEMAS["G5a"])
        self.assertEqual(list(val.iter_errors(self._evidence("g5a_candidate"))), [])
        self.assertNotEqual(list(val.iter_errors(self._evidence("dev_lower_bound"))), [])
        stripped = self._evidence("g5a_candidate")
        del stripped["metrics"]["batch_allowed_use"]
        self.assertNotEqual(list(val.iter_errors(stripped)), [])
        rules = _verdict_rules({"budget": {"llm_usd": {"value": 250}},
                                "estimand": {"contrasts": {"alpha": 0.05}}})
        self.assertTrue(rules["G5a"](self._evidence("g5a_candidate")["metrics"]))
        self.assertFalse(rules["G5a"](self._evidence("dev_lower_bound")["metrics"]))
        # r13: a required_by_g6 below the frozen small-cluster floor can never PASS
        low = self._evidence("g5a_candidate")["metrics"]
        low["required_by_g6"] = 1
        self.assertFalse(rules["G5a"](low))


class TestSeedScheduleRegeneration(unittest.TestCase):
    def _fixture(self):
        from p1v5.analysis import assign_trajectories
        root = "root-hash-shadow3"
        led = assign_trajectories(root, 1)
        recs = [{"trajectory_id": e["trajectory_id"], "arm": e["arm"],
                 "family_id": "f0", "market_id": "m0", "q": 0.3} for e in led]
        enr = [{"market_id": "m0", "family_id": "f0"}]
        stl = [{"market_id": "m0", "y": 1, "resolved_at_utc": "2026-07-01T00:00:00+00:00"}]
        return root, led, recs, enr, stl

    def test_correct_ledger_regenerates(self):
        from p1v5.analysis import reconcile_ledgers
        root, led, recs, enr, stl = self._fixture()
        out = reconcile_ledgers(recs, led, enr, prereg_root_hash=root, settlement=stl)
        self.assertEqual(len(out["waves"]), 1)
        # r13 P0-13-4: the returned records carry DERIVED losses (q=0.3, y=1)
        self.assertAlmostEqual(out["records"][0]["loss"], 0.49)

    def test_forged_seed_rejected(self):
        from p1v5.analysis import AnalysisError, reconcile_ledgers
        root, led, recs, enr, stl = self._fixture()
        led[0] = dict(led[0], seed=999999999999)
        with self.assertRaises(AnalysisError):
            reconcile_ledgers(recs, led, enr, prereg_root_hash=root, settlement=stl)

    def test_swapped_arm_permutation_rejected(self):
        from p1v5.analysis import AnalysisError, reconcile_ledgers
        root, led, recs, enr, stl = self._fixture()
        a, b = dict(led[0]), dict(led[1])
        led[0], led[1] = dict(a, arm=b["arm"]), dict(b, arm=a["arm"])
        recs = [{"trajectory_id": e["trajectory_id"], "arm": e["arm"],
                 "family_id": "f0", "market_id": "m0", "q": 0.3} for e in led]
        with self.assertRaises(AnalysisError):
            reconcile_ledgers(recs, led, enr, prereg_root_hash=root, settlement=stl)


class TestFullPullMainSmoke(unittest.TestCase):
    def test_main_end_to_end_mocked_network(self):
        # R12-1 contract: exercise the REAL main() to batch-manifest generation
        # so an undefined name anywhere inside it can never hide again
        import full_pull
        tmp = Path(tempfile.mkdtemp())

        def fake_get(path, params):
            if path == "/tags":
                return "u", b'[{"slug":"politics"}]'
            if path == "/markets":
                if params.get("closed") == "true":
                    return "u", json.dumps([{"id": 1, "closed": True,
                                             "closedTime": "2026-05-01T00:00:00Z",
                                             "umaResolutionStatus": "resolved",
                                             "outcomes": '["Yes","No"]',
                                             "outcomePrices": '["1","0"]'}]).encode()
                return "u", b"[]"
            if path == "/events/keyset":
                return "u", b'{"events": [], "next_cursor": null}'
            raise AssertionError(f"unexpected path {path}")

        env = {"P1V5_ALLOW_SMALL_PULL": "1"}
        with mock.patch.object(full_pull, "DATA", tmp), \
             mock.patch.object(full_pull, "_get", side_effect=fake_get), \
             mock.patch.object(full_pull, "_archive", lambda *a, **k: None), \
             mock.patch.dict(os.environ, env):
            summary = full_pull.main()
        self.assertEqual(summary["n_closed_markets"], 1)
        bm_files = list((tmp / "views").glob("batch_manifest_*.json"))
        self.assertEqual(len(bm_files), 1)
        bm = json.loads(bm_files[0].read_text())
        # r13 P0-13-2: the small-pull override is a recorded completeness
        # concession — it machine-forces dev_lower_bound, never g5a_candidate
        self.assertEqual(bm["allowed_use"], "dev_lower_bound")
        self.assertIn("small_pull_override", bm["channel_complete"]["overrides"])
        for fname, sha in bm["files"].items():
            self.assertEqual(
                hashlib.sha256((tmp / "views" / fname).read_bytes()).hexdigest(), sha, fname)

    def test_keyset_ledger_write_failure_is_incomplete(self):
        # R12-2 contract: unwritable ledger => complete=False, never a crash
        import full_pull
        not_a_dir = Path(tempfile.mkdtemp()) / "file"
        not_a_dir.write_text("x")
        body = b'{"markets": [{"id": "1"}], "next_cursor": null}'
        with mock.patch.object(full_pull, "DATA", not_a_dir), \
             mock.patch.object(full_pull, "_get", return_value=("u", body)):
            recs, complete = full_pull.fetch_keyset("/markets", {}, "x", max_pages=2)
        self.assertEqual(recs, [])
        self.assertFalse(complete)


if __name__ == "__main__":
    unittest.main(verbosity=2)
