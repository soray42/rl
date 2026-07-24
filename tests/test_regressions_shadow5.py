"""Shadow round-5 regressions (出厂检验 on commit 1fadb04).

F1 (P0): transcript reuse across forecast rows collapsed the bootstrap and
manufactured decisions — one transcript backs exactly one row, meta-bound.
F2 (P0): final_q was a free field — it now re-derives from round-2 messages
via the production parser + median (audit's FINAL:0.90-vs-0.05 replay).
F3 (P1): G6 genesis spot-check hardened to sha-derived indices.
F4 (P1): identity-relabeled receipt clones across an arm's questions die.
F5 (P2): {"_lineage": null} registry header refused.
"""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT / "tools"), str(ROOT), str(ROOT / "tests")):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.confirmatory import ConfirmatoryError, analyze_confirmatory  # noqa: E402
from test_regressions_r14 import (_patched, fixture_manifest, mk_bundle)  # noqa: E402


def _rehash_bundle(b):
    """Legally recompute the bundle manifest after editing member files."""
    from p1v5.confirmatory import BUNDLE_FILES
    bm = json.loads((b / "bundle_manifest.json").read_text())
    bm["files"] = {n: hashlib.sha256((b / n).read_bytes()).hexdigest()
                   for n in BUNDLE_FILES}
    (b / "bundle_manifest.json").write_text(json.dumps(bm))


class TestTranscriptReuse(unittest.TestCase):
    """F1: the shadow's 80-files-backing-480-rows construction, reversed."""

    def test_reused_transcript_rejected(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp)
        rows = [json.loads(l) for l in open(b / "forecasts.jsonl")]
        # point row 1 at row 0's transcript, keep everything else legal;
        # also align identity fields so the reuse check itself must catch it
        donor = rows[0]
        rows[1] = dict(rows[1], transcript_bundle_sha256=donor["transcript_bundle_sha256"])
        (b / "forecasts.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        _rehash_bundle(b)
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            with self.assertRaises(ConfirmatoryError) as cm:
                analyze_confirmatory(b)
        self.assertTrue("reuse" in str(cm.exception) or "trajectory" in str(cm.exception)
                        or "question_id" in str(cm.exception), str(cm.exception))

    def test_trajectory_identity_bound(self):
        # a transcript whose meta names a DIFFERENT trajectory is refused even
        # when the file itself is intact
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp)
        rows = [json.loads(l) for l in open(b / "forecasts.jsonl")]
        r0, r1 = rows[0], rows[1]
        # swap the two rows' transcript pointers (files intact, shas correct)
        rows[0] = dict(r0, transcript_bundle_sha256=r1["transcript_bundle_sha256"])
        rows[1] = dict(r1, transcript_bundle_sha256=r0["transcript_bundle_sha256"])
        (b / "forecasts.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        _rehash_bundle(b)
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            with self.assertRaises(ConfirmatoryError):
                analyze_confirmatory(b)

    def test_provenance_counts_unique_transcripts(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp)
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            out = analyze_confirmatory(b)
        pv = out["_provenance"]
        self.assertEqual(pv["n_forecast_rows"], pv["n_unique_transcripts_opened"])


class TestFinalQDerived(unittest.TestCase):
    """F2: the audit's FINAL:0.90-messages / final_q:0.05 bundle, reversed."""

    def _poison_first_transcript(self, b, mutate):
        rows = [json.loads(l) for l in open(b / "forecasts.jsonl")]
        old_sha = rows[0]["transcript_bundle_sha256"]
        tp = b / "transcripts" / f"{old_sha}.json"
        tb = json.loads(tp.read_text())
        mutate(tb)
        bb = json.dumps(tb, sort_keys=True).encode()
        new_sha = hashlib.sha256(bb).hexdigest()
        tp.unlink()
        (b / "transcripts" / f"{new_sha}.json").write_bytes(bb)
        rows[0]["transcript_bundle_sha256"] = new_sha
        (b / "forecasts.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        _rehash_bundle(b)

    def test_final_q_contradicting_messages_rejected(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp)

        def mutate(tb):
            tb["messages"] = [["agent-0", 2, "confident.\nFINAL: 0.90"]]
            tb["votes"] = {"agent-0": "0.9"}
            tb["final_q"] = "0.05"          # audit verbatim: free-field lie
        self._poison_first_transcript(b, mutate)
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            with self.assertRaises(ConfirmatoryError) as cm:
                analyze_confirmatory(b)
        self.assertIn("r5-F2", str(cm.exception))

    def test_votes_contradicting_messages_rejected(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp)

        def mutate(tb):
            tb["votes"] = {"agent-0": "0.9"}     # message still says the old q
        self._poison_first_transcript(b, mutate)
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            with self.assertRaises(ConfirmatoryError) as cm:
                analyze_confirmatory(b)
        self.assertIn("r5-F2", str(cm.exception))

    def test_no_round2_messages_rejected(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp)

        def mutate(tb):
            tb["messages"] = []
        self._poison_first_transcript(b, mutate)
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            with self.assertRaises(ConfirmatoryError):
                analyze_confirmatory(b)


class TestRegistryHeaderWellFormed(unittest.TestCase):
    """F5: {"_lineage": null} is not a lineage."""

    def test_null_lineage_rejected(self):
        tmp = tempfile.mkdtemp()
        b = mk_bundle(tmp)
        lines = (b / "registry.jsonl").read_text().splitlines()
        lines[0] = json.dumps({"_lineage": None})
        (b / "registry.jsonl").write_text("\n".join(lines) + "\n")
        _rehash_bundle(b)
        p1, p2 = _patched(fixture_manifest())
        with p1, p2:
            with self.assertRaises(ConfirmatoryError) as cm:
                analyze_confirmatory(b)
        self.assertIn("WELL-FORMED", str(cm.exception))


class TestG7aContentClones(unittest.TestCase):
    """F4: identity-relabeled receipt clones across one arm's questions."""

    def test_cloned_receipts_across_questions_fail(self):
        from test_regressions_r11 import TestG7aSourceBinding
        t = TestG7aSourceBinding("test_correct_binding_passes")
        src, rep = t._mk_source()
        td = Path(rep["transcript_dir"])
        # clone q0's receipts into every question of ONE arm (bundles stay
        # schema-valid and internally-labeled correctly — pure content clone)
        arm = "no_update"
        donor = json.loads((td / f"{arm}_q0.json").read_text())["receipts"]
        for k in range(1, rep["n_questions"]):
            f = td / f"{arm}_q{k}.json"
            doc = json.loads(f.read_text())
            doc["receipts"] = donor
            bb = json.dumps(doc, sort_keys=True).encode()
            f.write_bytes(bb)
            rep["transcript_bundles"][f"{arm}/q{k}"] = hashlib.sha256(bb).hexdigest()
        src.write_text(json.dumps(rep))
        from p1v5 import gate_runner
        from p1v5.gate_runner import eval_evidence_gate
        import uuid
        prc = ROOT / "evidence_src/pricing_v1.json"
        rb = hashlib.sha256(json.dumps(sorted(rep["transcript_bundles"].values())).encode()).hexdigest()
        metrics = {"cost_usd_estimate": rep["est_total_cost_usd"],
                   "cost_error_pct": 1.67, "n_dry_run_events": rep["n_questions"],
                   "source_report_sha256": hashlib.sha256(src.read_bytes()).hexdigest(),
                   "pricing_table_sha256": hashlib.sha256(prc.read_bytes()).hexdigest(),
                   "receipt_bundle_sha256": rb}
        doc = {"produced_by": "shadow5-test", "produced_at_utc": "2026-07-24T00:00:00+00:00",
               "inputs": {"manifest_sha256": "b" * 64, "input_lock_sha256": "c" * 64},
               "metrics": metrics, "verdict": "PASS"}
        p = ROOT / "build" / f"tmp_s5_{uuid.uuid4().hex}.json"
        p.write_text(json.dumps(doc))
        gate_runner.G7A_SOURCE_PATH = src
        try:
            r = eval_evidence_gate({"id": "G7a", "evidence_path": str(p.relative_to(ROOT))},
                                   "b" * 64, "c" * 64)
        finally:
            p.unlink()
            src.unlink()
            gate_runner.G7A_SOURCE_PATH = gate_runner.ROOT / "evidence_src/micro_pilot_live.json"
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("clone", r["reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
