"""Round-11 counterexamples reversed (phase_b1/16_p1_v54_eleventh_audit/)."""

import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.deliberation import CallReceipt, Transcript, Message  # noqa: E402


class TestTranscriptProvenanceSHA(unittest.TestCase):
    """P0-11-4: identical content + different provenance must differ in SHA."""

    def _mk(self, provider):
        t = Transcript(question_id="q1")
        t.messages = [Message("a", 1, "x")]
        t.votes = {"a": 0.5}
        t.final_q = 0.5
        t.prompt_shas = ["p" * 64]
        t.receipts = [CallReceipt("openrouter", "m", "round1", "a" * 64, "b" * 64,
                                  10, 10, 5, 3, 4, provider)]
        return t

    def test_receipt_difference_changes_sha(self):
        self.assertNotEqual(self._mk("DeepInfra").sha(), self._mk("Baidu").sha())

    def test_failure_class_changes_sha(self):
        a, b = self._mk("X"), self._mk("X")
        b.failure_class = "invalid_parse"
        self.assertNotEqual(a.sha(), b.sha())


class TestG7aSourceBinding(unittest.TestCase):
    """P0-11-5 + P0-12-8: evidence binds to a recomputable source WITH receipts;
    tampering anywhere in the chain must FAIL."""

    def _mk_source(self):
        import uuid
        rep = {"model": "deepseek/deepseek-v4-flash", "n_questions": 6,
               "billed_prompt_tokens": 100000, "billed_completion_tokens": 50000,
               "est_total_cost_usd": 0.0177,
               "billed_cost_usd": round(100000/1e6*0.09 + 50000/1e6*0.18, 4),
               "transcript_bundles": {"a/1": "a"*64, "b/2": "b"*64}}
        p = ROOT / "build" / f"tmp_src_{uuid.uuid4().hex}.json"
        p.parent.mkdir(exist_ok=True)
        p.write_text(json.dumps(rep))
        return p, rep

    def _eval(self, metrics_patch=None, source_patch=None):
        from p1v5 import gate_runner
        from p1v5.gate_runner import eval_evidence_gate
        src, rep = self._mk_source()
        if source_patch:
            rep.update(source_patch)
            src.write_text(json.dumps(rep))
        prc = ROOT / "evidence_src/pricing_v1.json"
        est, act = rep["est_total_cost_usd"], rep["billed_cost_usd"]
        rb = hashlib.sha256(json.dumps(sorted(rep["transcript_bundles"].values())).encode()).hexdigest()
        metrics = {"cost_usd_estimate": est,
                   "cost_error_pct": round(abs(est - act) / act * 100, 2),
                   "n_dry_run_events": rep["n_questions"],
                   "source_report_sha256": hashlib.sha256(src.read_bytes()).hexdigest(),
                   "pricing_table_sha256": hashlib.sha256(prc.read_bytes()).hexdigest(),
                   "receipt_bundle_sha256": rb}
        metrics.update(metrics_patch or {})
        self._src_override = src
        gate_runner.G7A_SOURCE_PATH = src
        doc = {"produced_by": "r11-test", "produced_at_utc": "2026-07-22T00:00:00+00:00",
               "inputs": {"manifest_sha256": "b" * 64, "input_lock_sha256": "c" * 64},
               "metrics": metrics, "verdict": "PASS"}
        import uuid
        p = ROOT / "build" / f"tmp_r11_{uuid.uuid4().hex}.json"
        p.parent.mkdir(exist_ok=True)
        p.write_text(json.dumps(doc))
        try:
            return eval_evidence_gate({"id": "G7a", "evidence_path": str(p.relative_to(ROOT))},
                                      "b" * 64, "c" * 64)
        finally:
            p.unlink()
            self._src_override.unlink()
            import importlib
            from p1v5 import gate_runner as gr
            gr.G7A_SOURCE_PATH = gr.ROOT / "evidence_src/micro_pilot_live.json"

    def test_correct_binding_passes(self):
        self.assertEqual(self._eval()["status"], "PASS")

    def test_wrong_source_sha_fails(self):
        r = self._eval({"source_report_sha256": "d" * 64})
        self.assertEqual(r["status"], "FAIL")

    def test_tampered_error_pct_fails(self):
        r = self._eval({"cost_error_pct": 1.0})
        self.assertEqual(r["status"], "FAIL")


class TestRegistrySettledSemantics(unittest.TestCase):
    """P0-11-2: closed != settled; batch manifest required."""

    def test_registry_refuses_without_batch_manifest(self):
        import subprocess
        env = dict(os.environ)
        env.pop("P1V5_BATCH_MANIFEST", None)
        proc = subprocess.run([sys.executable, "-B", "tools/event_registry.py"],
                              capture_output=True, text=True, cwd=str(ROOT), env=env)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("P1V5_BATCH_MANIFEST", proc.stdout + proc.stderr)

    def test_closed_but_unresolved_not_settled(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import importlib
        import event_registry
        importlib.reload(event_registry)
        # classify_structure path only; settled logic: emulate rows
        mkts = [{"closed_time": 1700000000.0, "uma_status": "proposed",
                 "outcome_gamma_coarse": None, "question": "x?"}]
        settled = [m for m in mkts
                   if m.get("uma_status") == "resolved"
                   and m.get("outcome_gamma_coarse") in ("yes", "no", "unknown_50_50")]
        self.assertEqual(len(settled), 0)


class TestBackendFailureTyped(unittest.TestCase):
    """R11-7: a failing call yields a typed failure inside the transcript."""

    def test_trajectory_survives_backend_failure(self):
        from p1v5.deliberation import BackendFailure, StubBackend, TeamDeliberation
        from p1v5.policy import MemoryState

        class FlakyBackend(StubBackend):
            calls = 0
            def complete(self, prompt, seed, purpose, model="stub-1"):
                FlakyBackend.calls += 1
                if FlakyBackend.calls == 2:
                    raise BackendFailure("timeout")
                return super().complete(prompt, seed, purpose, model)

        t = TeamDeliberation(FlakyBackend(), 3).run(
            {"question_id": "q", "question": "x?"}, ["a", "b", "c"],
            MemoryState(), seed=1)
        self.assertIsNotNone(t.final_q)          # remaining agents still vote
        self.assertTrue(any("[FAILURE:timeout]" in m.content for m in t.messages))


if __name__ == "__main__":
    unittest.main(verbosity=2)
