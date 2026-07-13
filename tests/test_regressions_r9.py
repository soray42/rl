"""Round-9 counterexamples reversed into permanent regressions.
Encodes phase_b1/14_p1_v5_ninth_audit/ attacks that succeeded against v5.2."""

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.checks import LOCK_PATH, deep_validate, verify_lock  # noqa: E402
from p1v5.config import ManifestError, _assert_all_finite, _reject_constant, load_manifest  # noqa: E402
from p1v5.gate_runner import PINNED_TERMS_SHA, eval_evidence_gate  # noqa: E402
from p1v5.scoring import ScoringError, score_stream  # noqa: E402


def _copy_manifest():
    m, _ = load_manifest(validate=False)
    return json.loads(json.dumps(m))


class TestGateSpecPinned(unittest.TestCase):
    """N9-R1: the r9 P0-1 attack and its whole mutation family must die."""

    def test_predicate_swap_rejected(self):
        m = _copy_manifest()
        for g in m["gates"]:
            if g["id"] != "G0":
                g["predicate"] = "check_g9a_search_protocol"
                g["depends_on"] = []
                g.pop("evidence_path", None)
        self.assertTrue(any("predicate" in x for x in deep_validate(m)))

    def test_single_predicate_swap_between_two_gates_rejected(self):
        m = _copy_manifest()
        by_id = {g["id"]: g for g in m["gates"]}
        by_id["G1"]["predicate"], by_id["G2"]["predicate"] = \
            by_id["G2"]["predicate"], by_id["G1"]["predicate"]
        self.assertTrue(any("predicate" in x for x in deep_validate(m)))

    def test_dependency_drop_and_add_rejected(self):
        m = _copy_manifest()
        by_id = {g["id"]: g for g in m["gates"]}
        by_id["FREEZE"]["depends_on"] = []                      # drop
        self.assertTrue(any("FREEZE" in x for x in deep_validate(m)))
        m2 = _copy_manifest()
        by_id2 = {g["id"]: g for g in m2["gates"]}
        by_id2["G1"]["depends_on"] = ["G0", "G9a"]              # add an edge
        self.assertTrue(any("G1" in x and "depends_on" in x for x in deep_validate(m2)))

    def test_lock_freeze_remap_rejected(self):
        m = _copy_manifest()
        by_id = {g["id"]: g for g in m["gates"]}
        by_id["LOCK"]["predicate"] = "check_g9a_search_protocol"
        by_id["FREEZE"]["predicate"] = "check_g9a_search_protocol"
        v = deep_validate(m)
        self.assertTrue(any("LOCK" in x for x in v) and any("FREEZE" in x for x in v))

    def test_evidence_path_moves_rejected(self):
        m = _copy_manifest()
        by_id = {g["id"]: g for g in m["gates"]}
        by_id["G8"].pop("evidence_path")                        # strip from evidence gate
        self.assertTrue(any("G8" in x and "evidence_path" in x for x in deep_validate(m)))
        m2 = _copy_manifest()
        by_id2 = {g["id"]: g for g in m2["gates"]}
        by_id2["G1"]["evidence_path"] = "evidence/rogue.json"   # attach to non-evidence gate
        self.assertTrue(any("G1" in x and "evidence_path" in x for x in deep_validate(m2)))

    def test_coprimary_rewrite_rejected(self):
        m = _copy_manifest()
        m["estimand"]["contrasts"]["coprimary"] = [
            {"id": "C1", "arm_a": "no_update", "arm_b": "shared_surplus"},
            {"id": "C2", "arm_a": "diff_agent_credit", "arm_b": "c3_action"}]
        self.assertTrue(any("coprimary" in x for x in deep_validate(m)))


class TestEvidenceSemantics(unittest.TestCase):
    """N9-R3: typed schemas + machine-derived verdicts."""

    def _eval(self, gate_id, evidence, cur_m="b" * 64, cur_l="c" * 64):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", dir=str(ROOT / "build"),
                                         delete=False) as f:
            json.dump(evidence, f)
            path = Path(f.name)
        try:
            gate = {"id": gate_id, "evidence_path": str(path.relative_to(ROOT))}
            return eval_evidence_gate(gate, cur_m, cur_l)
        finally:
            path.unlink()

    def _bound_inputs(self, cur_m, cur_l):
        return {"manifest_sha256": cur_m, "input_lock_sha256": cur_l}

    def test_null_metrics_and_fake_utc_fail(self):
        cur_m, cur_l = "b" * 64, "c" * 64
        res = self._eval("G8", {
            "produced_by": "x-tool", "produced_at_utc": "2026-99-99T99:99:99NOT_UTC",
            "inputs": self._bound_inputs(cur_m, cur_l),
            "metrics": {"n_fields_analyzed": None, "n_allow": None,
                        "n_restrict": None, "terms_sha256": None},
            "verdict": "PASS"}, cur_m, cur_l)
        self.assertEqual(res["status"], "FAIL")

    def test_impossible_calendar_date_fails_even_with_types(self):
        cur_m, cur_l = "b" * 64, "c" * 64
        res = self._eval("G8", {
            "produced_by": "x-tool", "produced_at_utc": "2026-99-99T99:99:99+00:00",
            "inputs": self._bound_inputs(cur_m, cur_l),
            "metrics": {"n_fields_analyzed": 12, "n_allow": 5, "n_restrict": 7,
                        "terms_sha256": PINNED_TERMS_SHA},
            "verdict": "PASS"}, cur_m, cur_l)
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("UTC", res["reason"])

    def test_logic_contradiction_self_pass_fails(self):
        cur_m, cur_l = "b" * 64, "c" * 64
        res = self._eval("G5b", {
            "produced_by": "x-tool", "produced_at_utc": "2026-07-13T12:00:00+00:00",
            "inputs": self._bound_inputs(cur_m, cur_l),
            "metrics": {"weeks_required": 6.0, "calendar_ok": False},
            "verdict": "PASS"}, cur_m, cur_l)
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("machine-derived", res["reason"])

    def test_budget_overrun_with_true_flag_fails(self):
        cur_m, cur_l = "b" * 64, "c" * 64
        res = self._eval("G7b", {
            "produced_by": "x-tool", "produced_at_utc": "2026-07-13T12:00:00+00:00",
            "inputs": self._bound_inputs(cur_m, cur_l),
            "metrics": {"total_cost_usd": 99999.0, "within_hard_cap": True},
            "verdict": "PASS"}, cur_m, cur_l)
        self.assertEqual(res["status"], "FAIL")

    def test_wrong_terms_hash_fails(self):
        cur_m, cur_l = "b" * 64, "c" * 64
        res = self._eval("G8", {
            "produced_by": "x-tool", "produced_at_utc": "2026-07-13T12:00:00+00:00",
            "inputs": self._bound_inputs(cur_m, cur_l),
            "metrics": {"n_fields_analyzed": 12, "n_allow": 5, "n_restrict": 7,
                        "terms_sha256": "d" * 64},
            "verdict": "PASS"}, cur_m, cur_l)
        self.assertEqual(res["status"], "FAIL")

    def test_extra_metric_key_rejected(self):
        cur_m, cur_l = "b" * 64, "c" * 64
        res = self._eval("G8", {
            "produced_by": "x-tool", "produced_at_utc": "2026-07-13T12:00:00+00:00",
            "inputs": self._bound_inputs(cur_m, cur_l),
            "metrics": {"n_fields_analyzed": 12, "n_allow": 5, "n_restrict": 7,
                        "terms_sha256": PINNED_TERMS_SHA, "smuggled": 1},
            "verdict": "PASS"}, cur_m, cur_l)
        self.assertEqual(res["status"], "FAIL")


class TestEvidenceLockLoopBroken(unittest.TestCase):
    """N9-R2 regression, T10-R1 REWRITTEN: never occupies a canonical evidence
    path. If real canonical evidence exists we verify coexistence with the lock;
    the PASS-path demonstration always uses a unique temporary evidence file."""

    def test_valid_evidence_and_lock_coexist(self):
        from p1v5.config import manifest_sha256
        if not LOCK_PATH.exists():
            self.skipTest("no lock yet")
        ok0, _ = verify_lock()
        if not ok0:
            self.skipTest("tree differs from lock (development state)")
        cur_m = manifest_sha256()
        cur_l = hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()
        ev_dir = ROOT / "evidence"
        ev_dir.mkdir(exist_ok=True)

        canonical = ev_dir / "g8_rights_matrix.json"
        if canonical.exists():
            # future real artifact: it must COEXIST with a valid lock (never PENDING)
            res = eval_evidence_gate({"id": "G8",
                                      "evidence_path": "evidence/g8_rights_matrix.json"},
                                     cur_m, cur_l)
            self.assertIn(res["status"], ("PASS", "FAIL"))
            ok1, ev1 = verify_lock()
            self.assertTrue(ok1, ev1)
            return

        import uuid
        p = ev_dir / f"tmp_loop_regression_{uuid.uuid4().hex}.json"
        p.write_text(json.dumps({
            "produced_by": "loop-regression-fixture",
            "produced_at_utc": "2026-07-13T12:00:00+00:00",
            "inputs": {"manifest_sha256": cur_m, "input_lock_sha256": cur_l},
            "metrics": {"n_fields_analyzed": 12, "n_allow": 5, "n_restrict": 7,
                        "terms_sha256": PINNED_TERMS_SHA},
            "verdict": "PASS"}))
        try:
            gate = {"id": "G8", "evidence_path": f"evidence/{p.name}"}
            res = eval_evidence_gate(gate, cur_m, cur_l)
            self.assertEqual(res["status"], "PASS", res)
            ok1, ev1 = verify_lock()      # evidence/ excluded => lock still valid
            self.assertTrue(ok1, ev1)
        finally:
            p.unlink()


class TestStrictJSON(unittest.TestCase):
    def test_literal_constants_rejected(self):
        with self.assertRaises(ManifestError):
            json.loads('{"x": Infinity}', parse_constant=_reject_constant)
        with self.assertRaises(ManifestError):
            json.loads('{"x": NaN}', parse_constant=_reject_constant)

    def test_overflow_smuggled_infinity_rejected(self):
        # "1e999" parses to inf WITHOUT hitting parse_constant — the tree check catches it
        doc = json.loads('{"x": 1e999}')
        with self.assertRaises(ManifestError):
            _assert_all_finite(doc)


class TestMagnitudeEndToEnd(unittest.TestCase):
    """r9 §7: same ranks/signs, different relative magnitudes => the retrieved
    context (the prompt-feeding quantity) must change."""

    def _build(self, tweak):
        from p1v5.policy import ARMS, MemoryState, ToyDeliberation
        arm = ARMS["diff_agent_credit"]
        # small effects: keep team prob far from clipping so credits stay monotone
        b1 = {"a1": 0.08, "a2": 0.06, "a3": 0.05, "a4": tweak, "a5": 0.01}
        b2 = {"c1": 0.075, "c2": 0.055, "c3": 0.045, "c4": 0.025, "c5": 0.005}
        mem = arm.update(MemoryState(), ToyDeliberation(b1, 1), 10.0, "batch-1")
        mem = arm.update(mem, ToyDeliberation(b2, 1), 11.0, "batch-2")
        ranks = {i.key: (i.rank, i.sign) for i in mem.items}
        retrieved = [i.key for i in mem.retrieve()]
        prompt_hash = hashlib.sha256(json.dumps(retrieved).encode()).hexdigest()
        return ranks, retrieved, prompt_hash

    def test_magnitude_only_change_alters_retrieved_context(self):
        ranks_a, retr_a, ph_a = self._build(0.03)
        ranks_b, retr_b, ph_b = self._build(0.02)
        self.assertEqual(ranks_a, ranks_b, "ranks/signs must be identical across scenarios")
        self.assertNotEqual(retr_a, retr_b, "retrieved context must differ on magnitude-only change")
        self.assertNotEqual(ph_a, ph_b)


class TestScoringReceiptConsistency(unittest.TestCase):
    def test_orphan_failure_receipt_rejected(self):
        with self.assertRaises(ScoringError):
            score_stream({"m1": 0.5}, {"m1": 1}, ["m1"], failures={"mX": "timeout"})

    def test_valid_forecast_plus_failure_receipt_fails_closed(self):
        with self.assertRaises(ScoringError):
            score_stream({"m1": 0.5}, {"m1": 1}, ["m1"], failures={"m1": "timeout"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
