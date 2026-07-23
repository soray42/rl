"""G0 predicate + mutant rejection (E2), unittest-discoverable."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.checks import check_g0_manifest, check_g9a_search_protocol  # noqa: E402
from p1v5.config import ManifestError, load_manifest  # noqa: E402


class TestManifest(unittest.TestCase):
    def test_g0_passes_on_authoritative_manifest(self):
        ok, ev = check_g0_manifest()
        self.assertTrue(ok, ev)

    def test_each_mutant_rejected_by_schema_or_deep_validation(self):
        import yaml
        import json
        import jsonschema
        from p1v5.checks import deep_validate
        schema = json.loads((ROOT / "schema/manifest.schema.json").read_text())
        jsonschema.Draft7Validator.check_schema(schema)
        mutants = sorted((ROOT / "tests/mutants").glob("*.yaml"))
        self.assertGreaterEqual(len(mutants), 5)
        for mp in mutants:
            mm = yaml.safe_load(mp.read_text())
            schema_errs = list(jsonschema.Draft7Validator(schema).iter_errors(mm))
            deep_errs = deep_validate(mm) if not schema_errs else ["(schema rejected)"]
            self.assertTrue(schema_errs or deep_errs,
                            f"{mp.name} accepted by BOTH schema and deep validation")

    def test_runtime_binding_detects_unknown_arm(self):
        # the r7 mutant renamed an arm to something not in the code registry;
        # schema-level arm enum now rejects it, and G0 also cross-checks ARMS
        m, _ = load_manifest(validate=True)
        from p1v5.policy import ARMS
        self.assertEqual(sorted(a["id"] for a in m["arms"]), sorted(ARMS))

    def test_g9a_content_checks(self):
        # P1-13-1 boundary, stated honestly: G9a's pinned evidence lives
        # OUT-OF-REPO by design (../phase_b2, sha pins in-repo). On an isolated
        # archive the referent directory is absent — the GATE fails closed in
        # the runner (correct for release), and this unit test SKIPS with the
        # reason declared instead of reading as a code regression.
        ext = (Path(__file__).resolve().parents[1] / "../phase_b2/04_special_searches").resolve()
        if not ext.exists():
            self.skipTest("external G9a evidence root absent (isolated archive); "
                          "gate fails closed in the runner")
        ok, ev = check_g9a_search_protocol()
        self.assertTrue(ok, ev)


if __name__ == "__main__":
    unittest.main(verbosity=2)
