"""Authoritative manifest loader v5.2 (round-8 finding #8, option 2).

The sole authoritative input is manifest.json, read with the stdlib JSON parser —
one grammar, one semantics, no YAML implicit-typing ambiguity (PyYAML's `010` -> 8
class of problems is structurally gone). manifest.yaml is a GENERATED display
file; G0 verifies it stays parse-equal to the JSON and the runtime never reads it
for configuration.
"""

import hashlib
import json
import sys
from pathlib import Path

if sys.flags.optimize > 0:  # pragma: no cover
    raise SystemExit("p1v5 refuses to run with PYTHONOPTIMIZE / -O (E9)")

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "manifest.json"


class ManifestError(Exception):
    pass


def _reject_constant(name):
    raise ManifestError(f"non-strict JSON constant {name} rejected (N9-R5)")


def _assert_all_finite(node, path="$"):
    import math
    if isinstance(node, float) and not math.isfinite(node):
        raise ManifestError(f"non-finite number at {path} (N9-R5)")
    if isinstance(node, dict):
        for k, v in node.items():
            _assert_all_finite(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _assert_all_finite(v, f"{path}[{i}]")


def load_manifest(validate: bool = True):
    raw = MANIFEST_PATH.read_bytes()
    try:
        m = json.loads(raw, parse_constant=_reject_constant)   # NaN/Infinity refused
    except json.JSONDecodeError as exc:
        raise ManifestError(f"manifest.json unparseable: {exc}")
    _assert_all_finite(m)
    if validate:
        import jsonschema
        schema_path = ROOT / "schema/manifest.schema.json"
        if not schema_path.exists():
            raise ManifestError("schema_ref target missing")
        schema = json.loads(schema_path.read_text())
        jsonschema.Draft7Validator.check_schema(schema)
        errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(m),
                        key=lambda e: list(e.absolute_path))
        if errors:
            msgs = [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in errors[:10]]
            raise ManifestError(f"{len(errors)} schema violations: " + " | ".join(msgs))
        if m.get("schema_ref") != "schema/manifest.schema.json":
            raise ManifestError("schema_ref mismatch")
    return m, raw


def manifest_sha256() -> str:
    return hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()


def display_yaml_in_sync() -> bool:
    """The generated manifest.yaml must stay parse-equal to manifest.json."""
    import yaml
    m, _ = load_manifest(validate=False)
    disp = yaml.safe_load((ROOT / "manifest.yaml").read_text())
    return disp == m


class RuntimeConfig:
    def __init__(self):
        m, _ = load_manifest(validate=True)
        self.manifest = m
        mp = m["memory_policy_common"]
        self.capacity_items = mp["capacity_items"]
        self.admission_top_k = mp["admission_top_k"]
        self.retrieval_top_m = mp["retrieval_top_m"]
        self.failure_loss = m["estimand"]["endpoint"]["failure_loss"]
        self.arm_ids = [a["id"] for a in m["arms"]]
        self.gate_ids = [g["id"] for g in m["gates"]]


_CONFIG = None


def get_config() -> RuntimeConfig:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = RuntimeConfig()
    return _CONFIG
