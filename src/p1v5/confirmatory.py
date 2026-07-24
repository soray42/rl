"""R14-2/3/4: THE confirmatory entry point.

The engine in analysis.py recomputes formulas; this module binds the formula
INPUTS to opened, re-hashed referents (W3C-PROV style used/wasDerivedFrom):

- accepts a content-addressed ANALYSIS BUNDLE directory, never free Python lists;
- every q is DERIVED from an opened transcript bundle (re-hashed against the
  forecast row's sha); failure rows derive failure_class the same way;
- every y is DERIVED from an opened market receipt row (uma resolution status,
  binary outcome, resolution time); settlement is not a free field anywhere;
- family identity is DERIVED from the market receipt via the frozen family
  rule and cross-checked against enrollment AND the opened registry;
- the follow-up cutoff comes from the FROZEN manifest (refuses while PENDING)
  and every settlement must resolve on/before it; later-settling markets must
  appear in the censoring ledger instead (R14-3);
- alpha / delta / n_boot come from the frozen manifest — no caller overrides;
  the bootstrap seed is derived from root + contrast + an inputs digest per
  the manifest's frozen schedule (R14-4);
- the output _provenance uniquely identifies every scientific input: all five
  ledger shas, registry sha, manifest sha, analysis + confirmatory code shas,
  every frozen parameter and the derived seed (P1-14-2).

analyze_coprimary stays available as the DEV/SIMULATION engine (G6 must sweep
planted worlds through it); its output is tiered dev_engine_not_confirmatory
and can never ground a claim.
"""

import datetime
import hashlib
import json
from pathlib import Path

from .analysis import _parse_utc_ts, analyze_coprimary
from .config import load_manifest, manifest_sha256


class ConfirmatoryError(Exception):
    pass


BUNDLE_FILES = ("assignment.jsonl", "enrollment.jsonl", "market_receipts.jsonl",
                "forecasts.jsonl", "censoring.jsonl", "registry.jsonl")


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _is_hex64(s) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _strict_rows(path: Path) -> list:
    rows = []
    for ln in path.read_text().splitlines():
        if ln.strip():
            rows.append(json.loads(
                ln, parse_constant=lambda n: (_ for _ in ()).throw(ValueError(n))))
    return rows


def frozen_family_id(receipt: dict) -> str:
    """FROZEN family rule: the lowest event id the market belongs to; markets
    with no event mapping are their own singleton family. Deterministic and
    re-derivable from the receipt — never from caller agreement."""
    evs = receipt.get("event_ids") or []
    return sorted(str(e) for e in evs)[0] if evs else str(receipt["market_id"])


def _epoch_to_utc(ts) -> str:
    return datetime.datetime.fromtimestamp(
        float(ts), datetime.timezone.utc).isoformat(timespec="seconds")


def analyze_confirmatory(bundle_dir) -> dict:
    """No statistical or trust parameters exist on this signature BY DESIGN
    (R14-4): the manifest is loaded from the repo, the expected root IS the
    frozen manifest sha, and every other input arrives content-addressed
    inside the bundle. Anything a caller could override is not confirmatory."""
    bundle_dir = Path(bundle_dir)
    manifest, _ = load_manifest(validate=False)

    # ---- frozen statistical contract (R14-4): manifest is the ONLY source ----
    con = manifest["estimand"]["contrasts"]
    alpha, n_boot = con["alpha"], con["n_boot"]
    swe = con["smallest_worthwhile_effect"]
    if swe.get("status") != "FROZEN" or not isinstance(swe.get("value"), (int, float)):
        raise ConfirmatoryError("R14-4: smallest_worthwhile_effect (delta) is not FROZEN "
                                "in the manifest; confirmatory analysis refuses to run")
    delta = swe["value"]
    cut = manifest["clocks"].get("follow_up_cutoff_utc") or {}
    if cut.get("status") != "FROZEN" or not isinstance(cut.get("value"), str):
        raise ConfirmatoryError("R14-3: follow_up_cutoff_utc is not FROZEN in the manifest; "
                                "confirmatory analysis refuses to run")
    cutoff_utc = cut["value"]
    cutoff_dt = _parse_utc_ts(cutoff_utc)
    if cutoff_dt is None:
        raise ConfirmatoryError(f"frozen cutoff is not a valid UTC instant: {cutoff_utc!r}")

    # ---- bundle manifest: content-addressed inputs (R14-2) ----
    bmp = bundle_dir / "bundle_manifest.json"
    if not bmp.exists():
        raise ConfirmatoryError("analysis bundle lacks bundle_manifest.json")
    bman = json.loads(bmp.read_text(),
                      parse_constant=lambda n: (_ for _ in ()).throw(ValueError(n)))
    if bman.get("schema_version") != "analysis_bundle_v1":
        raise ConfirmatoryError("unknown analysis bundle schema_version")
    root = bman.get("prereg_root_hash")
    if not _is_hex64(root):
        raise ConfirmatoryError("P1-14-5: prereg_root_hash must be a 64-hex digest, "
                                f"got {root!r}")
    expected_root = manifest_sha256()
    if root != expected_root:
        raise ConfirmatoryError("prereg_root_hash does not equal the frozen root "
                                "(manifest sha at preregistration)")
    files = bman.get("files") or {}
    if sorted(files) != sorted(BUNDLE_FILES):
        raise ConfirmatoryError(f"bundle files must be exactly {sorted(BUNDLE_FILES)}, "
                                f"got {sorted(files)}")
    for name, want in files.items():
        p = bundle_dir / name
        if not p.exists():
            raise ConfirmatoryError(f"bundle file missing on disk: {name}")
        got = _sha(p.read_bytes())
        if got != want:
            raise ConfirmatoryError(f"bundle file sha mismatch for {name}")

    assignment = _strict_rows(bundle_dir / "assignment.jsonl")
    enrollment = _strict_rows(bundle_dir / "enrollment.jsonl")
    receipts = _strict_rows(bundle_dir / "market_receipts.jsonl")
    fore_rows = _strict_rows(bundle_dir / "forecasts.jsonl")
    censoring = _strict_rows(bundle_dir / "censoring.jsonl")
    registry_rows = _strict_rows(bundle_dir / "registry.jsonl")

    # ---- registry: enrolled markets' events must exist in the opened registry ----
    if not registry_rows or "_lineage" not in registry_rows[0]:
        raise ConfirmatoryError("bundle registry lacks its _lineage header")
    reg_events = {r["event_id"] for r in registry_rows[1:]}

    # ---- settlement DERIVED from market receipts (R14-2 #4) ----
    rec_of = {}
    for r in receipts:
        if r["market_id"] in rec_of:
            raise ConfirmatoryError(f"duplicate market receipt {r['market_id']}")
        rec_of[r["market_id"]] = r
    settlement, must_censor = [], set()
    for mid, r in rec_of.items():
        resolved_binary = (r.get("uma_status") == "resolved"
                          and r.get("outcome_gamma_coarse") in ("yes", "no")
                          and r.get("uma_end"))
        if resolved_binary:
            iso = _epoch_to_utc(r["uma_end"])
            # R14-3: the cutoff PARTICIPATES — datetime comparison, not string
            if _parse_utc_ts(iso) <= cutoff_dt:
                settlement.append({"market_id": mid,
                                   "y": 1 if r["outcome_gamma_coarse"] == "yes" else 0,
                                   "resolved_at_utc": iso})
                continue
        must_censor.add(mid)               # unresolved / non-binary / late => censor

    # ---- family + enrollment DERIVED from receipts and registry (R14-2 #5) ----
    cen_ids = {c.get("market_id") for c in censoring if isinstance(c, dict)}
    for e in enrollment:
        mid = e.get("market_id")
        if mid not in rec_of:
            raise ConfirmatoryError(f"enrolled market {mid} has no market receipt")
        derived_fam = frozen_family_id(rec_of[mid])
        if e.get("family_id") != derived_fam:
            raise ConfirmatoryError(f"family relabel: enrollment says {e.get('family_id')!r} "
                                    f"for {mid}, frozen rule derives {derived_fam!r}")
        evs = rec_of[mid].get("event_ids") or []
        if evs and not (set(str(x) for x in evs) & reg_events):
            raise ConfirmatoryError(f"enrolled market {mid} maps to no event in the "
                                    f"opened registry")
        if mid in must_censor and mid not in cen_ids:
            raise ConfirmatoryError(f"market {mid} is unresolved-by-cutoff but has no "
                                    f"censoring receipt (R14-3)")
    for c in censoring:
        if isinstance(c, dict) and c.get("cutoff_utc") != cutoff_utc:
            raise ConfirmatoryError(f"censoring cutoff {c.get('cutoff_utc')!r} != frozen "
                                    f"manifest cutoff {cutoff_utc!r}")

    # ---- q / failure_class DERIVED from opened transcript bundles (R14-2 #3) ----
    records = []
    tdir = bundle_dir / "transcripts"
    for row in fore_rows:
        tsha = row.get("transcript_bundle_sha256")
        if not _is_hex64(tsha):
            raise ConfirmatoryError(f"forecast row lacks transcript_bundle_sha256: {row!r}")
        tp = tdir / f"{tsha}.json"
        if not tp.exists():
            raise ConfirmatoryError(f"transcript bundle missing on disk: {tsha[:16]}…")
        raw = tp.read_bytes()
        if _sha(raw) != tsha:
            raise ConfirmatoryError(f"transcript bundle sha mismatch: {tsha[:16]}…")
        tb = json.loads(raw)
        if tb.get("question_id") != row.get("market_id"):
            raise ConfirmatoryError(f"transcript question_id {tb.get('question_id')!r} != "
                                    f"forecast row market {row.get('market_id')!r}")
        if (tb.get("meta") or {}).get("arm") != row.get("arm"):
            raise ConfirmatoryError(f"transcript meta.arm != forecast row arm for "
                                    f"{row.get('market_id')}")
        base = {"trajectory_id": row["trajectory_id"], "arm": row["arm"],
                "market_id": row["market_id"], "family_id": row["family_id"]}
        fc = tb.get("failure_class")
        final_q = tb.get("final_q")
        if fc:
            records.append(dict(base, failure_class=fc))
        else:
            # bundle serializes final_q via repr(); "None" without failure_class
            # is a malformed transcript, not a forecast
            try:
                q = float(final_q)
            except (TypeError, ValueError):
                raise ConfirmatoryError(f"transcript final_q underivable for "
                                        f"{row.get('market_id')}: {final_q!r}")
            records.append(dict(base, q=q))

    # ---- frozen bootstrap seed (R14-4 #3) ----
    inputs_digest = _sha("".join(sorted(files.values())).encode())
    boot_seed = int(hashlib.sha256(
        f"{root}|boot|coprimary|{inputs_digest}".encode()).hexdigest()[:16], 16)

    out = analyze_coprimary(records, delta=delta, alpha=alpha, n_boot=n_boot,
                            seed=boot_seed, assignment_ledger=assignment,
                            enrollment=enrollment, censoring=censoring,
                            prereg_root_hash=root, settlement=settlement,
                            enrollment_lineage={"registry_sha256": files["registry.jsonl"]})

    # ---- provenance that uniquely identifies the analysis world (P1-14-2) ----
    code_dir = Path(__file__).resolve().parent
    out["_provenance"].update({
        "epistemic_status": "CONFIRMATORY",
        "bundle_manifest_sha256": _sha(bmp.read_bytes()),
        "ledger_sha256": dict(files),
        "manifest_sha256": manifest_sha256(),
        "analysis_code_sha256": _sha((code_dir / "analysis.py").read_bytes()),
        "confirmatory_code_sha256": _sha((code_dir / "confirmatory.py").read_bytes()),
        "alpha": alpha, "delta": delta, "n_boot": n_boot,
        "follow_up_cutoff_utc": cutoff_utc,
        "bootstrap_seed": boot_seed,
        "bootstrap_seed_schedule": con["bootstrap_seed_schedule"],
        "inputs_digest_sha256": inputs_digest,
        "n_transcripts_opened": len(fore_rows),
        "family_rule": "frozen_family_id: min(event_ids) else market_id",
    })
    return out
