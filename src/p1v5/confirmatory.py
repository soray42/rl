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

import statistics

from .analysis import _parse_utc_ts, analyze_coprimary
from .config import load_manifest, manifest_sha256
from .deliberation import parse_probability


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
    # shadow r5 F5: the header must BE a lineage record, not just a present key
    reg_lin = (registry_rows[0].get("_lineage") if registry_rows else None)
    if not isinstance(reg_lin, dict) \
            or not _is_hex64(reg_lin.get("batch_manifest_sha256")) \
            or reg_lin.get("allowed_use") not in ("dev_lower_bound", "g5a_candidate"):
        raise ConfirmatoryError("bundle registry lacks a WELL-FORMED _lineage header "
                                "(batch_manifest_sha256 + allowed_use)")
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
    # shadow r5 F1: one transcript backs exactly ONE forecast row, and its
    # meta must name THAT trajectory — reuse collapses the bootstrap and
    # manufactures decisions. shadow r5 F2: final_q is NOT a free field — it
    # re-derives from the bundle's own round-2 messages through the production
    # vote parser and median, the same discipline topic labels already get.
    records, seen_tsha = [], set()
    tdir = bundle_dir / "transcripts"
    for row in fore_rows:
        tsha = row.get("transcript_bundle_sha256")
        if not _is_hex64(tsha):
            raise ConfirmatoryError(f"forecast row lacks transcript_bundle_sha256: {row!r}")
        if tsha in seen_tsha:
            raise ConfirmatoryError(f"transcript reuse: {tsha[:16]}… backs more than one "
                                    f"forecast row (r5-F1)")
        seen_tsha.add(tsha)
        tp = tdir / f"{tsha}.json"
        if not tp.exists():
            raise ConfirmatoryError(f"transcript bundle missing on disk: {tsha[:16]}…")
        raw = tp.read_bytes()
        if _sha(raw) != tsha:
            raise ConfirmatoryError(f"transcript bundle sha mismatch: {tsha[:16]}…")
        tb = json.loads(raw)
        meta = tb.get("meta") or {}
        if tb.get("question_id") != row.get("market_id"):
            raise ConfirmatoryError(f"transcript question_id {tb.get('question_id')!r} != "
                                    f"forecast row market {row.get('market_id')!r}")
        if meta.get("arm") != row.get("arm"):
            raise ConfirmatoryError(f"transcript meta.arm != forecast row arm for "
                                    f"{row.get('market_id')}")
        if meta.get("trajectory_id") != row.get("trajectory_id"):
            raise ConfirmatoryError(f"transcript meta.trajectory_id "
                                    f"{meta.get('trajectory_id')!r} != forecast row "
                                    f"trajectory {row.get('trajectory_id')!r} (r5-F1)")
        base = {"trajectory_id": row["trajectory_id"], "arm": row["arm"],
                "market_id": row["market_id"], "family_id": row["family_id"]}
        fc = tb.get("failure_class")
        if fc:
            records.append(dict(base, failure_class=fc))
            continue
        # r5-F2: recompute every vote from the round-2 message text with the
        # production parser, then the median — stored votes/final_q may only
        # CONFIRM the derivation, never replace it
        r2_msgs = [m for m in tb.get("messages", [])
                   if isinstance(m, (list, tuple)) and len(m) == 3 and m[1] == 2]
        if not r2_msgs:
            raise ConfirmatoryError(f"transcript for {row['market_id']} has no round-2 "
                                    f"messages; q underivable (r5-F2)")
        derived_votes = {m[0]: parse_probability(m[2]) for m in r2_msgs}
        stored_votes = tb.get("votes") or {}
        if set(stored_votes) != set(derived_votes) or any(
                stored_votes[a] != repr(v) for a, v in derived_votes.items()):
            raise ConfirmatoryError(f"transcript votes for {row['market_id']} do not "
                                    f"re-derive from its round-2 messages (r5-F2)")
        valid = [v for v in derived_votes.values() if v is not None]
        if not valid:
            raise ConfirmatoryError(f"transcript for {row['market_id']} derives no valid "
                                    f"vote yet claims a forecast (r5-F2)")
        q = statistics.median(valid)
        try:
            stated = float(tb.get("final_q"))
        except (TypeError, ValueError):
            raise ConfirmatoryError(f"transcript final_q unreadable for "
                                    f"{row.get('market_id')}: {tb.get('final_q')!r}")
        if abs(stated - q) > 1e-12:
            raise ConfirmatoryError(f"transcript final_q {stated} != median of derived "
                                    f"votes {q} for {row['market_id']} (r5-F2)")
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
        # r5-F1: unique files, honestly counted (reuse is a hard error above)
        "n_forecast_rows": len(fore_rows),
        "n_unique_transcripts_opened": len(seen_tsha),
        "family_rule": "frozen_family_id: min(event_ids) else market_id",
    })
    return out
