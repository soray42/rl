"""E3: randomized assignment, ITT estimator, crossed bootstrap, four-way rule.

Implements the manifest's frozen statistical design:
- assignment: blocked equal-probability randomization of the 5 arms per
  enrollment wave, seeds = sha256(prereg_root_hash + index), ledgered;
- endpoint: per-trajectory mean Brier over eligible markets, RECOMPUTED from
  each record's committed forecast q and the settlement ledger's terminal y
  (r13 P0-13-4: caller-supplied losses are forbidden);
- contrast: within-wave contrast mean, negative favors arm_a;
- uncertainty: crossed bootstrap resampling complete WAVES x FAMILIES jointly;
- multiplicity: Bonferroni NOMINAL simultaneous percentile CIs over the two
  pinned co-primary contrasts (coverage certified only by production G6);
- decision: four-way interval rule (benefit/equivalence/harm/inconclusive);
  equivalence ONLY via CI containment in [-delta, +delta] (Lakens discipline).

This module is deliberately dependency-free and deterministic given seeds.
G6's power/Type-I simulation must use THESE functions (audit E3 requirement).
"""

import datetime
import hashlib
import random
from collections import defaultdict

from .checks import CANONICAL_ARMS, CANONICAL_COPRIMARY


class AnalysisError(Exception):
    pass


# ---------------------------------------------------------------------------
# Assignment (ITT: assignment is fixed forever at enrollment)
# ---------------------------------------------------------------------------

def trajectory_seed(prereg_root_hash: str, index: int) -> int:
    """Domain-separated (r11 P1-7): distinct hash domains for traj vs assignment (64-bit truncation: collision improbable, not impossible)."""
    return int(hashlib.sha256(f"{prereg_root_hash}|traj|{index}".encode()).hexdigest()[:16], 16)


def assignment_seed(prereg_root_hash: str, wave: int) -> int:
    return int(hashlib.sha256(f"{prereg_root_hash}|assign|{wave}".encode()).hexdigest()[:16], 16)


def assign_trajectories(prereg_root_hash: str, k_per_arm: int) -> list:
    """Blocked randomization: each wave of 5 consecutive trajectories receives a
    seeded permutation of the 5 arms => exact equal allocation, ledgered."""
    if k_per_arm < 1:
        raise AnalysisError("k_per_arm must be >= 1")
    ledger = []
    arms = list(CANONICAL_ARMS)
    for wave in range(k_per_arm):
        perm = list(arms)
        random.Random(assignment_seed(prereg_root_hash, wave)).shuffle(perm)
        for slot, arm in enumerate(perm):
            idx = wave * len(arms) + slot
            ledger.append({"trajectory_id": f"traj-{idx:04d}", "index": idx,
                           "wave": wave, "arm": arm,
                           "seed": trajectory_seed(prereg_root_hash, idx)})
    return ledger


# ---------------------------------------------------------------------------
# Endpoint + contrast estimator
# ---------------------------------------------------------------------------

def _trajectory_means(records: list) -> dict:
    """records: {trajectory_id, arm, family_id, market_id, loss}. Returns
    trajectory_id -> (arm, mean loss). Every record must be complete."""
    by_traj = defaultdict(list)
    arm_of = {}
    for r in records:
        for k in ("trajectory_id", "arm", "family_id", "market_id", "loss"):
            if k not in r:
                raise AnalysisError(f"record missing {k}: {r}")
        if r["arm"] not in CANONICAL_ARMS:
            raise AnalysisError(f"unknown arm {r['arm']}")
        prev = arm_of.setdefault(r["trajectory_id"], r["arm"])
        if prev != r["arm"]:
            raise AnalysisError(f"trajectory {r['trajectory_id']} appears under two arms (ITT violation)")
        by_traj[r["trajectory_id"]].append(r["loss"])
    return {t: (arm_of[t], sum(v) / len(v)) for t, v in by_traj.items()}


def contrast_tau(records: list, arm_a: str, arm_b: str, waves: dict = None) -> float:
    """R12: point estimate = mean of WITHIN-WAVE contrasts (design-compatible
    with the blocked assignment); ledger-free pooled version is forbidden."""
    means = _trajectory_means(records)
    tm = {t_: m for t_, (arm, m) in means.items()}
    if not waves:
        raise AnalysisError("contrast_tau requires the wave map (blocked design)")
    cs = []
    for w in sorted(waves):
        c = _wave_contrast(waves[w], arm_a, arm_b, tm)
        if c is None:
            raise AnalysisError(f"wave {w} missing a trajectory mean for {arm_a}/{arm_b}")
        cs.append(c)
    return sum(cs) / len(cs)


# small-cluster floor (MacKinnon-Nielsen-Webb discipline, cited by audits r5/r8):
# below these counts the percentile bootstrap is anti-conservative and can turn
# noise into "significant" directional claims — refuse rather than fabricate.
MIN_FAMILIES = 8   # shadow r2: coverage at 5 still ~2x nominal; floor raised, real guarantee = G6 at design point
MIN_TRAJ_PER_ARM = 6


def _guard_cluster_sizes(records: list, arm_a: str, arm_b: str):
    families = {r["family_id"] for r in records}
    per_arm = defaultdict(set)
    for r in records:
        per_arm[r["arm"]].add(r["trajectory_id"])
    if len(families) < MIN_FAMILIES:
        raise AnalysisError(f"small-cluster regime: {len(families)} families < {MIN_FAMILIES}; "
                            "bootstrap invalid, no analysis is produced")
    for arm in (arm_a, arm_b):
        if len(per_arm[arm]) < MIN_TRAJ_PER_ARM:
            raise AnalysisError(f"small-cluster regime: arm {arm} has "
                                f"{len(per_arm[arm])} trajectories < {MIN_TRAJ_PER_ARM}")


def _wave_contrast(wave_trajs: dict, arm_a: str, arm_b: str, traj_mean: dict):
    ta, tb = wave_trajs.get(arm_a), wave_trajs.get(arm_b)
    if ta not in traj_mean or tb not in traj_mean:
        return None
    return traj_mean[ta] - traj_mean[tb]


def crossed_bootstrap_taus(records: list, arm_a: str, arm_b: str,
                           n_boot: int, seed: int, waves: dict = None) -> list:
    """R12 (P0-12-5): the resampling units are COMPLETE WAVES (each holds one
    trajectory per arm — the blocked randomization unit) crossed with FAMILIES.
    tau* = weighted mean of within-wave contrasts. The blocked design is thus
    preserved exactly, not approximately."""
    if not waves:
        raise AnalysisError("crossed_bootstrap_taus requires the wave map from reconcile_ledgers")
    _guard_cluster_sizes(records, arm_a, arm_b)
    rng = random.Random(seed)
    families = sorted({r["family_id"] for r in records})
    wave_ids = sorted(waves)
    by_key = defaultdict(list)
    for r in records:
        by_key[(r["family_id"], r["trajectory_id"])].append(r)
    taus = []
    for _ in range(n_boot):
        fam_counts = defaultdict(int)
        for _ in families:
            fam_counts[rng.choice(families)] += 1
        wave_counts = defaultdict(int)
        for _ in wave_ids:
            wave_counts[rng.choice(wave_ids)] += 1
        traj_mean = {}
        needed = {t_ for w in wave_ids if wave_counts[w] for t_ in waves[w].values()}
        for traj in needed:
            num = den = 0.0
            for fam in families:
                fw = fam_counts[fam]
                if fw == 0:
                    continue
                rs = by_key.get((fam, traj))
                if rs:
                    num += fw * sum(r["loss"] for r in rs)
                    den += fw * len(rs)
            if den > 0:
                traj_mean[traj] = num / den
        num = den = 0.0
        for w in wave_ids:
            cw = wave_counts[w]
            if cw == 0:
                continue
            c = _wave_contrast(waves[w], arm_a, arm_b, traj_mean)
            if c is not None:
                num += cw * c
                den += cw
        if den == 0:
            continue
        taus.append(num / den)
    if len(taus) < max(50, n_boot // 2):
        raise AnalysisError(f"bootstrap degenerate: only {len(taus)}/{n_boot} valid resamples")
    return taus


def percentile_ci(taus: list, level: float) -> tuple:
    if not 0 < level < 1:
        raise AnalysisError(f"bad CI level {level}")
    s = sorted(taus)
    lo_idx = int(((1 - level) / 2) * (len(s) - 1))
    hi_idx = int((1 - (1 - level) / 2) * (len(s) - 1))
    return s[lo_idx], s[hi_idx]


def bootstrap_p_two_sided(taus: list) -> float:
    """Two-sided bootstrap p for H0: tau=0 (proportion-based, sign method)."""
    n = len(taus)
    frac_pos = sum(1 for t in taus if t > 0) / n
    frac_neg = sum(1 for t in taus if t < 0) / n
    return max(min(2 * min(frac_pos, frac_neg), 1.0), 1.0 / n)


# ---------------------------------------------------------------------------
# Bonferroni-nominal CIs + four-way decision over the two pinned co-primary contrasts
# ---------------------------------------------------------------------------

def four_way(ci_lo: float, ci_hi: float, delta: float) -> str:
    if delta <= 0:
        raise AnalysisError("delta must be positive")
    if ci_hi < -delta:
        return "meaningful_benefit"
    if ci_lo > delta:
        return "meaningful_harm"
    if -delta <= ci_lo and ci_hi <= delta:
        return "practical_equivalence"
    return "inconclusive"


FROZEN_FAILURE_LOSS = 1.0     # manifest estimand.endpoint.failure_loss (schema const)

# r13 P0-13-6: censoring reasons are a FROZEN enum — free-text (or empty)
# reasons carry no science and were an accepted bypass
CENSOR_REASONS = ("unresolved_at_cutoff", "market_voided", "settlement_invalid")


def _parse_utc_ts(ts):
    """Calendar-valid, timezone-aware, offset-zero UTC instant (else None)."""
    if not isinstance(ts, str):
        return None
    try:
        dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None or dt.utcoffset() != datetime.timedelta(0):
        return None
    return dt


def reconcile_ledgers(records: list, assignment_ledger: list,
                      enrollment: list, censoring: list = None,
                      prereg_root_hash: str = None, settlement: list = None) -> dict:
    """R12 (P0-12-4/5): TYPED ledgers with scientific semantics, not bare lists.
    - assignment rows need trajectory_id/arm/wave/index/seed; duplicate ids fatal;
    - enrollment rows need market_id + family_id: the family MAPPING lives here,
      result rows can never relabel families (small-cluster bypass closed);
    - censoring rows need market_id/reason/cutoff_utc receipts;
    - a record with failure_class MUST carry the frozen failure loss (1.0);
    Returns {"eligible": [...], "family_of": {...}, "waves": {wave: {arm: traj}}}."""
    import math
    for e in assignment_ledger or []:
        for k in ("trajectory_id", "arm", "wave", "index", "seed"):
            if k not in e:
                raise AnalysisError(f"assignment row missing '{k}': {e}")
    ids = [e["trajectory_id"] for e in (assignment_ledger or [])]
    if len(ids) != len(set(ids)):
        raise AnalysisError("duplicate trajectory_id in assignment ledger")
    expected_trajs = {e["trajectory_id"]: e["arm"] for e in assignment_ledger or []}
    if not expected_trajs:
        raise AnalysisError("empty assignment ledger")
    waves = defaultdict(dict)
    for e in assignment_ledger:
        if e["arm"] in waves[e["wave"]]:
            raise AnalysisError(f"wave {e['wave']} has two trajectories for arm {e['arm']}")
        waves[e["wave"]][e["arm"]] = e["trajectory_id"]
    for w, arms_ in waves.items():
        if sorted(arms_) != sorted(CANONICAL_ARMS):
            raise AnalysisError(f"wave {w} incomplete: arms {sorted(arms_)}")
    if prereg_root_hash is not None:
        # shadow r3 (R3-NEW-2): seeds/arms are only trustworthy if the WHOLE
        # ledger regenerates from the frozen seed schedule — hand-picked seeds
        # (run many, keep the favorite, backfill the ledger) fail here
        expected = assign_trajectories(prereg_root_hash, k_per_arm=len(waves))
        keys = ("trajectory_id", "index", "wave", "arm", "seed")
        got = sorted(({k: e[k] for k in keys} for e in assignment_ledger),
                     key=lambda e: e["index"])
        if got != sorted(expected, key=lambda e: e["index"]):
            raise AnalysisError("assignment ledger does not regenerate from the frozen seed "
                                "schedule (root|assign / root|traj domains); seeds or arm "
                                "permutations were altered after randomization")
    family_of = {}
    for e in enrollment or []:
        if not isinstance(e, dict) or "market_id" not in e or "family_id" not in e:
            raise AnalysisError(f"enrollment row must be {{market_id, family_id}}: {e!r}")
        if e["market_id"] in family_of:
            raise AnalysisError(f"duplicate enrollment market {e['market_id']}")
        family_of[e["market_id"]] = e["family_id"]
    # r13 P0-13-4: terminal outcomes come from a SETTLEMENT ledger; every
    # enrolled market must be settled XOR censored (settlement-or-censoring
    # completeness), and losses below are derived, never accepted
    if settlement is None:
        raise AnalysisError("R13-4: settlement ledger required — rows {market_id, y, "
                            "resolved_at_utc}; caller-supplied losses are forbidden")
    y_of = {}
    for s in settlement:
        if not isinstance(s, dict) or not all(k in s for k in ("market_id", "y", "resolved_at_utc")):
            raise AnalysisError(f"settlement row must be {{market_id, y, resolved_at_utc}}: {s!r}")
        if s["y"] not in (0, 1):
            raise AnalysisError(f"settlement y must be terminal binary 0/1, got {s['y']!r} "
                                f"for {s['market_id']}")
        if _parse_utc_ts(s["resolved_at_utc"]) is None:
            raise AnalysisError(f"settlement resolved_at_utc is not a valid UTC instant: {s!r}")
        if s["market_id"] in y_of:
            raise AnalysisError(f"duplicate settlement row for market {s['market_id']}")
        if s["market_id"] not in family_of:
            raise AnalysisError(f"settlement row for unenrolled market {s['market_id']}")
        y_of[s["market_id"]] = int(s["y"])
    censored, cutoffs = set(), set()
    for c in censoring or []:
        if not isinstance(c, dict) or not all(k in c for k in ("market_id", "reason", "cutoff_utc")):
            raise AnalysisError(f"censoring row needs market_id/reason/cutoff_utc receipts: {c!r}")
        if c["reason"] not in CENSOR_REASONS:
            raise AnalysisError(f"censoring reason must be in the frozen enum {CENSOR_REASONS}, "
                                f"got {c['reason']!r}")
        if _parse_utc_ts(c["cutoff_utc"]) is None:
            raise AnalysisError(f"censoring cutoff_utc is not a valid UTC instant: {c!r}")
        if c["market_id"] not in family_of:
            raise AnalysisError(f"censoring row for unenrolled market {c['market_id']}")
        if c["market_id"] in y_of:
            raise AnalysisError(f"market {c['market_id']} appears in BOTH settlement and censoring")
        censored.add(c["market_id"])
        cutoffs.add(c["cutoff_utc"])
    if len(cutoffs) > 1:
        raise AnalysisError(f"censoring must use ONE frozen design cutoff, got {sorted(cutoffs)}")
    unaccounted = sorted(set(family_of) - set(y_of) - censored)
    if unaccounted:
        raise AnalysisError(f"settlement-or-censoring incomplete: enrolled markets with neither "
                            f"terminal outcome nor censoring receipt: {unaccounted[:3]}")
    eligible = [m for m in family_of if m not in censored]
    if not eligible:
        raise AnalysisError("no eligible markets after censoring")
    seen = defaultdict(set)
    derived = []
    for r in records:
        t_, mkt = r["trajectory_id"], r["market_id"]
        if t_ not in expected_trajs:
            raise AnalysisError(f"unexpected trajectory {t_} not in assignment ledger")
        if r["arm"] != expected_trajs[t_]:
            raise AnalysisError(f"trajectory {t_} arm {r['arm']} != ledger {expected_trajs[t_]}")
        if mkt in censored:
            raise AnalysisError(f"record for censored market {mkt} (must be excluded for ALL)")
        if mkt not in family_of:
            raise AnalysisError(f"record for unenrolled market {mkt}")
        if r.get("family_id") != family_of[mkt]:
            raise AnalysisError(f"family relabel: record says {r.get('family_id')!r} for {mkt}, "
                                f"enrollment fixes {family_of[mkt]!r}")
        if r.get("failure_class") is not None:
            # a failed call has no committed forecast; its loss is the frozen constant
            if not (isinstance(r["failure_class"], str) and r["failure_class"]):
                raise AnalysisError(f"failure_class must be a non-empty string: {r!r}")
            if "q" in r:
                raise AnalysisError(f"failure row for {t_}/{mkt} carries a forecast q — "
                                    f"a failed call committed nothing")
            if "loss" in r and r["loss"] != FROZEN_FAILURE_LOSS:
                raise AnalysisError(f"typed failure row must carry frozen loss "
                                    f"{FROZEN_FAILURE_LOSS}, got {r['loss']} ({r['failure_class']})")
            loss = FROZEN_FAILURE_LOSS
        else:
            # r13 P0-13-4: the loss IS (q - y)^2 with q committed in the record
            # and y from the settlement ledger; a self-reported loss may only
            # confirm the derivation, never replace it
            if "q" not in r:
                raise AnalysisError(f"R13-4: record for {t_}/{mkt} lacks committed forecast q; "
                                    f"losses are recomputed, never caller-supplied")
            q = r["q"]
            if not (isinstance(q, (int, float)) and math.isfinite(q) and 0.0 <= q <= 1.0):
                raise AnalysisError(f"forecast q out of [0,1] or non-finite for {t_}/{mkt}: {q!r}")
            loss = (float(q) - y_of[mkt]) ** 2
            if "loss" in r and abs(r["loss"] - loss) > 1e-12:
                raise AnalysisError(f"self-reported loss {r['loss']} != Brier recomputed from "
                                    f"committed q and terminal y ({loss:.6f}) for {t_}/{mkt}")
        if mkt in seen[t_]:
            raise AnalysisError(f"duplicate market {mkt} for trajectory {t_}")
        seen[t_].add(mkt)
        derived.append(dict(r, loss=loss))
    for t_ in expected_trajs:
        missing = set(eligible) - seen[t_]
        if missing:
            raise AnalysisError(
                f"ITT violation: randomized trajectory {t_} lacks rows for "
                f"{len(missing)} eligible markets (e.g. {sorted(missing)[:3]}); "
                f"failures must enter as typed frozen-loss rows, never deletions")
    return {"eligible": eligible, "family_of": family_of, "waves": dict(waves),
            "records": derived, "n_settled": len(y_of)}


def analyze_coprimary(records: list, delta: float, alpha: float = 0.05,
                      n_boot: int = 2000, seed: int = 20260713,
                      assignment_ledger: list = None, enrollment: list = None,
                      censoring: list = None, prereg_root_hash: str = None,
                      settlement: list = None, enrollment_lineage: dict = None) -> dict:
    """Both pinned contrasts with Bonferroni NOMINAL simultaneous percentile CIs
    (R11-5, r12): each co-primary gets a percentile CI at level 1 - alpha/2;
    actual finite-sample coverage is certified only by the production G6
    simulation, never claimed a priori. Four-way decisions read directly off
    these CIs; unadjusted bootstrap p-values are reported descriptively only.

    r13 hardening: the confirmatory API REQUIRES the settlement ledger (losses
    recomputed from committed q + terminal y), the frozen prereg_root_hash
    (whole-ledger seed-schedule regeneration), and an enrollment lineage naming
    the source registry sha; each was previously optional and hence a bypass."""
    if assignment_ledger is None or enrollment is None:
        raise AnalysisError("R11-4: analyze_coprimary requires assignment_ledger and "
                            "enrollment (plus censoring ledger); ledger-free analysis is forbidden")
    if settlement is None:
        raise AnalysisError("R13-4: analyze_coprimary requires the settlement ledger; "
                            "caller-supplied losses are forbidden")
    if prereg_root_hash is None:
        raise AnalysisError("R13-5: analyze_coprimary requires the frozen prereg_root_hash; "
                            "an optional root was an auditable bypass")
    rs = (enrollment_lineage or {}).get("registry_sha256") if isinstance(enrollment_lineage, dict) else None
    if not (isinstance(rs, str) and len(rs) == 64 and all(ch in "0123456789abcdef" for ch in rs)):
        raise AnalysisError("R13-6: analyze_coprimary requires enrollment_lineage "
                            "{registry_sha256: <64-hex>} naming the family mapping's source; "
                            "referent verification happens at the gate layer")
    led = reconcile_ledgers(records, assignment_ledger, enrollment, censoring,
                            prereg_root_hash=prereg_root_hash, settlement=settlement)
    records = led["records"]        # losses DERIVED here, never caller-supplied
    waves = led["waves"]
    m = len(CANONICAL_COPRIMARY)
    level = 1 - alpha / m                 # Bonferroni: 97.5% each for alpha=0.05
    results = {}
    for i, c in enumerate(CANONICAL_COPRIMARY):
        taus = crossed_bootstrap_taus(records, c["arm_a"], c["arm_b"],
                                      n_boot, seed + i, waves=waves)
        ci = percentile_ci(taus, level)
        results[c["id"]] = {
            "arm_a": c["arm_a"], "arm_b": c["arm_b"],
            "tau_hat": contrast_tau(records, c["arm_a"], c["arm_b"], waves=waves),
            "p_unadjusted_descriptive": bootstrap_p_two_sided(taus),
            # r12: NOMINAL simultaneous level; actual coverage is certified only
            # by the production G6 coverage simulation, never claimed a priori
            "ci_level_nominal": level, "multiplicity": "bonferroni_nominal_pending_g6",
            "ci": ci, "decision": four_way(ci[0], ci[1], delta),
        }
    # R14-4: this function is the DEV/SIMULATION ENGINE — its parameters are
    # free so G6 can sweep planted worlds through the exact production code
    # path, and its output is TIERED so it can never ground a claim. The only
    # confirmatory entry is confirmatory.analyze_confirmatory, which reads
    # every statistical parameter from the frozen manifest and derives every
    # input from opened, re-hashed referents.
    results["_provenance"] = {"epistemic_status": "dev_engine_not_confirmatory",
                              "prereg_root_hash": prereg_root_hash,
                              "enrollment_registry_sha256": rs,
                              "n_settled": led["n_settled"],
                              "n_eligible_markets": len(led["eligible"])}
    return results
