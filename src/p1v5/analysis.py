"""E3: randomized assignment, ITT estimator, crossed bootstrap, Holm, four-way.

Implements the manifest's frozen statistical design:
- assignment: blocked equal-probability randomization of the 5 arms per
  enrollment wave, seeds = sha256(prereg_root_hash + index), ledgered;
- endpoint: per-trajectory mean Brier over eligible markets (manifest metric);
- contrast: tau = mean(arm_a) - mean(arm_b), negative favors arm_a;
- uncertainty: crossed cluster bootstrap resampling event FAMILIES and
  TRAJECTORIES independently (round-4/round-5 pseudo-replication lessons);
- multiplicity: Holm over the two pinned co-primary contrasts;
- decision: four-way interval rule (benefit/equivalence/harm/inconclusive);
  equivalence ONLY via CI containment in [-delta, +delta] (Lakens discipline).

This module is deliberately dependency-free and deterministic given seeds.
G6's power/Type-I simulation must use THESE functions (audit E3 requirement).
"""

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
    """Domain-separated (r11 P1-7): 'traj' domain, never colliding with assignment."""
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


def contrast_tau(records: list, arm_a: str, arm_b: str) -> float:
    means = _trajectory_means(records)
    a = [m for arm, m in means.values() if arm == arm_a]
    b = [m for arm, m in means.values() if arm == arm_b]
    if not a or not b:
        raise AnalysisError(f"empty arm in contrast {arm_a} vs {arm_b}")
    return sum(a) / len(a) - sum(b) / len(b)


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


def crossed_bootstrap_taus(records: list, arm_a: str, arm_b: str,
                           n_boot: int, seed: int) -> list:
    """Resample FAMILIES and TRAJECTORIES independently (crossed uncertainty).
    A resampled dataset keeps only records whose family AND trajectory were
    drawn; multiplicities multiply."""
    _guard_cluster_sizes(records, arm_a, arm_b)
    rng = random.Random(seed)
    families = sorted({r["family_id"] for r in records})
    trajs = sorted({r["trajectory_id"] for r in records})
    by_key = defaultdict(list)
    for r in records:
        by_key[(r["family_id"], r["trajectory_id"])].append(r)
    arm_of = {}
    for r in records:
        arm_of[r["trajectory_id"]] = r["arm"]
    # R11-5: trajectory resampling is STRATIFIED BY ARM — per-arm counts are
    # preserved by construction, no replicate ever lacks an arm, the blocked
    # design is respected (never pooled-then-dropped).
    trajs_by_arm = defaultdict(list)
    for t_ in trajs:
        trajs_by_arm[arm_of[t_]].append(t_)
    taus = []
    for _ in range(n_boot):
        fam_counts = defaultdict(int)
        for _ in families:
            fam_counts[rng.choice(families)] += 1
        traj_counts = defaultdict(int)
        for arm_trajs in trajs_by_arm.values():
            for _ in arm_trajs:
                traj_counts[rng.choice(arm_trajs)] += 1
        # shadow-audit r1 P0-3 fix: trajectory resample WEIGHTS must survive
        # aggregation. Per-trajectory means are recomputed on family-resampled
        # records, then averaged across trajectories WEIGHTED by traj_counts —
        # a trajectory drawn 5x contributes 5x, not merely "present".
        traj_mean = {}
        for traj in trajs:
            if traj_counts[traj] == 0:
                continue
            num = den = 0.0
            for fam in families:
                w = fam_counts[fam]
                if w == 0:
                    continue
                rs = by_key.get((fam, traj))
                if rs:
                    num += w * sum(r["loss"] for r in rs)
                    den += w * len(rs)
            if den > 0:
                traj_mean[traj] = num / den
        def arm_mean(arm):
            num = den = 0.0
            for traj, m in traj_mean.items():
                if arm_of[traj] == arm:
                    num += traj_counts[traj] * m
                    den += traj_counts[traj]
            return num / den if den else None
        ma, mb = arm_mean(arm_a), arm_mean(arm_b)
        if ma is None or mb is None:
            continue        # a resample may drop an arm entirely; skip, do not fabricate
        taus.append(ma - mb)
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
# Holm + four-way decision over the two pinned co-primary contrasts
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


def reconcile_ledgers(records: list, assignment_ledger: list,
                      enrollment: list, censoring: list = None) -> None:
    """R11-4: full-join validation BEFORE any estimation. A randomized trajectory
    can never vanish; every enrolled eligible market needs exactly one row
    (forecast or typed-failure with frozen loss) per trajectory; losses are
    finite in [0,1]; censored markets are excluded consistently for everyone."""
    import math
    censoring = set(censoring or [])
    expected_trajs = {e["trajectory_id"]: e["arm"] for e in assignment_ledger}
    if not expected_trajs:
        raise AnalysisError("empty assignment ledger")
    eligible = [m for m in enrollment if m not in censoring]
    if not eligible:
        raise AnalysisError("no eligible markets after censoring")
    seen = defaultdict(set)
    for r in records:
        t_, mkt = r["trajectory_id"], r["market_id"]
        if t_ not in expected_trajs:
            raise AnalysisError(f"unexpected trajectory {t_} not in assignment ledger")
        if r["arm"] != expected_trajs[t_]:
            raise AnalysisError(f"trajectory {t_} arm {r['arm']} != ledger {expected_trajs[t_]}")
        if mkt in censoring:
            raise AnalysisError(f"record for censored market {mkt} (must be excluded for ALL)")
        if mkt not in set(enrollment):
            raise AnalysisError(f"record for unenrolled market {mkt}")
        if not (isinstance(r["loss"], (int, float)) and math.isfinite(r["loss"])
                and 0.0 <= r["loss"] <= 1.0):
            raise AnalysisError(f"loss out of [0,1] or non-finite for {t_}/{mkt}: {r['loss']!r}")
        if mkt in seen[t_]:
            raise AnalysisError(f"duplicate market {mkt} for trajectory {t_}")
        seen[t_].add(mkt)
    for t_ in expected_trajs:
        missing = set(eligible) - seen[t_]
        if missing:
            raise AnalysisError(
                f"ITT violation: randomized trajectory {t_} lacks rows for "
                f"{len(missing)} eligible markets (e.g. {sorted(missing)[:3]}); "
                f"failures must enter as typed frozen-loss rows, never deletions")


def analyze_coprimary(records: list, delta: float, alpha: float = 0.05,
                      n_boot: int = 2000, seed: int = 20260713,
                      assignment_ledger: list = None, enrollment: list = None,
                      censoring: list = None) -> dict:
    """Both pinned contrasts with BONFERRONI SIMULTANEOUS CIs (R11-5): each
    co-primary gets a percentile CI at level 1 - alpha/2, giving provable
    simultaneous coverage >= 1 - alpha without stepdown machinery. Four-way
    decisions read directly off these simultaneous CIs; unadjusted bootstrap
    p-values are reported descriptively only."""
    if assignment_ledger is None or enrollment is None:
        raise AnalysisError("R11-4: analyze_coprimary requires assignment_ledger and "
                            "enrollment (plus censoring ledger); ledger-free analysis is forbidden")
    reconcile_ledgers(records, assignment_ledger, enrollment, censoring)
    m = len(CANONICAL_COPRIMARY)
    level = 1 - alpha / m                 # Bonferroni: 97.5% each for alpha=0.05
    results = {}
    for i, c in enumerate(CANONICAL_COPRIMARY):
        taus = crossed_bootstrap_taus(records, c["arm_a"], c["arm_b"],
                                      n_boot, seed + i)
        ci = percentile_ci(taus, level)
        results[c["id"]] = {
            "arm_a": c["arm_a"], "arm_b": c["arm_b"],
            "tau_hat": contrast_tau(records, c["arm_a"], c["arm_b"]),
            "p_unadjusted_descriptive": bootstrap_p_two_sided(taus),
            "ci_level": level, "multiplicity": "bonferroni_simultaneous",
            "ci": ci, "decision": four_way(ci[0], ci[1], delta),
        }
    return results
