"""Typed credit-to-memory policies v5.2.

Round-8 structural fixes:
- G2 BY CONSTRUCTION: the memory pipeline consumes raw (q, y) records and computes
  credits under the internal canonical Brier convention. There is NO parameter
  through which a published-score affine transform can reach memory — the round-8
  in-domain cancellation counterexample has no code path anymore.
- MAGNITUDE RE-ENTRY (round-8 identity finding): each memory item stores the
  scale-free quantized credit ratio; retrieval and eviction order by |ratio|, so
  fine-grained credit VALUES (not just rank/sign) shape memory behavior.
"""

import hashlib
import json
import random
from dataclasses import dataclass
from typing import Optional

from .config import get_config

NEUTRAL_REPLACEMENT_EFFECT = 0.02
QUANT_SIG_DIGITS = 9


def brier_utility(q: float, y: int) -> float:
    """Internal canonical convention. Not configurable, not injectable."""
    return -((q - y) ** 2)


@dataclass(frozen=True)
class MemoryItem:
    key: str
    text: str
    rank: int
    sign: int
    ratio: float            # quantized, scale-free relative credit magnitude
    feedback_clock: float

    def sha(self) -> str:
        return hashlib.sha256(json.dumps(
            [self.key, self.text, self.rank, self.sign, repr(self.ratio),
             self.feedback_clock], sort_keys=True).encode()).hexdigest()


class MemoryState:
    def __init__(self, items: Optional[list] = None, applied_batches: Optional[set] = None):
        self.items: list = list(items or [])
        self.applied_batches: set = set(applied_batches or ())

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {"items": [[i.key, i.text, i.rank, i.sign, repr(i.ratio), i.feedback_clock]
                       for i in self.items],
             "applied_batches": sorted(self.applied_batches)},
            sort_keys=True).encode()

    def sha(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def write_batch(self, batch_id: str, new_items: list) -> "MemoryState":
        if batch_id in self.applied_batches:      # exactly-once
            return self
        cfg = get_config()
        items = self.items + sorted(new_items, key=lambda i: (i.rank, i.key))
        if len(items) > cfg.capacity_items:
            # eviction: lowest |ratio| first, then oldest feedback clock, then key
            items = sorted(items, key=lambda i: (-abs(i.ratio), i.feedback_clock, i.key),
                           )[:cfg.capacity_items]
        return MemoryState(items, self.applied_batches | {batch_id})

    def retrieve(self) -> list:
        cfg = get_config()
        return sorted(self.items,
                      key=lambda i: (-abs(i.ratio), -i.feedback_clock, i.sha())
                      )[:cfg.retrieval_top_m]


def quantize_ratio(value: float, ref: float) -> float:
    if ref == 0.0:
        return 0.0
    r = value / ref
    if r == 0.0:
        return 0.0
    from math import floor, log10
    digits = QUANT_SIG_DIGITS - 1 - floor(log10(abs(r)))
    return round(r, int(digits))


def rank_and_sign(credits: dict) -> dict:
    """Within-batch normalization: key -> (rank, sign, quantized_ratio)."""
    ref = max((abs(v) for v in credits.values()), default=0.0)
    quant = {k: quantize_ratio(v, ref) for k, v in credits.items()}
    order = sorted(quant.items(), key=lambda kv: (-abs(kv[1]), kv[0]))
    out = {}
    for pos, (key, q) in enumerate(order, start=1):
        out[key] = (pos, 1 if q > 0 else (-1 if q < 0 else 0), q)
    return out


# ---------------------------------------------------------------------------
# Toy deliberation world (raw q/y only; receipts for compute parity)
# ---------------------------------------------------------------------------

class ToyDeliberation:
    def __init__(self, effects: dict, y: int):
        self.effects = dict(effects)
        self.y = y
        self.receipts: list = []

    def team_prob(self, effect_map: Optional[dict] = None) -> float:
        eff = self.effects if effect_map is None else effect_map
        return min(0.99, max(0.01, 0.5 + sum(eff.values())))

    def rollout(self, effect_map: dict, receipt_kind: str) -> float:
        self.receipts.append({"kind": receipt_kind, "n_effects": len(effect_map)})
        return self.team_prob(effect_map)


# ---------------------------------------------------------------------------
# Credits: functions of raw (probabilities, outcome) ONLY
# ---------------------------------------------------------------------------

def credit_shared_surplus(world: ToyDeliberation) -> dict:
    surplus = brier_utility(world.team_prob(), world.y) - brier_utility(0.5, world.y)
    return {k: surplus for k in world.effects}


def credit_diff_agent(world: ToyDeliberation) -> dict:
    full = brier_utility(world.team_prob(), world.y)
    out = {}
    for k in world.effects:
        rest = {kk: v for kk, v in world.effects.items() if kk != k}
        out[k] = full - brier_utility(world.team_prob(rest), world.y)
    return out


def _c3_rollout_credits(world: ToyDeliberation, receipt_kind: str) -> dict:
    base = brier_utility(world.rollout(world.effects, receipt_kind), world.y)
    out = {}
    for k in sorted(world.effects):
        replaced = dict(world.effects)
        replaced[k] = NEUTRAL_REPLACEMENT_EFFECT
        out[k] = base - brier_utility(world.rollout(replaced, receipt_kind), world.y)
    return out


def credit_c3_action(world: ToyDeliberation) -> dict:
    return _c3_rollout_credits(world, "c3_action")


def sattolo_derangement(keys: list, seed: int) -> dict:
    perm = list(keys)
    rng = random.Random(seed)
    for i in range(len(perm) - 1, 0, -1):
        j = rng.randrange(i)
        perm[i], perm[j] = perm[j], perm[i]
    return dict(zip(keys, perm))


def credit_c3_sham(world: ToyDeliberation, batch_id: str) -> dict:
    real = _c3_rollout_credits(world, "c3_action")
    keys = sorted(real)
    if len(keys) < 2:
        return {k: 0.0 for k in keys}
    seed = int(hashlib.sha256(batch_id.encode()).hexdigest()[:8], 16)
    mapping = sattolo_derangement(keys, seed)
    return {k: real[mapping[k]] for k in keys}


# ---------------------------------------------------------------------------
# Arms (no utility parameter exists anywhere in the update path)
# ---------------------------------------------------------------------------

def _admit(norm: dict, feedback_clock: float) -> list:
    cfg = get_config()
    picked = sorted(norm.items(), key=lambda kv: (kv[1][0], kv[0]))[:cfg.admission_top_k]
    return [MemoryItem(key=k, text=f"experience:{k}", rank=r, sign=s, ratio=q,
                       feedback_clock=feedback_clock)
            for k, (r, s, q) in picked if s > 0]


class Arm:
    arm_id = "abstract"

    def _credits(self, world, batch_id):
        raise NotImplementedError

    def update(self, memory: MemoryState, world: ToyDeliberation,
               feedback_clock: float, batch_id: str) -> MemoryState:
        if batch_id in memory.applied_batches:
            return memory
        credits = self._credits(world, batch_id)
        if credits is None:
            return memory.write_batch(batch_id, [])
        return memory.write_batch(batch_id, _admit(rank_and_sign(credits), feedback_clock))


class NoUpdate(Arm):
    arm_id = "no_update"

    def _credits(self, world, batch_id):
        return None


class SharedSurplus(Arm):
    arm_id = "shared_surplus"

    def _credits(self, world, batch_id):
        return credit_shared_surplus(world)


class DiffAgentCredit(Arm):
    arm_id = "diff_agent_credit"

    def _credits(self, world, batch_id):
        return credit_diff_agent(world)


class C3Action(Arm):
    arm_id = "c3_action"

    def _credits(self, world, batch_id):
        return credit_c3_action(world)


class C3ComputeMatchedSham(Arm):
    arm_id = "c3_compute_matched_sham"

    def _credits(self, world, batch_id):
        return credit_c3_sham(world, batch_id)


ARMS = {a.arm_id: a for a in [NoUpdate(), SharedSurplus(), DiffAgentCredit(),
                              C3Action(), C3ComputeMatchedSham()]}


def published_score(mean_brier: float, a: float, b: float) -> float:
    """The ONLY place an affine convention exists: reporting. Guarded by the
    manifest's admissible domain; has no path back into any policy object."""
    cfg = get_config()
    dom = cfg.manifest["score_invariance"]["admissible_domain"]
    if not (abs(a) <= dom["a_abs_max"] and dom["b_min"] <= b <= dom["b_max"]):
        raise ValueError("reporting transform outside admissible domain")
    return a + b * mean_brier
