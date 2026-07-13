"""Endpoint scoring v5.2 (round-8 finding #7 closures).

- failure penalty is selected by MODE, never by a free numeric parameter:
  "primary" -> manifest failure_loss (1.0); "sensitivity_025" -> 0.25;
- all-censored enrollment is an explicit error, not ZeroDivisionError;
- duplicate enrollment ids rejected;
- explicit failure-class channel (deliberate_abstention / provider_failure /
  invalid_parse / timeout) via the `failures` map; unexplained None defaults to
  provider_failure.
Known open item (ledgered, E4): failure side effects on later memory/resource
state are only excludable once the real pipeline exists."""

import math

from .config import get_config

FAILURE_CLASSES = ("deliberate_abstention", "provider_failure", "invalid_parse", "timeout")
MODES = ("primary", "sensitivity_025")


class ScoringError(Exception):
    pass


def brier(q: float, y: int) -> float:
    return (q - y) ** 2


def _valid_q(q) -> bool:
    return (isinstance(q, (int, float)) and not isinstance(q, bool)
            and math.isfinite(q) and 0.0 <= q <= 1.0)


def score_stream(forecasts: dict, outcomes: dict, enrollment: list,
                 mode: str = "primary", failures: dict = None) -> dict:
    if mode not in MODES:
        raise ScoringError(f"unknown scoring mode {mode!r}; allowed: {MODES}")
    cfg = get_config()
    penalty = cfg.failure_loss if mode == "primary" else 0.25
    failures = failures or {}
    if not enrollment:
        raise ScoringError("empty enrollment: refusing vacuous zero-loss success")
    if len(set(enrollment)) != len(enrollment):
        raise ScoringError("duplicate market ids in enrollment")
    enrolled_set = set(enrollment)
    for mid, cls in failures.items():
        if cls not in FAILURE_CLASSES:
            raise ScoringError(f"unknown failure class {cls!r} for {mid}")
        if mid not in enrolled_set:                 # r9 §8: no orphan failure receipts
            raise ScoringError(f"failure receipt for unenrolled market {mid}")
    missing_from_outcomes = [m for m in enrollment if m not in outcomes]
    extraneous = [m for m in outcomes if m not in enrollment]
    if extraneous:
        raise ScoringError(f"outcomes for unenrolled markets: {extraneous}")
    if not outcomes:
        raise ScoringError("all enrolled markets censored: no scoreable outcomes; "
                           "report attrition, do not fabricate an endpoint")
    ledger, total = [], 0.0
    for mid in sorted(outcomes):
        y = outcomes[mid]
        if y not in (0, 1) or isinstance(y, bool):
            raise ScoringError(f"invalid outcome y={y!r} for {mid}")
        q = forecasts.get(mid)
        failure = None
        if _valid_q(q):
            if mid in failures:                     # r9 §8: valid q + failure receipt
                raise ScoringError(f"conflicting records for {mid}: valid forecast "
                                   f"AND failure receipt {failures[mid]!r} (fail closed)")
            loss = brier(float(q), y)
        else:
            failure = failures.get(mid) or ("invalid_parse" if q is not None
                                            else "provider_failure")
            loss = penalty
            q = None
        total += loss
        ledger.append({"market_id": mid, "q": q, "y": y, "loss": loss,
                       "failure_class": failure})
    n = len(ledger)
    return {"mean_brier": total / n, "n_scored": n, "mode": mode,
            "n_enrolled": len(enrollment), "censored": missing_from_outcomes,
            "failure_rate": sum(1 for e in ledger if e["failure_class"]) / n,
            "ledger": ledger}
