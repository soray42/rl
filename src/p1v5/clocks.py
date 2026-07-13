"""Immutable canonical event ledger + settlement product state (E5, rebuilt).

Round-7 root cause: v5.0 folded state in ARRIVAL order. v5.1 stores raw events and
derives state as a PURE FOLD over the canonical order (t, source, msg_id) —
order-independence holds by construction, not by hoping events commute.

Fail-closed rules:
- structurally invalid events -> dead-letter, idempotency key NOT consumed;
- illegal transitions during fold -> question quarantined (never silently final);
- neg-risk group with two terminal YES -> whole group quarantined;
- prompt commitments are write-once per forecast_id; late ingestion can never
  rewrite one (recommit under the same id raises).
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

OUTCOMES = ("yes", "no", "unknown_50_50")
EVENT_KINDS = ("enroll", "close_trading", "clarification", "proposal", "challenge",
               "dispute_reset", "dvm", "dvm_too_early", "finalize", "observe",
               "apply_queue", "outcome_public")


class ClockError(Exception):
    pass


@dataclass(frozen=True)
class QuestionState:
    question_id: str
    enrolled: bool = False
    quarantined: bool = False
    quarantine_reason: Optional[str] = None
    rules_version: int = 1
    rules_effective_at: Optional[float] = None
    trading_state: str = "open"
    oracle_round: int = 0
    oracle_status: str = "none"
    terminal_outcome_kind: str = "none"
    prediction_cutoff: float = float("-inf")   # fail-closed until enroll sets it
    outcome_public_time: Optional[float] = None
    finalized_at: Optional[float] = None
    final_msg_key: Optional[str] = None
    observed_at: Optional[float] = None
    applied_at: Optional[float] = None
    group_id: Optional[str] = None
    source_published_at: Optional[float] = None
    source_retrieved_at: Optional[float] = None

    def is_final(self) -> bool:
        return (not self.quarantined and self.terminal_outcome_kind != "none"
                and self.finalized_at is not None)

    def endpoint_eligible(self) -> bool:
        return self.is_final() and self.terminal_outcome_kind in ("yes", "no")


def _finite(x) -> bool:
    import math
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def _validate_event(msg: dict) -> Optional[str]:
    import math
    for req in ("msg_id", "source", "question_id", "kind", "t"):
        if req not in msg:
            return f"missing field {req}"
    for sid in ("msg_id", "source", "question_id"):
        if not isinstance(msg[sid], str) or not msg[sid]:
            return f"{sid} must be a non-empty string"     # typed ids: canonical sort safety
    if "group_id" in msg and msg["group_id"] is not None and not isinstance(msg["group_id"], str):
        return "group_id must be a string"
    if msg["kind"] not in EVENT_KINDS:
        return f"unknown kind {msg['kind']}"
    if (not isinstance(msg["t"], (int, float)) or isinstance(msg["t"], bool)
            or not math.isfinite(msg["t"])):
        return "non-finite t"       # NaN/inf break the canonical total order (r8 #6)
    for opt in ("source_published_at", "source_retrieved_at"):
        if opt in msg and (not isinstance(msg[opt], (int, float))
                           or not math.isfinite(msg[opt])):
            return f"non-finite {opt}"
    if msg["kind"] == "enroll" and (
            not isinstance(msg.get("prediction_cutoff"), (int, float))
            or isinstance(msg.get("prediction_cutoff"), bool)
            or not math.isfinite(msg.get("prediction_cutoff"))):
        return "enroll without finite numeric prediction_cutoff"
    if msg["kind"] == "finalize" and msg.get("outcome") not in OUTCOMES:
        return f"illegal outcome {msg.get('outcome')!r}"
    if msg["kind"] == "proposal" and not isinstance(msg.get("round"), int):
        return "proposal without integer round"
    if msg["kind"] == "clarification" and not isinstance(msg.get("rules_version"), int):
        return "clarification without integer rules_version"
    return None


def _quarantine(cur: QuestionState, reason: str) -> QuestionState:
    from dataclasses import replace
    return replace(cur, quarantined=True, quarantine_reason=reason)


def _fold_one(cur: QuestionState, msg: dict) -> QuestionState:
    """Pure transition. Illegal transition => quarantine (fail closed)."""
    from dataclasses import replace
    if cur.quarantined:
        return cur
    kind = msg["kind"]
    if not cur.enrolled and kind != "enroll":
        return _quarantine(cur, f"event {kind} before enroll")
    if kind == "enroll":
        if cur.enrolled:
            return _quarantine(cur, "double enroll")
        return replace(cur, enrolled=True, prediction_cutoff=msg["prediction_cutoff"],
                       rules_effective_at=msg["t"], group_id=msg.get("group_id"))
    if kind == "close_trading":
        return replace(cur, trading_state="closed")
    if kind == "clarification":
        if msg["rules_version"] <= cur.rules_version:
            return _quarantine(cur, "non-monotone rules_version")
        return replace(cur, rules_version=msg["rules_version"], rules_effective_at=msg["t"])
    if kind == "proposal":
        if cur.terminal_outcome_kind != "none":
            return _quarantine(cur, "proposal after finalize")
        if cur.oracle_status not in ("none",):
            return _quarantine(cur, f"proposal while status={cur.oracle_status}")
        if msg["round"] != cur.oracle_round + 1:
            return _quarantine(cur, f"non-consecutive proposal round {msg['round']}")
        return replace(cur, oracle_round=msg["round"], oracle_status="proposed")
    if kind == "challenge":
        if cur.oracle_status != "proposed" or msg.get("round") != cur.oracle_round:
            return _quarantine(cur, "challenge without matching live proposal")
        return replace(cur, oracle_status="challenged")
    if kind == "dispute_reset":
        # official flow (T10-R3): ONLY the first challenge resets to a new proposal
        if cur.oracle_status != "challenged":
            return _quarantine(cur, "dispute_reset without challenge")
        if cur.oracle_round != 1:
            return _quarantine(cur, f"dispute_reset at round {cur.oracle_round}: second+ challenge must go to DVM")
        return replace(cur, oracle_status="none")
    if kind == "dvm":
        # official flow (T10-R3): DVM is reachable ONLY from the second+ challenge
        if cur.oracle_status != "challenged":
            return _quarantine(cur, "dvm without challenge")
        if cur.oracle_round < 2:
            return _quarantine(cur, "dvm after FIRST challenge: must dispute_reset instead")
        return replace(cur, oracle_status="dvm")
    if kind == "dvm_too_early":
        if cur.oracle_status != "dvm":
            return _quarantine(cur, "too_early outside dvm")
        return replace(cur, oracle_status="none")
    if kind == "finalize":
        if cur.oracle_status not in ("proposed", "dvm"):
            return _quarantine(cur, f"finalize from status={cur.oracle_status}")
        if cur.terminal_outcome_kind != "none":
            return _quarantine(cur, "double finalize")
        return replace(cur, terminal_outcome_kind=msg["outcome"], finalized_at=msg["t"],
                       final_msg_key=msg["msg_id"], trading_state="closed",
                       oracle_status="none")
    if kind == "observe":
        upd = {}
        if cur.observed_at is None or msg["t"] < cur.observed_at:
            upd["observed_at"] = msg["t"]
        for f in ("source_published_at", "source_retrieved_at"):
            if f in msg and (getattr(cur, f) is None or msg[f] < getattr(cur, f)):
                upd[f] = msg[f]
        return replace(cur, **upd) if upd else cur
    if kind == "apply_queue":
        if cur.observed_at is None:
            return _quarantine(cur, "apply before observe")
        if cur.applied_at is None or msg["t"] < cur.applied_at:
            return replace(cur, applied_at=max(msg["t"], cur.observed_at))
        return cur
    if kind == "outcome_public":
        if cur.outcome_public_time is None or msg["t"] < cur.outcome_public_time:
            return replace(cur, outcome_public_time=msg["t"])
        return cur
    raise ClockError(f"unreachable kind {kind}")


@dataclass
class Ledger:
    events: dict = field(default_factory=dict)        # scoped key -> raw event (immutable)
    dead_letter: list = field(default_factory=list)
    commitments: dict = field(default_factory=dict)   # forecast_id -> commitment (write-once)

    # -- ingestion ---------------------------------------------------------
    def ingest(self, msg: dict) -> bool:
        err = _validate_event(msg)
        if err is not None:
            self.dead_letter.append({"event": msg, "reason": err})
            return False                                # idempotency key NOT consumed
        key = (msg["source"], msg["question_id"], msg["msg_id"])
        if key in self.events:
            if self.events[key] != msg:
                self.dead_letter.append({"event": msg, "reason": "idempotency key reuse with different payload"})
            return False
        self.events[key] = dict(msg)
        return True

    # -- canonical fold ----------------------------------------------------
    def _canonical_events(self, question_id: Optional[str] = None) -> list:
        evs = [e for e in self.events.values()
               if question_id is None or e["question_id"] == question_id]
        return sorted(evs, key=lambda e: (e["t"], e["source"], e["msg_id"]))

    def _fold_single(self, question_id: str) -> QuestionState:
        cur = QuestionState(question_id=question_id)
        for e in self._canonical_events(question_id):
            cur = _fold_one(cur, e)
        return cur

    def state(self, question_id: str) -> QuestionState:
        """Single-question view GOES THROUGH the global invariants (r8 #6): the
        neg-risk group check can never be bypassed by asking for one question."""
        return self.all_states().get(question_id, QuestionState(question_id=question_id))

    def all_states(self) -> dict:
        qids = {e["question_id"] for e in self.events.values()}
        states = {qid: self._fold_single(qid) for qid in sorted(qids)}
        # neg-risk group invariant: at most one terminal yes per group
        groups: dict = {}
        for q in states.values():
            if q.group_id is not None and q.terminal_outcome_kind == "yes":
                groups.setdefault(q.group_id, []).append(q.question_id)
        from dataclasses import replace
        for gid, winners in groups.items():
            if len(winners) > 1:
                for qid, q in states.items():
                    if q.group_id == gid:
                        states[qid] = replace(q, quarantined=True,
                                              quarantine_reason=f"negrisk group {gid} has {len(winners)} yes winners")
        return states

    # -- admissibility -----------------------------------------------------
    @staticmethod
    def forecast_admissible(q: QuestionState, input_at: float, forecast_at: float) -> bool:
        if not (_finite(input_at) and _finite(forecast_at)):   # T10 §6.2: non-finite args fail closed
            return False
        if q.quarantined or not q.enrolled:
            return False
        if q.trading_state != "open" or q.is_final():
            return False
        if not (input_at < forecast_at < q.prediction_cutoff):
            return False
        if q.outcome_public_time is not None and q.outcome_public_time <= forecast_at:
            return False
        return True

    @staticmethod
    def feedback_eligible(q: QuestionState, prompt_state_cutoff: float, forecast_at: float) -> bool:
        if not (_finite(prompt_state_cutoff) and _finite(forecast_at)):
            return False
        if q.quarantined or not q.is_final():
            return False
        if q.observed_at is None or q.applied_at is None:
            return False
        return (q.finalized_at <= q.observed_at <= q.applied_at
                <= prompt_state_cutoff < forecast_at)

    # -- prompt commitment (write-once) -------------------------------------
    def freeze_prompt(self, forecast_id: str, prompt_state_cutoff: float,
                      forecast_at: float, memory_sha: str = "0" * 64,
                      model_config: str = "toy") -> str:
        import re as _re
        if not isinstance(forecast_id, str) or not forecast_id:
            raise ClockError("forecast_id must be a non-empty string")
        if not (_finite(prompt_state_cutoff) and _finite(forecast_at)):
            raise ClockError("non-finite commitment timestamps refused")
        if not _re.fullmatch(r"[0-9a-f]{64}", memory_sha):
            raise ClockError("memory_sha must be 64-hex")
        if forecast_id in self.commitments:
            raise ClockError(f"forecast_id {forecast_id} already committed (write-once)")
        states = self.all_states()
        visible = [
            {"question_id": q.question_id, "outcome": q.terminal_outcome_kind,
             "rules_version": q.rules_version, "finalized_at": q.finalized_at,
             "observed_at": q.observed_at, "applied_at": q.applied_at}
            for q in states.values()
            if self.feedback_eligible(q, prompt_state_cutoff, forecast_at)
        ]
        visible.sort(key=lambda d: d["question_id"])
        payload = json.dumps({"visible": visible, "memory_sha": memory_sha,
                              "model_config": model_config,
                              "prompt_state_cutoff": prompt_state_cutoff,
                              "forecast_at": forecast_at},
                             sort_keys=True, separators=(",", ":"))
        h = hashlib.sha256(payload.encode()).hexdigest()
        self.commitments[forecast_id] = {"hash": h, "payload": payload}
        return h
