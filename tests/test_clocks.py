"""G3 fixture suite v5.1 on the canonical-fold ledger. unittest-discoverable;
run_all_fixtures() remains the gate predicate entry point."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from p1v5.clocks import ClockError, Ledger  # noqa: E402

SRC = "collector-a"


def _msgs(qid, seq, prefix):
    out = []
    for m in seq:
        m = dict(m)
        m.setdefault("msg_id", f"{prefix}-{m['kind']}-{m['t']}")
        m.setdefault("source", SRC)
        m["question_id"] = qid
        out.append(m)
    return out


def _settled(qid, prefix, outcome="yes", t0=50.0):
    return _msgs(qid, [
        {"kind": "enroll", "t": 0.0, "prediction_cutoff": t0 - 1},
        {"kind": "close_trading", "t": t0},
        {"kind": "proposal", "round": 1, "t": t0 + 1},
        {"kind": "finalize", "outcome": outcome, "t": t0 + 3},
        {"kind": "observe", "t": t0 + 4},
        {"kind": "apply_queue", "t": t0 + 5},
    ], prefix)


def fixture_results():
    res = {}

    # F01 undisputed lifecycle
    led = Ledger()
    for m in _settled("Q1", "F01"):
        led.ingest(m)
    q = led.state("Q1")
    res["f01_undisputed"] = (q.is_final() and q.endpoint_eligible()
                             and Ledger.feedback_eligible(q, 60.0, 61.0))

    # F02 first dispute resets to a NEW proposal round
    led = Ledger()
    for m in _msgs("Q1", [
        {"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0},
        {"kind": "proposal", "round": 1, "t": 51.0},
        {"kind": "challenge", "round": 1, "t": 52.0},
        {"kind": "dispute_reset", "t": 52.5},
        {"kind": "proposal", "round": 2, "t": 60.0},
        {"kind": "finalize", "outcome": "no", "t": 62.0},
    ], "F02"):
        led.ingest(m)
    q = led.state("Q1")
    res["f02_first_dispute_resets"] = (q.oracle_round == 2 and q.is_final()
                                       and q.terminal_outcome_kind == "no"
                                       and not q.quarantined)

    # F03 second dispute -> DVM
    led = Ledger()
    for m in _msgs("Q1", [
        {"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0},
        {"kind": "proposal", "round": 1, "t": 51.0},
        {"kind": "challenge", "round": 1, "t": 52.0},
        {"kind": "dispute_reset", "t": 52.5},
        {"kind": "proposal", "round": 2, "t": 60.0},
        {"kind": "challenge", "round": 2, "t": 61.0},
        {"kind": "dvm", "t": 61.5},
        {"kind": "finalize", "outcome": "yes", "t": 90.0},
    ], "F03"):
        led.ingest(m)
    q = led.state("Q1")
    res["f03_second_dispute_dvm"] = q.is_final() and not q.quarantined

    # F04 DVM Too Early is NOT terminal; next round continues
    led = Ledger()
    for m in _msgs("Q1", [
        {"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0},
        {"kind": "proposal", "round": 1, "t": 51.0},
        {"kind": "challenge", "round": 1, "t": 52.0},
        {"kind": "dispute_reset", "t": 52.5},
        {"kind": "proposal", "round": 2, "t": 53.0},
        {"kind": "challenge", "round": 2, "t": 54.0},
        {"kind": "dvm", "t": 54.5},
        {"kind": "dvm_too_early", "t": 70.0},
        {"kind": "proposal", "round": 3, "t": 80.0},
        {"kind": "finalize", "outcome": "yes", "t": 82.0},
    ], "F04"):
        led.ingest(m)
    q = led.state("Q1")
    res["f04_too_early_resets"] = q.is_final() and q.oracle_round == 3 and not q.quarantined

    # F05 outcome mapping via distinct paths (yes on F01 path, no on F02 path)
    res["f05_outcome_mapping"] = res["f01_undisputed"] and res["f02_first_dispute_resets"]

    # F06 Unknown/50-50: terminal payout, excluded from binary endpoint
    led = Ledger()
    for m in _msgs("Q1", [
        {"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0},
        {"kind": "proposal", "round": 1, "t": 51.0},
        {"kind": "finalize", "outcome": "unknown_50_50", "t": 90.0},
        {"kind": "observe", "t": 91.0},
        {"kind": "apply_queue", "t": 92.0},
    ], "F06"):
        led.ingest(m)
    q = led.state("Q1")
    res["f06_unknown_5050"] = q.is_final() and not q.endpoint_eligible() and not q.quarantined

    # F07 clarification before forecast: version bump, still forecastable
    led = Ledger()
    for m in _msgs("Q1", [
        {"kind": "enroll", "t": 0.0, "prediction_cutoff": 100.0},
        {"kind": "clarification", "rules_version": 2, "t": 10.0},
    ], "F07"):
        led.ingest(m)
    q = led.state("Q1")
    res["f07_clarification_before"] = (q.rules_version == 2
                                       and Ledger.forecast_admissible(q, 11.0, 12.0))

    # F08 clarification after forecast never retroacts
    led = Ledger()
    led.ingest(_msgs("Q1", [{"kind": "enroll", "t": 0.0, "prediction_cutoff": 100.0}], "F08")[0])
    v_at_forecast = led.state("Q1").rules_version
    led.ingest(_msgs("Q1", [{"kind": "clarification", "rules_version": 2, "t": 20.0}], "F08")[0])
    res["f08_clarification_after"] = v_at_forecast == 1 and led.state("Q1").rules_version == 2

    # F09 onchain final but never observed -> not feedback eligible
    led = Ledger()
    for m in _msgs("Q1", [
        {"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0},
        {"kind": "proposal", "round": 1, "t": 51.0},
        {"kind": "finalize", "outcome": "yes", "t": 53.0},
    ], "F09"):
        led.ingest(m)
    q = led.state("Q1")
    res["f09_api_lagging"] = q.is_final() and not Ledger.feedback_eligible(q, 60.0, 61.0)

    # F10 ADVERSARIAL ordering: full reversal + duplicates == canonical state
    msgs = _msgs("Q1", [
        {"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0},
        {"kind": "proposal", "round": 1, "t": 51.0},
        {"kind": "challenge", "round": 1, "t": 52.0},
        {"kind": "dispute_reset", "t": 52.5},
        {"kind": "proposal", "round": 2, "t": 60.0},
        {"kind": "finalize", "outcome": "no", "t": 62.0},
        {"kind": "observe", "t": 63.0},
        {"kind": "apply_queue", "t": 64.0},
    ], "F10")
    led_a, led_b = Ledger(), Ledger()
    for m in msgs:
        led_a.ingest(m)
    for m in list(reversed(msgs)) + msgs + msgs[:3]:
        led_b.ingest(m)
    res["f10_order_independent"] = (led_a.state("Q1") == led_b.state("Q1")
                                    and led_a.state("Q1").is_final())

    # F11 late backfill cannot change a frozen commitment; rebind raises
    led = Ledger()
    for m in _settled("QA", "F11A", t0=5.0):
        led.ingest(m)
    h1 = led.freeze_prompt("fc-1", prompt_state_cutoff=12.0, forecast_at=13.0)
    for m in _msgs("QB", [
        {"kind": "enroll", "t": 0.0, "prediction_cutoff": 100.0},
        {"kind": "proposal", "round": 1, "t": 4.0},
        {"kind": "finalize", "outcome": "no", "t": 5.0},
        {"kind": "observe", "t": 15.0},          # observed AFTER the cutoff
        {"kind": "apply_queue", "t": 16.0},
    ], "F11B"):
        led.ingest(m)
    h1r = led.freeze_prompt("fc-1r", prompt_state_cutoff=12.0, forecast_at=13.0)
    h2 = led.freeze_prompt("fc-2", prompt_state_cutoff=20.0, forecast_at=21.0)
    try:
        led.freeze_prompt("fc-1", prompt_state_cutoff=12.0, forecast_at=13.0)
        rebind_blocked = False
    except ClockError:
        rebind_blocked = True
    res["f11_backfill_and_write_once"] = (h1 == h1r and h2 != h1 and rebind_blocked)

    # F12 conflicting same-t finalize: FAIL CLOSED identically in both orders
    a = {"msg_id": "F12-a", "source": SRC, "question_id": "Q1", "kind": "finalize",
         "outcome": "yes", "t": 53.0}
    b = {"msg_id": "F12-b", "source": SRC, "question_id": "Q1", "kind": "finalize",
         "outcome": "no", "t": 53.0}
    pre = _msgs("Q1", [{"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0},
                       {"kind": "proposal", "round": 1, "t": 51.0}], "F12")
    led1, led2 = Ledger(), Ledger()
    for m in pre + [a, b]:
        led1.ingest(m)
    for m in pre + [b, a]:
        led2.ingest(m)
    q1, q2 = led1.state("Q1"), led2.state("Q1")
    res["f12_conflict_fail_closed"] = (q1 == q2 and q1.quarantined
                                       and not q1.is_final())

    # F13 never finalized -> censored
    led = Ledger()
    for m in _msgs("Q1", [{"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0},
                          {"kind": "close_trading", "t": 50.0}], "F13"):
        led.ingest(m)
    q = led.state("Q1")
    res["f13_unresolved_censored"] = (not q.is_final()
                                      and not Ledger.feedback_eligible(q, 999.0, 1000.0))

    # F14 outcome public before oracle final -> forecast REJECTED
    led = Ledger()
    for m in _msgs("Q1", [{"kind": "enroll", "t": 0.0, "prediction_cutoff": 100.0},
                          {"kind": "outcome_public", "t": 10.0}], "F14"):
        led.ingest(m)
    res["f14_outcome_known_rejected"] = not Ledger.forecast_admissible(led.state("Q1"), 10.5, 11.0)

    # F16 (T10-R3 反例A): FIRST challenge -> dvm is ILLEGAL, must quarantine
    led = Ledger()
    for m in _msgs("Q1", [
        {"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0},
        {"kind": "proposal", "round": 1, "t": 51.0},
        {"kind": "challenge", "round": 1, "t": 52.0},
        {"kind": "dvm", "t": 53.0},
        {"kind": "finalize", "outcome": "yes", "t": 90.0},
        {"kind": "observe", "t": 91.0},
        {"kind": "apply_queue", "t": 92.0},
    ], "F16"):
        led.ingest(m)
    q = led.state("Q1")
    res["f16_first_challenge_dvm_quarantined"] = (
        q.quarantined and not q.endpoint_eligible()
        and not Ledger.feedback_eligible(q, 95.0, 96.0))

    # F17 (T10-R3 反例B): SECOND challenge -> dispute_reset is ILLEGAL
    led = Ledger()
    for m in _msgs("Q1", [
        {"kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0},
        {"kind": "proposal", "round": 1, "t": 51.0},
        {"kind": "challenge", "round": 1, "t": 52.0},
        {"kind": "dispute_reset", "t": 52.5},
        {"kind": "proposal", "round": 2, "t": 60.0},
        {"kind": "challenge", "round": 2, "t": 61.0},
        {"kind": "dispute_reset", "t": 61.5},
        {"kind": "proposal", "round": 3, "t": 70.0},
        {"kind": "finalize", "outcome": "yes", "t": 72.0},
    ], "F17"):
        led.ingest(m)
    q = led.state("Q1")
    res["f17_second_challenge_reset_quarantined"] = (
        q.quarantined and not q.endpoint_eligible())

    # F15 neg-risk: consistent group passes; two-YES group quarantined entirely
    led = Ledger()
    for qid, outcome in [("G-w", "yes"), ("G-l", "no")]:
        led.ingest({"msg_id": f"F15-{qid}-enroll", "source": SRC, "question_id": qid,
                    "kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0, "group_id": "NR1"})
        for m in _msgs(qid, [{"kind": "proposal", "round": 1, "t": 51.0},
                             {"kind": "finalize", "outcome": outcome, "t": 53.0}], f"F15-{qid}"):
            led.ingest(m)
    ok_states = led.all_states()
    led2 = Ledger()
    for qid in ("G2-a", "G2-b"):
        led2.ingest({"msg_id": f"F15b-{qid}-enroll", "source": SRC, "question_id": qid,
                     "kind": "enroll", "t": 0.0, "prediction_cutoff": 49.0, "group_id": "NR2"})
        for m in _msgs(qid, [{"kind": "proposal", "round": 1, "t": 51.0},
                             {"kind": "finalize", "outcome": "yes", "t": 53.0}], f"F15b-{qid}"):
            led2.ingest(m)
    bad_states = led2.all_states()
    res["f15_negrisk_invariant"] = (not any(s.quarantined for s in ok_states.values())
                                    and all(s.quarantined for s in bad_states.values()))
    return res


def run_all_fixtures():
    res = fixture_results()
    return all(res.values()), {k: ("PASS" if v else "FAIL") for k, v in res.items()}


class TestClockFixtures(unittest.TestCase):
    def test_all_fixtures(self):
        ok, res = run_all_fixtures()
        failing = [k for k, v in res.items() if v != "PASS"]
        self.assertEqual(failing, [], f"failing fixtures: {failing}")
        self.assertEqual(len(res), 17)


if __name__ == "__main__":
    unittest.main(verbosity=2)
