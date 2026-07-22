"""Micro-pilot runner: full pipeline over REAL collected markets.

Modes:
  dry  (default) — StubBackend, zero cost, end-to-end plumbing + cost model shape
  live           — OpenRouterBackend (needs OPENROUTER_API_KEY); tiny N, hard cap

Produces build/micro_pilot_<mode>.json with per-arm scores, receipts totals and
a G7a-shaped cost block. DEV TIER: retrospective replay of already-resolved
markets — never confirmatory, feeds G4/G7a design only."""

import datetime
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p1v5.checks import CANONICAL_ARMS  # noqa: E402
from p1v5.deliberation import (OpenRouterBackend, StubBackend, TeamDeliberation,  # noqa: E402
                               credit_c3_action_t, credit_c3_sham_t,
                               credit_diff_agent_t, credit_shared_surplus_t,
                               update_memory_from_credits)
from p1v5.policy import MemoryState  # noqa: E402
from p1v5.scoring import score_stream  # noqa: E402

PRICE_IN_PER_MTOK = {"stub-1": 0.0, "deepseek/deepseek-v4-flash": 0.09}
PRICE_OUT_PER_MTOK = {"stub-1": 0.0, "deepseek/deepseek-v4-flash": 0.18}
CHARS_PER_TOKEN = 2.43   # calibrated from first live dry-run: 405,078 chars / 166,919 billed tokens
HARD_CAP_USD = 5.0


def load_questions(n: int) -> list:
    views = sorted((ROOT / "data/views").glob("two_clock_view_*.jsonl"))
    if not views:
        raise SystemExit("no collected data; run collector first")
    qs, seen_events = [], set()
    rows = [json.loads(l) for l in views[-1].read_text().splitlines()]
    rows.sort(key=lambda v: v.get("closed_time") or 0)   # R11-9: real forecast-clock order
    for v in rows:
        if (v["uma_status"] == "resolved" and v["outcome_gamma_coarse"] in ("yes", "no")
                and not v["neg_risk"] and v["question"]):
            evs = set(v["event_ids"] or [v["market_id"]])
            if evs & seen_events:      # shadow r1 P0-2: one market per event, no siblings
                continue
            seen_events.update(evs)
            qs.append({"question_id": v["market_id"], "question": v["question"],
                       "closed_time": v.get("closed_time"),
                       "y": 1 if v["outcome_gamma_coarse"] == "yes" else 0})
        if len(qs) >= n:
            break
    return qs


def run_pilot(mode: str = "dry", n_questions: int = 6, n_agents: int = 3) -> dict:
    if mode == "dry":
        backend, model = StubBackend(), "stub-1"
    else:
        model = "deepseek/deepseek-v4-flash"
        backend = OpenRouterBackend(model)
    questions = load_questions(n_questions)
    slices = [f"private evidence slice {i} (dev tier: question text only)"
              for i in range(n_agents)]
    report = {"mode": mode, "model": model, "n_questions": len(questions),
              "epistemic_status": "DEV_NONCAUSAL",   # R11-9: retrospective, never effect evidence
              "arms": {}, "receipt_chars_total": 0, "transcript_bundles": {}}
    tdir = ROOT / "data/transcripts" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    tdir.mkdir(parents=True, exist_ok=True)
    for arm in CANONICAL_ARMS:
        team = TeamDeliberation(backend, n_agents)
        memory = MemoryState()
        forecasts, chars = {}, 0
        chars_in = chars_out = 0
        for k, q in enumerate(questions):
            t = team.run(q, slices, memory, seed=1000 + k)
            forecasts[q["question_id"]] = t.final_q
            bundle = t.to_bundle(meta={"arm": arm, "k": k, "mode": mode,
                                       "closed_time": q.get("closed_time"),
                                       "epistemic_status": "DEV_NONCAUSAL"})
            bpath = tdir / f"{arm}_{q['question_id']}.json"
            bpath.write_text(json.dumps(bundle, ensure_ascii=False, sort_keys=True))
            report["transcript_bundles"][f"{arm}/{q['question_id']}"] = t.sha()
            y = q["y"]
            batch = f"{arm}-b{k}"
            if arm == "no_update":
                credits = {}
            elif arm == "shared_surplus":
                credits = credit_shared_surplus_t(t, y)
            elif arm == "diff_agent_credit":
                credits = credit_diff_agent_t(t, y)
            elif arm == "c3_action":
                credits = credit_c3_action_t(team, q, slices, memory, t, y, seed=2000 + k)
            else:
                credits = credit_c3_sham_t(team, q, slices, memory, t, y,
                                           seed=2000 + k, batch_id=batch)
            memory = update_memory_from_credits(
                memory, credits, feedback_clock=float(k), batch_id=batch,
                # shadow r1 P0-2: memory text encodes CREDIT signal only, never
                # the settlement outcome literal (leak path to sibling markets)
                texts={a: f"on '{q['question'][:60]}': {a} was "
                          f"{'credited' if credits.get(a, 0) > 0 else 'not credited'} "
                          f"for its contribution"
                       for a in credits})
            chars += sum(r.prompt_chars + r.output_chars for r in t.receipts)
            chars_in += sum(r.prompt_chars for r in t.receipts)
            chars_out += sum(r.output_chars for r in t.receipts)
            report["billed_prompt_tokens"] = report.get("billed_prompt_tokens", 0) + sum(
                r.prompt_tokens for r in t.receipts)
            report["billed_completion_tokens"] = report.get("billed_completion_tokens", 0) + sum(
                r.completion_tokens for r in t.receipts)
            if mode == "live":       # shadow r1 F7: cap checked per QUESTION, not per arm
                spent = (report.get("billed_prompt_tokens", 0) / 1e6 * PRICE_IN_PER_MTOK[model]
                         + report.get("billed_completion_tokens", 0) / 1e6 * PRICE_OUT_PER_MTOK[model])
                if spent > HARD_CAP_USD:
                    raise SystemExit(f"hard cap ${HARD_CAP_USD} hit mid-run (${spent:.2f}); aborting")
        outcomes = {q["question_id"]: q["y"] for q in questions}
        s = score_stream(forecasts, outcomes, [q["question_id"] for q in questions])
        # shadow r1 F7: split in/out prices (average-price estimator biased)
        est_cost = ((chars_in / CHARS_PER_TOKEN) / 1e6 * PRICE_IN_PER_MTOK[model]
                    + (chars_out / CHARS_PER_TOKEN) / 1e6 * PRICE_OUT_PER_MTOK[model])
        report["arms"][arm] = {"mean_brier": round(s["mean_brier"], 4),
                               "failure_rate": s["failure_rate"],
                               "chars": chars, "est_cost_usd": round(est_cost, 4)}
        report["receipt_chars_total"] += chars
        # per-arm checkpoint: a timeout kill never loses completed arms
        ckpt = ROOT / "build" / f"micro_pilot_{mode}_partial.json"
        ckpt.parent.mkdir(exist_ok=True)
        ckpt.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        if mode == "live" and sum(a["est_cost_usd"] for a in report["arms"].values()) > HARD_CAP_USD:
            raise SystemExit("hard cap reached; aborting live pilot")
    report["est_total_cost_usd"] = round(sum(a["est_cost_usd"] for a in report["arms"].values()), 4)
    report["billed_cost_usd"] = round(
        report.get("billed_prompt_tokens", 0) / 1e6 * PRICE_IN_PER_MTOK[model]
        + report.get("billed_completion_tokens", 0) / 1e6 * PRICE_OUT_PER_MTOK[model], 4)
    report["produced_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    out = ROOT / "build" / f"micro_pilot_{mode}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    return report


if __name__ == "__main__":
    mode = "live" if "--live" in sys.argv else "dry"
    print(json.dumps(run_pilot(mode), indent=2, ensure_ascii=False))
