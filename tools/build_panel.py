"""Panel v2 builder: join registry + LLM topic labels, keep only paper-eligible
topics (macro_indicators/monetary_policy/geopolitics/elections_politics/
financial_markets), assemble the recurring-series panel across three cadence
tiers, and emit the G5a-shaped yield summary.

Eligibility = LLM label in ELIGIBLE (tag whitelist is advisory only now, since
event-channel tags were largely empty). AI/tech rankings land in tech_business
and are excluded (user directive)."""

import datetime
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VIEWS = ROOT / "data/views"
ELIGIBLE = {"macro_indicators", "monetary_policy", "geopolitics",
            "elections_politics", "financial_markets"}


def main() -> dict:
    reg = {json.loads(l)["event_id"]: json.loads(l)
           for l in open(sorted(VIEWS.glob("event_registry_*.jsonl"))[-1])}
    # LLM labels: prefer finished topics file, else live checkpoint
    topics = {}
    tfiles = sorted(VIEWS.glob("llm_topics_2*.jsonl"))
    if tfiles:
        for l in open(tfiles[-1]):
            o = json.loads(l)
            topics[o["event_id"]] = o["topic_llm"]
    ckpt = VIEWS / "llm_topics_checkpoint.jsonl"
    if ckpt.exists():
        for l in open(ckpt):
            o = json.loads(l)
            topics.setdefault(o["event_id"], o["c"])

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    eligible_events = []
    for eid, r in reg.items():
        cat = topics.get(eid)
        if cat in ELIGIBLE and r["n_settled"] > 0:
            r = dict(r, topic_llm=cat)
            eligible_events.append(r)

    # recurring series over LLM-eligible events
    series = defaultdict(list)
    for r in eligible_events:
        series[r["series_key"]].append(r)
    panel = []
    for key, evs in series.items():
        if len(evs) < 3 or not key:
            continue
        closes = sorted(e["last_close"] for e in evs if e["last_close"])
        gaps = [(b - a) / 86400 for a, b in zip(closes, closes[1:])]
        med_gap = sorted(gaps)[len(gaps) // 2] if gaps else None
        if med_gap is None or med_gap < 5.0:
            continue
        cadence = ("weekly" if med_gap <= 10 else "monthly" if med_gap <= 45 else "rolling")
        panel.append({
            "series_key": key, "example_title": evs[-1]["title"],
            "n_instances": len(evs), "median_gap_days": round(med_gap, 1),
            "cadence_tier": cadence,
            "topic": Counter(e["topic_llm"] for e in evs).most_common(1)[0][0],
            "structure": Counter(e["structure"] for e in evs).most_common(1)[0][0],
            "total_markets": sum(e["n_markets"] for e in evs),
        })
    panel.sort(key=lambda p: -p["n_instances"])

    # yield per ISO week over eligible events (G5a raw)
    per_week = defaultdict(int)
    for r in eligible_events:
        if r["last_close"]:
            wk = datetime.date.fromtimestamp(r["last_close"]).isocalendar()
            per_week[f"{wk[0]}-W{wk[1]:02d}"] += 1
    recent = dict(sorted(per_week.items())[-12:])
    weekly_vals = [v for k, v in sorted(per_week.items()) if k >= "2026-W17"]
    summary = {
        "n_eligible_settled_events": len(eligible_events),
        "topic_hist": dict(Counter(r["topic_llm"] for r in eligible_events)),
        "structure_hist": dict(Counter(r["structure"] for r in eligible_events)),
        "n_panel_series": len(panel),
        "panel_by_cadence": dict(Counter(p["cadence_tier"] for p in panel)),
        "yield_recent_weeks": recent,
        "median_eligible_events_per_week_since_W17":
            (sorted(weekly_vals)[len(weekly_vals) // 2] if weekly_vals else None),
        "labels_used": len(topics),
        "stamp": stamp,
    }
    (VIEWS / f"panel_v2_{stamp}.json").write_text(
        json.dumps({"summary": summary, "panel": panel}, indent=2, ensure_ascii=False))
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print("\n=== 面板 v2 序列(按节奏分层,前 24)===")
    for tier in ("weekly", "monthly", "rolling"):
        ts = [p for p in panel if p["cadence_tier"] == tier][:8]
        if ts:
            print(f"\n[{tier}]")
            for p in ts:
                print(f"  {p['n_instances']:>2}期/{p['median_gap_days']:>4}天 "
                      f"{p['topic'][:16]:16s} {p['structure'][:12]:12s} {p['example_title'][:46]}")
    return summary


if __name__ == "__main__":
    main()
