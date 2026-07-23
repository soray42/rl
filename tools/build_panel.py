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
    import os as _os
    reg_path = _os.environ.get("P1V5_REGISTRY")
    top_path = _os.environ.get("P1V5_TOPICS")
    if not reg_path or not top_path:
        raise SystemExit("R12: set P1V5_REGISTRY and P1V5_TOPICS explicitly; implicit latest is forbidden")
    reg_lines = [json.loads(l) for l in open(reg_path)]
    # shadow r3 (P0-12-3 core): a registry without a _lineage header has lost its
    # batch provenance and can feed nothing downstream — fail closed
    if not reg_lines or "_lineage" not in reg_lines[0]:
        raise SystemExit("shadow-r3: registry lacks the _lineage header (batch_manifest_sha256/"
                         "allowed_use); rebuild it with tools/event_registry.py — lineage-less "
                         "registries are forbidden downstream")
    lin = reg_lines[0]["_lineage"]
    import hashlib as _hh
    lineage = {"batch_manifest_sha256": lin["batch_manifest_sha256"],
               "batch_allowed_use": lin["allowed_use"],
               "registry_sha256": _hh.sha256(open(reg_path, "rb").read()).hexdigest(),
               "topics_sha256": _hh.sha256(open(top_path, "rb").read()).hexdigest()}
    reg = {r["event_id"]: r for r in reg_lines[1:]}
    # LLM labels: prefer finished topics file, else live checkpoint
    # r13 P0-13-3: a topics _lineage header must LINK to this registry; a
    # label file generated from a different registry is refused, not joined
    topics = {}
    for l in open(top_path):
        o = json.loads(l)
        if "_lineage" in o:
            t_reg_sha = o["_lineage"].get("registry_sha256")
            if t_reg_sha != lineage["registry_sha256"]:
                raise SystemExit(f"R13-3: topics lineage registry_sha256 {t_reg_sha!r} != "
                                 f"the registry actually being joined "
                                 f"({lineage['registry_sha256']}); refusing cross-batch join")
            continue
        topics[o["event_id"]] = o.get("topic_llm") or o.get("c")

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    eligible_events = []
    for eid, r in reg.items():
        cat = topics.get(eid)
        # shadow r3: eligibility needs a BINARY settled endpoint (n_settled also
        # counts unknown_50_50, which the primary Brier endpoint cannot consume)
        if cat in ELIGIBLE and r["n_settled_binary"] > 0:
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

    # r13 P0-13-7: settlement yield uses the UMA RESOLUTION clock, never the
    # trading-close clock; events lacking the settlement clock are COUNTED out
    # loud, not silently folded in (the r12 contract already banned calling a
    # close-clock histogram "yield")
    per_week = defaultdict(int)
    no_settlement_clock = 0
    for r in eligible_events:
        ts = r.get("last_uma_end_binary")
        if ts:
            wk = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).date().isocalendar()
            per_week[f"{wk[0]}-W{wk[1]:02d}"] += 1
        else:
            no_settlement_clock += 1
    recent = dict(sorted(per_week.items())[-12:])
    weekly_vals = [v for k, v in sorted(per_week.items()) if k >= "2026-W17"]
    summary = {
        "n_eligible_settled_events": len(eligible_events),
        "topic_hist": dict(Counter(r["topic_llm"] for r in eligible_events)),
        "structure_hist": dict(Counter(r["structure"] for r in eligible_events)),
        "n_panel_series": len(panel),
        "panel_by_cadence": dict(Counter(p["cadence_tier"] for p in panel)),
        "settlement_yield_recent_weeks_uma_end_clock": recent,
        "median_eligible_settlements_per_week_since_W17":
            (sorted(weekly_vals)[len(weekly_vals) // 2] if weekly_vals else None),
        "n_events_missing_settlement_clock_excluded_from_yield": no_settlement_clock,
        "labels_used": len(topics),
        "lineage": lineage,
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
