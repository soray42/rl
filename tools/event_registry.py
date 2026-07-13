"""Event registry builder: clean + structurally classify the full pull.

Per event: structure class (standalone / categorical / threshold_ladder /
deadline_hazard / mixed), topic class (tag whitelist/blacklist), recurring-series
key (title with dates/numbers normalized), settlement cadence.

Outputs data/views/event_registry_<stamp>.jsonl + panel-candidate summary
(recurring series with >=MIN_REPEATS settled instances). This file is the raw
material for the enrollment rulebook (G5a) — classification rules are code,
hence auditable and frozen with the repo.
"""

import datetime
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TOPIC_WHITELIST = {"politics", "finance", "elections", "equities", "economy", "fed",
                   "geopolitics", "world", "macro-indicators", "macro-graph",
                   "macro-single", "rates", "commodities", "inflation",
                   "us-presidential-election", "midterms", "trade-war", "china",
                   "ukraine", "middle-east", "war", "federal-government", "court",
                   "immigration", "ai", "business", "crypto-prices"}
TOPIC_BLACKLIST = {"sports", "games", "esports", "soccer", "tennis", "cricket",
                   "baseball", "basketball", "nba", "nfl", "mlb", "hockey", "mma",
                   "golf", "f1", "pop-culture", "celebrities", "music", "movies",
                   "video-games"}

THRESHOLD_PAT = re.compile(
    r"(above|below|over|under|between|reach|hit|exceed|at least|\bo/u\b|"
    r"settle at|close at|top \$|\$[\d,.]+[bmk]?|[\d,.]+%|\d+ bps)", re.I)
DEADLINE_PAT = re.compile(r"\b(by|before|until|within)\b.{0,30}"
                          r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|"
                          r"\d{4}|\d+ (day|week|month)s?)", re.I)
CATEGORICAL_TITLE_PAT = re.compile(r"^(who|which|next|winner|what will .* (be|say))|"
                                   r"(winner|nominee|leader|chair|president|pick)\??$", re.I)
SERIES_STRIP = re.compile(
    r"(\b(january|february|march|april|may|june|july|august|september|october|"
    r"november|december|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec)\b|"
    r"\bq[1-4]\b|\b20\d\d\b|\bweek \d+\b|\b\d+(st|nd|rd|th)?\b|[\d,.$%]+)", re.I)

MIN_REPEATS = 3


def series_key(title: str) -> str:
    s = SERIES_STRIP.sub("#", title or "")
    s = re.sub(r"[^a-z]+", " ", s.lower())
    return " ".join(s.split())[:80]


def classify_structure(ev, mkts):
    n = len(mkts)
    qs = [m.get("question") or "" for m in mkts]
    if n == 1:
        return "standalone"
    if ev.get("neg_risk") or CATEGORICAL_TITLE_PAT.search(ev.get("title") or ""):
        return "categorical"
    thr = sum(1 for q in qs if THRESHOLD_PAT.search(q))
    ddl = sum(1 for q in qs if DEADLINE_PAT.search(q))
    if thr >= max(2, n // 2) and ddl < n // 2:
        return "threshold_ladder"
    if ddl >= max(2, n // 2):
        return "deadline_hazard"
    return "mixed"


def topic_class(tags):
    t = set(tags or [])
    if t & TOPIC_BLACKLIST:
        return "excluded"
    if t & TOPIC_WHITELIST:
        return "eligible"
    return "unclassified"


def main() -> dict:
    views = ROOT / "data/views"
    mfile = sorted(views.glob("full_*_markets.jsonl"))[-1]
    efile = sorted(views.glob("full_*_events.jsonl"))[-1]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")

    ev_meta = {}
    for line in open(efile):
        e = json.loads(line)
        ev_meta[e["event_id"]] = e
    ev_markets = defaultdict(list)
    for line in open(mfile):
        v = json.loads(line)
        for eid in v["event_ids"] or []:
            ev_markets[eid].append(v)

    rows, series_map = [], defaultdict(list)
    for eid, mkts in ev_markets.items():
        meta = ev_meta.get(eid, {})
        title = meta.get("title") or (mkts[0].get("question") or "")
        settled = [m for m in mkts if m.get("closed_time")]
        row = {
            "event_id": eid,
            "title": title,
            "n_markets": len(mkts),
            "n_settled": len(settled),
            "structure": classify_structure(
                {"neg_risk": meta.get("neg_risk"), "title": title}, mkts),
            "topic": topic_class(meta.get("tags")),
            "tags": meta.get("tags") or [],
            "series_key": series_key(title),
            "last_close": max((m["closed_time"] for m in settled), default=None),
            "volume": meta.get("volume"),
        }
        rows.append(row)
        if row["topic"] == "eligible" and row["n_settled"] > 0:
            series_map[row["series_key"]].append(row)

    out = views / f"event_registry_{stamp}.jsonl"
    with open(out, "w") as f:
        for r in sorted(rows, key=lambda r: r["event_id"]):
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # recurring-series panel candidates: same normalized title, >=MIN_REPEATS settled
    panel = []
    for key, evs in series_map.items():
        if len(evs) >= MIN_REPEATS and key:
            closes = sorted(e["last_close"] for e in evs if e["last_close"])
            gaps = [(b - a) / 86400 for a, b in zip(closes, closes[1:])]
            med_gap = sorted(gaps)[len(gaps) // 2] if gaps else None
            # TRUE temporal recurrence needs spacing; same-day clusters are
            # cross-sectional families (calendar-shock material), not series
            if med_gap is None or med_gap < 5.0:
                continue
            panel.append({
                "series_key": key,
                "example_title": evs[-1]["title"],
                "n_instances": len(evs),
                "structures": dict(Counter(e["structure"] for e in evs)),
                "median_gap_days": (sorted(gaps)[len(gaps) // 2] if gaps else None),
                "total_markets": sum(e["n_markets"] for e in evs),
            })
    panel.sort(key=lambda p: -p["n_instances"])
    summary = {
        "n_events": len(rows),
        "structure_hist": dict(Counter(r["structure"] for r in rows)),
        "topic_hist": dict(Counter(r["topic"] for r in rows)),
        "eligible_structure_hist": dict(Counter(
            r["structure"] for r in rows if r["topic"] == "eligible")),
        "n_recurring_series_eligible": len(panel),
        "panel_top30": panel[:30],
        "registry_path": str(out.relative_to(ROOT)),
        "source_markets": mfile.name, "source_events": efile.name,
    }
    (views / f"event_registry_{stamp}_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


if __name__ == "__main__":
    s = main()
    print(json.dumps({k: v for k, v in s.items() if k != "panel_top30"},
                     indent=2, ensure_ascii=False))
    print("\n=== 重复序列面板候选(前 20)===")
    for p in s["panel_top30"][:20]:
        print(f"  [{p['n_instances']:>2}期 | 每{p['median_gap_days'] or '?'}天 | "
              f"{p['total_markets']:>3}盘 | {max(p['structures'], key=p['structures'].get)}] "
              f"{p['example_title'][:58]}")
