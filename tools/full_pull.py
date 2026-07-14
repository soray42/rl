"""Full post-release pull (channel A+B): every market settled on/after the
model-release eligibility line, plus tags and events, weekly-windowed to stay
under the offset wall. Collection layer takes EVERYTHING (no topic pruning);
enrollment rules prune later, auditable.

Outputs under data/views/full_<stamp>_*:
  markets.jsonl  extended two-clock view (+volume/liquidity fields as present)
  events.jsonl   event id -> title/tags/market count (if endpoint cooperates)
  tags.json      full tag table
Prints a yield summary: settled independent events per ISO week (G5a raw input).
"""

import datetime
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p1v5.collector import DATA, PAGE_LIMIT, _archive, _get, two_clock_view  # noqa: E402

ELIGIBILITY_LINE = "2026-04-24"      # deepseek-v4-flash release date (conservative cutoff)


def fetch_keyset(path: str, base_params: dict, kind: str, max_pages: int = 4000) -> tuple:
    """Cursor pagination via the API's own deep-pagination endpoint (the 422
    error body's recommendation; shadow r1 P0-1 follow-up: day windows ALSO
    capped, keyset is the only complete channel). Returns (records, complete)."""
    import hashlib as _h
    out, cursor, seen_pages = [], None, set()
    for page in range(max_pages):
        params = dict(base_params, limit=PAGE_LIMIT)
        try:
            # cursor appended RAW: urlencode round-trip broke server-side cursor
            # decoding (2026-07-14 loop incident: 4,150 pages, 22 unique)
            from p1v5.collector import GAMMA, USER_AGENT, _last_call, RATE_SECONDS
            import urllib.parse, urllib.request, time as _t
            wait = RATE_SECONDS - (_t.monotonic() - _last_call[0])
            if wait > 0:
                _t.sleep(wait)
            url = f"{GAMMA}{path}/keyset?{urllib.parse.urlencode(params)}"
            if cursor:
                url += f"&cursor={cursor}"
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
            _last_call[0] = _t.monotonic()
        except Exception as exc:
            print(f"    keyset page {page} error ({exc}); stopping INCOMPLETE", flush=True)
            return out, False
        sha = _h.sha256(raw).hexdigest()
        if sha in seen_pages:            # loop breaker: identical page => cursor dead
            print(f"    keyset page {page}: CURSOR LOOP detected, stopping INCOMPLETE", flush=True)
            return out, False
        seen_pages.add(sha)
        _archive(kind, url, raw)
        doc = json.loads(raw)
        batch = doc.get("markets") or doc.get("events") or doc.get("data") or []
        out.extend(batch)
        cursor = doc.get("next_cursor")
        if page % 100 == 0:
            print(f"    keyset page {page}: cum {len(out)}", flush=True)
        if not cursor or not batch:
            return out, True
    print("    keyset max_pages exhausted: INCOMPLETE", flush=True)
    return out, False


def fetch_all(path: str, base_params: dict, kind: str, max_pages: int = 22) -> tuple:
    """shadow-audit r1 P0-1 fix: returns (records, hit_cap). hit_cap=True means
    the LAST page was still full — the window may be truncated and the caller
    MUST split it or record it as known-incomplete. Never silent."""
    out = []
    for page in range(max_pages):
        params = dict(base_params, limit=PAGE_LIMIT, offset=page * PAGE_LIMIT)
        try:
            url, raw = _get(path, params)
        except Exception as exc:                 # offset wall (HTTP 422) or transient
            print(f"    page {page} error ({exc}); treating as cap", flush=True)
            return out, True
        _archive(kind, url, raw)
        batch = json.loads(raw)
        if isinstance(batch, dict):
            batch = batch.get("data", [])
        out.extend(batch)
        if len(batch) < PAGE_LIMIT:
            return out, False
    return out, True


def day_windows(lo: str, hi: str) -> list:
    s = datetime.date.fromisoformat(lo)
    e = datetime.date.fromisoformat(hi)
    out = []
    while s < e:
        nxt = s + datetime.timedelta(days=1)
        out.append((s.isoformat(), nxt.isoformat()))
        s = nxt
    return out


def week_windows(start: str, end: str) -> list:
    s = datetime.date.fromisoformat(start)
    e = datetime.date.fromisoformat(end)
    wins = []
    while s <= e:
        nxt = s + datetime.timedelta(days=7)
        wins.append((s.isoformat(), min(nxt, e + datetime.timedelta(days=1)).isoformat()))
        s = nxt
    return wins


def main() -> dict:
    today = datetime.date.today().isoformat()
    now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")

    tags, _tcap = fetch_all("/tags", {}, "gamma_tags", max_pages=10)
    print(f"tags: {len(tags)}", flush=True)

    truncated = []
    markets, complete = fetch_keyset("/markets", {"closed": "true",
                                                  "end_date_min": ELIGIBILITY_LINE},
                                     "gamma_markets")
    if not complete:
        truncated.append("closed-keyset-incomplete")
    seen_ids = {str(m.get("id")) for m in markets}
    print(f"closed keyset: {len(markets)} markets (complete={complete})", flush=True)
    active, acomplete = fetch_keyset("/markets", {"closed": "false"}, "gamma_markets")
    if not acomplete:
        truncated.append("active-keyset-incomplete")
    fresh_active = [m for m in active if str(m.get("id")) not in seen_ids]
    print(f"active keyset: +{len(fresh_active)} (complete={acomplete})", flush=True)

    events = []
    try:
        eb, ecomplete = fetch_keyset("/events", {"closed": "true",
                                                 "end_date_min": ELIGIBILITY_LINE},
                                     "gamma_events")
        events.extend(eb)
        if not ecomplete:
            truncated.append("events-closed-keyset-incomplete")
        eb, ecomplete = fetch_keyset("/events", {"closed": "false"}, "gamma_events")
        events.extend(eb)
        if not ecomplete:
            truncated.append("events-active-keyset-incomplete")
        print(f"events: {len(events)}", flush=True)
    except Exception as exc:
        print(f"events channel failed ({exc}); market-embedded event ids still available", flush=True)

    out_dir = DATA / "views"
    out_dir.mkdir(parents=True, exist_ok=True)
    vol_fields = ("volume", "volumeNum", "volume24hr", "volumeClob", "liquidity",
                  "liquidityNum", "liquidityClob")
    with open(out_dir / f"full_{stamp}_markets.jsonl", "w") as f:
        for m in markets + fresh_active:
            v = two_clock_view(m, now_ts)
            v["start_date"] = m.get("startDate")
            v["closed"] = m.get("closed")
            for k in vol_fields:
                if m.get(k) is not None:
                    v[k] = m[k]
            f.write(json.dumps(v, ensure_ascii=False) + "\n")
    ev_index = {}
    with open(out_dir / f"full_{stamp}_events.jsonl", "w") as f:
        for e in events:
            row = {"event_id": str(e.get("id")), "title": e.get("title"),
                   "slug": e.get("slug"), "closed": e.get("closed"),
                   "neg_risk": e.get("negRisk"),
                   "tags": [t.get("slug") for t in (e.get("tags") or [])],
                   "n_markets": len(e.get("markets") or []),
                   "volume": e.get("volume")}
            ev_index[row["event_id"]] = row
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    (out_dir / f"full_{stamp}_tags.json").write_text(json.dumps(tags, ensure_ascii=False))

    # yield summary: settled EVENTS per ISO week (independent-unit raw material)
    week_events = defaultdict(set)
    ladder = Counter()
    mkts_per_event = Counter()
    for m in markets:
        v = two_clock_view(m, now_ts)
        wk = None
        if v["closed_time"]:
            wk = datetime.date.fromtimestamp(v["closed_time"]).isocalendar()
            wk = f"{wk[0]}-W{wk[1]:02d}"
        for e in v["event_ids"] or ["?"]:
            mkts_per_event[e] += 1
            if wk:
                week_events[wk].add(e)
    for e, n in mkts_per_event.items():
        ladder["1"] += (n == 1)
        ladder["2-5"] += (2 <= n <= 5)
        ladder[">5"] += (n > 5)
    tag_hist = Counter(t for row in ev_index.values() for t in row["tags"])
    summary = {
        "eligibility_line": ELIGIBILITY_LINE,
        "n_closed_markets": len(markets),
        "n_active_markets": len(fresh_active),
        "n_unique_events_closed": len(mkts_per_event),
        "events_by_ladder_size": dict(ladder),
        "settled_events_per_week": {k: len(v) for k, v in sorted(week_events.items())},
        "n_events_indexed": len(ev_index),
        "possibly_truncated_windows": truncated,
        "top_tags": tag_hist.most_common(30),
        "stamp": stamp,
    }
    (out_dir / f"full_{stamp}_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


if __name__ == "__main__":
    main()
