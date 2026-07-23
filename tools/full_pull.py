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
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p1v5.collector import DATA, PAGE_LIMIT, _archive, _get, two_clock_view  # noqa: E402

ELIGIBILITY_LINE = "2026-04-24"      # deepseek-v4-flash release date (conservative cutoff)


def fetch_all(path: str, base_params: dict, kind: str, max_pages: int = 22) -> tuple:
    """Offset pagination with cap detection. Returns (records, hit_cap)."""
    out = []
    for page in range(max_pages):
        params = dict(base_params, limit=PAGE_LIMIT, offset=page * PAGE_LIMIT)
        try:
            url, raw = _get(path, params)
        except Exception as exc:
            print(f"    page {page} error ({exc}); treating as cap", flush=True)
            return out, True
        _archive(kind, url, raw)
        try:
            batch = json.loads(raw)
        except json.JSONDecodeError:
            print(f"    page {page} bad JSON; treating as cap", flush=True)
            return out, True
        if isinstance(batch, dict):
            batch = batch.get("data", [])
        out.extend(batch)
        if len(batch) < PAGE_LIMIT:
            return out, False
    return out, True


def fetch_keyset(path: str, base_params: dict, kind: str, max_pages: int = 4000,
                 run_id: str = "") -> tuple:
    """R11-1: official contract — next page via AFTER_CURSOR, urlencoded like any
    opaque query value. Page ledger records cursor/response SHAs and id ranges;
    no-progress (repeat page SHA OR non-advancing ids OR non-advancing cursor)
    fails closed.

    r13 P0-13-1 fail-closed set: the endpoint's OWN key must be present (a
    /markets response carrying only 'events' is a contract violation, not data);
    every row must have an id; ids must be unique within AND across pages; an
    empty page that still advertises next_cursor contradicts the documented
    'next_cursor omitted on the final page' contract. All four => INCOMPLETE.
    Returns (records, complete)."""
    out, after, seen_pages, prev_cursor_sha = [], None, set(), None
    seen_ids_global = set()
    expected_key = "markets" if path.startswith("/markets") else "events"
    ledger_path = DATA / "keyset_page_ledger.jsonl"
    for page in range(max_pages):
        params = dict(base_params, limit=PAGE_LIMIT)
        if after:
            params["after_cursor"] = after          # official param name, urlencoded by _get
        try:
            url, raw = _get(f"{path}/keyset", params)
            sha = hashlib.sha256(raw).hexdigest()
            doc = json.loads(raw)
            # R12/r13: response SCHEMA must contain THIS endpoint's list key;
            # an error body or a wrong-endpoint key is INCOMPLETE, never a stop
            if not isinstance(doc, dict) or expected_key not in doc:
                print(f"    keyset page {page}: expected key '{expected_key}' absent "
                      f"({list(doc)[:3] if isinstance(doc, dict) else type(doc).__name__}); INCOMPLETE", flush=True)
                return out, False
            batch = doc.get(expected_key) or []
            nxt = doc.get("next_cursor")
            raw_ids = [m.get("id") for m in batch]
            if any(i is None for i in raw_ids):
                print(f"    keyset page {page}: {sum(1 for i in raw_ids if i is None)} rows "
                      f"missing id; INCOMPLETE", flush=True)
                return out, False
            ids = [str(i) for i in raw_ids]
            if len(ids) != len(set(ids)):
                print(f"    keyset page {page}: duplicate ids WITHIN page; INCOMPLETE", flush=True)
                return out, False
        except Exception as exc:
            print(f"    keyset page {page} error ({exc}); INCOMPLETE", flush=True)
            return out, False
        try:
            with open(ledger_path, "a") as lf:
                # P1-13-3: rows carry run identity + full request context so a
                # batch can be traced back to its exact pages across runs
                lf.write(json.dumps({
                    "run_id": run_id, "page": page, "kind": kind, "url": url,
                    "params": {k: v for k, v in base_params.items()},
                    "incoming_cursor_sha": hashlib.sha256((after or "").encode()).hexdigest()[:16],
                    "next_cursor_sha": hashlib.sha256((nxt or "").encode()).hexdigest()[:16],
                    "response_sha": sha, "n": len(ids),
                    "first_id": ids[0] if ids else None, "last_id": ids[-1] if ids else None,
                }) + "\n")
        except Exception as exc:
            # R12-2 contract: a ledger that cannot be written = an unauditable
            # page = INCOMPLETE channel, never a crash and never a silent skip
            print(f"    keyset page {page}: ledger write failed ({exc}); INCOMPLETE", flush=True)
            return out, False
        if sha in seen_pages:
            print(f"    keyset page {page}: repeat response, INCOMPLETE", flush=True)
            return out, False
        seen_pages.add(sha)
        dup = seen_ids_global & set(ids)
        if dup:      # R12: cross-page duplicate ids = no real progress
            print(f"    keyset page {page}: {len(dup)} duplicate ids across pages, INCOMPLETE", flush=True)
            return out, False
        seen_ids_global.update(ids)
        cur_cursor_sha = hashlib.sha256((nxt or "").encode()).hexdigest()
        if nxt and cur_cursor_sha == prev_cursor_sha:
            print(f"    keyset page {page}: cursor not advancing, INCOMPLETE", flush=True)
            return out, False
        prev_cursor_sha = cur_cursor_sha
        # numeric-id monotonicity is ADVISORY only (cursor is opaque; no order
        # guarantee in the contract) — the binding guards are page-sha repeat,
        # cursor non-advance and cross-page duplicate ids above
        try:
            _archive(kind, url, raw)
        except Exception as exc:
            print(f"    keyset page {page}: archive write failed ({exc}); INCOMPLETE", flush=True)
            return out, False
        out.extend(batch)
        if page % 100 == 0:
            print(f"    keyset page {page}: cum {len(out)}", flush=True)
        if not batch:
            if nxt:      # r13: empty page + continuation cursor contradicts the contract
                print(f"    keyset page {page}: EMPTY page but next_cursor present; INCOMPLETE", flush=True)
                return out, False
            return out, True
        if not nxt:      # documented: next_cursor omitted on the final page
            return out, True
        after = nxt
    print("    keyset max_pages exhausted: INCOMPLETE", flush=True)
    return out, False


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

    # shadow r2 P0 fix: day-window implementation RESTORED as the primary channel
    # (it produced the good 171,505-market dataset); keyset is opt-in experimental
    # (--keyset) until its cursor semantics are actually solved.
    import sys as _s
    use_keyset = "--keyset" in _s.argv
    truncated = []
    markets, seen_ids = [], set()
    if use_keyset:
        markets, complete = fetch_keyset("/markets", {"closed": "true",
                                                      "end_date_min": ELIGIBILITY_LINE},
                                         "gamma_markets", run_id=stamp)
        if not complete:
            truncated.append("closed-keyset-incomplete")
        seen_ids = {str(m.get("id")) for m in markets}
    else:
        for lo, hi in week_windows(ELIGIBILITY_LINE, today):
            batch, cap = fetch_all("/markets", {"closed": "true", "end_date_min": lo,
                                                "end_date_max": hi}, "gamma_markets")
            if cap:
                print(f"  CAP HIT {lo}..{hi}: splitting into day windows", flush=True)
                batch = []
                for dlo, dhi in day_windows(lo, hi):
                    db, dcap = fetch_all("/markets", {"closed": "true",
                                                      "end_date_min": dlo,
                                                      "end_date_max": dhi}, "gamma_markets")
                    batch.extend(db)
                    if dcap:
                        truncated.append(f"{dlo}..{dhi}")
            fresh = [m for m in batch if str(m.get("id")) not in seen_ids]
            seen_ids.update(str(m.get("id")) for m in fresh)
            markets.extend(fresh)
            print(f"closed window {lo}..{hi}: +{len(fresh)} (cum {len(markets)})", flush=True)
    active, acap = fetch_all("/markets", {"closed": "false", "order": "volume24hr",
                                          "ascending": "false"}, "gamma_markets")
    if acap:
        truncated.append("active-channel-capped")
    fresh_active = [m for m in active if str(m.get("id")) not in seen_ids]
    print(f"active: +{len(fresh_active)}", flush=True)
    # shadow r2 P0: refuse to WRITE a ghost dataset silently
    overrides = []
    if len(markets) < 10000:
        print(f"SANITY REFUSAL: only {len(markets)} closed markets collected "
              f"(expected >=10k in-window); NOT writing views. Set P1V5_ALLOW_SMALL_PULL=1 to override.", flush=True)
        import os as _o
        if not _o.environ.get("P1V5_ALLOW_SMALL_PULL"):
            raise SystemExit(3)
        # r13 P0-13-2: an override is a completeness concession — it must be
        # RECORDED and it machine-forces the batch down to dev_lower_bound
        overrides.append("small_pull_override")

    events = []
    try:
        eb, ecomplete = fetch_keyset("/events", {"closed": "true",
                                                 "end_date_min": ELIGIBILITY_LINE},
                                     "gamma_events_closed", run_id=stamp)
        events.extend(eb)
        if not ecomplete:
            truncated.append("events-closed-keyset-incomplete")
        eb, ecomplete = fetch_keyset("/events", {"closed": "false"},
                                     "gamma_events_active", run_id=stamp)
        events.extend(eb)
        if not ecomplete:
            truncated.append("events-active-keyset-incomplete")
        print(f"events: {len(events)}", flush=True)
    except Exception as exc:
        truncated.append(f"events-channel-exception:{type(exc).__name__}")
        print(f"events channel failed ({exc}); recorded as INCOMPLETE", flush=True)

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

    # closed-events per ISO week (trading-close clock; SETTLEMENT yield is computed
    # downstream from resolved-only registry, never from this summary)
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
        "closed_events_per_week_NOT_settled": {k: len(v) for k, v in sorted(week_events.items())},
        "n_events_indexed": len(ev_index),
        "possibly_truncated_windows": truncated,
        "top_tags": tag_hist.most_common(30),
        "stamp": stamp,
    }
    (out_dir / f"full_{stamp}_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    # R11-2: content-addressed batch manifest — the ONLY legitimate handle downstream
    def _sha(p):
        return hashlib.sha256(open(p, "rb").read()).hexdigest()
    # r13 P0-13-2: allowed_use is MACHINE-DERIVED from completeness + overrides;
    # consumers re-derive and refuse any manifest where the label disagrees
    all_complete = not truncated and not overrides
    ledger_p = DATA / "keyset_page_ledger.jsonl"
    bm = {"batch_id": f"batch_{stamp}",
          "eligibility_line": ELIGIBILITY_LINE,
          "files": {f"full_{stamp}_markets.jsonl": _sha(out_dir / f"full_{stamp}_markets.jsonl"),
                    f"full_{stamp}_events.jsonl": _sha(out_dir / f"full_{stamp}_events.jsonl"),
                    f"full_{stamp}_summary.json": _sha(out_dir / f"full_{stamp}_summary.json"),
                    f"full_{stamp}_tags.json": _sha(out_dir / f"full_{stamp}_tags.json")},
          # P1-13-3: page ledger + collection log bound by sha (DATA-root artifacts)
          "aux": {"keyset_page_ledger_sha256": _sha(ledger_p) if ledger_p.exists() else None,
                  "collection_log_sha256": _sha(DATA / "collection_log.jsonl")
                                           if (DATA / "collection_log.jsonl").exists() else None},
          "channel_complete": {"incomplete_reasons": truncated, "overrides": overrides},
          "allowed_use": "g5a_candidate" if all_complete else "dev_lower_bound"}
    (out_dir / f"batch_manifest_{stamp}.json").write_text(json.dumps(bm, indent=2, ensure_ascii=False))
    print(f"batch manifest: allowed_use={bm['allowed_use']}", flush=True)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


if __name__ == "__main__":
    main()
