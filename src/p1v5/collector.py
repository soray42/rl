"""Polymarket collector v1 (dev tier: Gamma API, read-only, rate-limited).

Rights posture (see phase_b2/05_rights/): individual academic API collection is
the contract-tolerated channel; collected market data is RESTRICT for public
redistribution — raw snapshots live under data/ (excluded from the input lock,
never released; releases carry ids + timestamps + refetch scripts only).

Provenance discipline: every HTTP response is archived byte-exact with
(url, retrieved_at UTC, sha256) appended to data/collection_log.jsonl.
Two-clock extraction is a VIEW over the archive, never a replacement for it.

Tier honesty: Gamma exposes coarse UMA fields (umaResolutionStatus, umaEndDate,
closedTime, one-level umaResolutionStatuses). Full proposal/dispute round
history needs onchain/UMA logs and belongs to the prospective collector (E4).
Events mapped from this tier are tagged provenance_tier="gamma_coarse" and are
DEV/PILOT data only — never confirmatory.
"""

import datetime
import hashlib
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
GAMMA = "https://gamma-api.polymarket.com"
RATE_SECONDS = 1.0          # polite: ~1 req/s, far under any documented limit
PAGE_LIMIT = 100            # documented maximum
OFFSET_WALL = 2000          # recon: deeper offsets 422; paginate by date windows instead
USER_AGENT = "p1v5-academic-collector/0.1 (individual academic research; contact: sora.yng42@gmail.com)"

_last_call = [0.0]


class CollectorError(Exception):
    pass


def _get(path: str, params: dict) -> tuple:
    wait = RATE_SECONDS - (time.monotonic() - _last_call[0])
    if wait > 0:
        time.sleep(wait)
    url = f"{GAMMA}{path}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
    _last_call[0] = time.monotonic()
    return url, raw


def _archive(kind: str, url: str, raw: bytes) -> Path:
    utc = datetime.datetime.now(datetime.timezone.utc)
    day_dir = DATA / "raw" / kind / utc.strftime("%Y-%m-%d")
    day_dir.mkdir(parents=True, exist_ok=True)
    sha = hashlib.sha256(raw).hexdigest()
    out = day_dir / f"{utc.strftime('%H%M%S')}_{sha[:12]}.json"
    out.write_bytes(raw)
    with open(DATA / "collection_log.jsonl", "a") as f:
        f.write(json.dumps({"url": url, "retrieved_at_utc": utc.isoformat(),
                            "sha256": sha, "bytes": len(raw),
                            "path": str(out.relative_to(ROOT))}) + "\n")
    return out


def fetch_markets(closed: bool, pages: int = 1, extra: dict = None) -> list:
    """Paged market fetch with byte-exact archiving. Returns parsed list."""
    all_markets = []
    for page in range(pages):
        offset = page * PAGE_LIMIT
        if offset >= OFFSET_WALL:
            raise CollectorError(f"offset {offset} >= wall {OFFSET_WALL}: switch to date-window pagination")
        params = {"limit": PAGE_LIMIT, "offset": offset, "closed": str(closed).lower()}
        params.update(extra or {})
        url, raw = _get("/markets", params)
        _archive("gamma_markets", url, raw)
        batch = json.loads(raw)
        if not isinstance(batch, list):
            raise CollectorError(f"unexpected response shape: {type(batch)}")
        all_markets.extend(batch)
        if len(batch) < PAGE_LIMIT:
            break
    return all_markets


def _parse_ts(s):
    if not s or not isinstance(s, str):
        return None
    s = s.strip().replace(" ", "T", 1)
    if s.endswith("+00"):
        s += ":00"
    try:
        dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp()


def two_clock_view(market: dict, retrieved_at: float) -> dict:
    """Extract the two-clock summary. This is where the Paper-1 pseudo-resolution
    trap is made explicit: endDate is NOT settlement."""
    end_date = _parse_ts(market.get("endDate"))
    closed_time = _parse_ts(market.get("closedTime"))
    uma_end = _parse_ts(market.get("umaEndDate"))
    prices = market.get("outcomePrices")
    outcome = None
    if market.get("umaResolutionStatus") == "resolved" and isinstance(prices, (list, str)):
        try:
            pv = [float(x) for x in (json.loads(prices) if isinstance(prices, str) else prices)]
            if pv == [1.0, 0.0]:
                outcome = "yes"
            elif pv == [0.0, 1.0]:
                outcome = "no"
            elif all(abs(x - 0.5) < 1e-9 for x in pv):
                outcome = "unknown_50_50"
        except (ValueError, TypeError):
            outcome = None
    return {
        "provenance_tier": "gamma_coarse",
        "market_id": str(market.get("id")),
        "condition_id": market.get("conditionId"),
        "question": market.get("question"),
        "neg_risk": bool(market.get("negRisk")),
        "event_ids": [str(e.get("id")) for e in (market.get("events") or [])],
        "end_date": end_date,
        "closed_time": closed_time,
        "uma_end": uma_end,
        "uma_status": market.get("umaResolutionStatus"),
        "uma_status_history": market.get("umaResolutionStatuses"),
        "outcome_gamma_coarse": outcome,
        "pseudo_resolution_gap_days": (round((end_date - (uma_end or closed_time)) / 86400, 2)
                                       if end_date and (uma_end or closed_time) else None),
        "retrieved_at": retrieved_at,
    }


def collect_dev_sample(closed_pages: int = 3, open_pages: int = 1) -> dict:
    """One dev-tier collection run: archives raw pages, writes a two-clock view
    table, and returns summary stats (incl. pseudo-resolution gap distribution)."""
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    closed = fetch_markets(True, pages=closed_pages,
                           extra={"order": "endDate", "ascending": "false"})
    open_ = fetch_markets(False, pages=open_pages,
                          extra={"order": "volume24hr", "ascending": "false"})
    views = [two_clock_view(m, now) for m in closed + open_]
    out = DATA / "views"
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    view_path = out / f"two_clock_view_{stamp}.jsonl"
    with open(view_path, "w") as f:
        for v in views:
            f.write(json.dumps(v, ensure_ascii=False) + "\n")
    gaps = [v["pseudo_resolution_gap_days"] for v in views
            if v["pseudo_resolution_gap_days"] is not None]
    resolved = [v for v in views if v["uma_status"] == "resolved"]
    return {
        "n_markets": len(views),
        "n_closed_fetched": len(closed),
        "n_open_fetched": len(open_),
        "n_uma_resolved": len(resolved),
        "n_negrisk": sum(1 for v in views if v["neg_risk"]),
        "outcome_counts": {o: sum(1 for v in resolved if v["outcome_gamma_coarse"] == o)
                           for o in ("yes", "no", "unknown_50_50", None)},
        "pseudo_gap_days": {
            "n": len(gaps),
            "min": min(gaps) if gaps else None,
            "median": sorted(gaps)[len(gaps) // 2] if gaps else None,
            "max": max(gaps) if gaps else None,
            "n_gap_over_1d": sum(1 for g in gaps if g > 1),
        },
        "view_path": str(view_path.relative_to(ROOT)),
    }


if __name__ == "__main__":
    print(json.dumps(collect_dev_sample(), indent=2, ensure_ascii=False))
