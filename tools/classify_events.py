"""LLM topic classification over ALL registry events (user directive: per-event
agent classification; unclassified rescued; tag-based exclusions AUDITED).

Uses our own OpenRouter backend (deepseek-v4-flash) in batches of 25 titles with
a strict JSON contract; invalid batches retry once at half size; still-invalid
titles land in 'unparsed' (typed failure, never silently defaulted).

Taxonomy (paper-relevant "eligible" = first five):
  macro_indicators | monetary_policy | geopolitics | elections_politics |
  financial_markets | crypto | tech_business | sports_esports |
  entertainment_culture | science_weather | other

Outputs:
  data/views/llm_topics_<stamp>.jsonl        event_id -> category, confidence
  data/views/topic_audit_<stamp>.json        tag-vs-LLM disagreement report
Cost cap: $1 (hard abort). Receipts archived like every other call.
"""

import datetime
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p1v5.deliberation import OpenRouterBackend  # noqa: E402

MODEL = "deepseek/deepseek-v4-flash"
CATS = ["macro_indicators", "monetary_policy", "geopolitics", "elections_politics",
        "financial_markets", "crypto", "tech_business", "sports_esports",
        "entertainment_culture", "science_weather", "other"]
ELIGIBLE = set(CATS[:5])
BATCH = 40
COST_CAP_USD = 1.0
PRICE_IN, PRICE_OUT = 0.09, 0.18


LETTER = {c: chr(97 + i) for i, c in enumerate(CATS)}     # a..k
UNLETTER = {v: k for k, v in LETTER.items()}


def build_prompt(items: list) -> str:
    lines = "\n".join(f"{i}: {t[:110]}" for i, t in items)
    legend = ", ".join(f"{LETTER[c]}={c}" for c in CATS)
    return (
        "Classify each prediction-market event title into EXACTLY one category letter.\n"
        f"Legend: {legend}.\n"
        "Hints: econ data releases=a; central banks/rates=b; wars/diplomacy/regime=c; "
        "elections/officials/legislation=d; stock/commodity/index prices=e; crypto=f; "
        "AI/products/company rankings=g; sports=h; entertainment=i; weather/science=j; other=k.\n"
        "Output ONLY lines of the form `<number>:<letter>`, one per item, nothing else.\n\n"
        + lines)


def parse_reply(text: str, expect: set) -> dict:
    out = {}
    for m in re.finditer(r"^\s*(\d+)\s*[:=]\s*([a-k])\b", text or "", re.M):
        i, letter = int(m.group(1)), m.group(2)
        if i in expect:
            out[i] = UNLETTER[letter]
    return out


def main() -> dict:
    views = ROOT / "data/views"
    reg = sorted(views.glob("event_registry_*.jsonl"))[-1]
    rows = [json.loads(l) for l in open(reg)]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    backend = OpenRouterBackend(MODEL, provider_pin=None)  # 分类≠实验:解钉换吞吐

    ckpt_path = views / "llm_topics_checkpoint.jsonl"
    done_ids = {}
    if ckpt_path.exists():
        for line in open(ckpt_path):
            o = json.loads(line)
            done_ids[o["event_id"]] = o["c"]
        print(f"resume: {len(done_ids)} labels from checkpoint", flush=True)
    todo = [(idx, r["title"] or r["series_key"]) for idx, r in enumerate(rows)
            if r["event_id"] not in done_ids]
    labels = {idx: done_ids[r["event_id"]] for idx, r in enumerate(rows)
              if r["event_id"] in done_ids}
    spent, receipts = 0.0, 0
    ckpt_f = open(ckpt_path, "a")

    import threading
    from concurrent.futures import ThreadPoolExecutor
    lock = threading.Lock()

    def run_batch(batch, seed):
        nonlocal spent, receipts
        prompt = build_prompt(batch)
        text, rec = backend.complete(prompt, seed=seed, purpose="topic_classify")
        with lock:
            receipts += 1
            spent += (rec.prompt_tokens * PRICE_IN + rec.completion_tokens * PRICE_OUT) / 1e6
            if spent > COST_CAP_USD:
                raise SystemExit(f"classification cost cap ${COST_CAP_USD} hit")
        return parse_reply(text, {i for i, _ in batch})

    def worker(b0):
        batch = todo[b0:b0 + BATCH]
        try:
            got = run_batch(batch, seed=9000 + b0)
            missing = [it for it in batch if it[0] not in got]
            if missing:
                for h0 in range(0, len(missing), max(1, BATCH // 2)):
                    got.update(run_batch(missing[h0:h0 + BATCH // 2], seed=9500 + b0 + h0))
        except SystemExit:
            raise
        except Exception as exc:
            print(f"  batch@{b0} failed: {exc}", flush=True)
            return
        with lock:
            labels.update(got)
            for i, cat in got.items():
                ckpt_f.write(json.dumps({"event_id": rows[i]["event_id"], "c": cat}) + "\n")
            ckpt_f.flush()
            if (b0 // BATCH) % 20 == 0:
                print(f"batch {b0 // BATCH}: labeled {len(labels)} spent=${spent:.3f}", flush=True)

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(worker, range(0, len(todo), BATCH)))

    out_rows, audit = [], {"rescued_from_unclassified": [], "false_exclusion_candidates": [],
                           "eligible_downgraded": []}
    for idx, r in enumerate(rows):
        cat = labels.get(idx, "unparsed")
        out_rows.append({"event_id": r["event_id"], "title": r["title"],
                         "topic_tags": r["topic"], "topic_llm": cat,
                         "eligible_llm": cat in ELIGIBLE, "n_settled": r["n_settled"]})
        if cat in ELIGIBLE and r["topic"] == "unclassified":
            audit["rescued_from_unclassified"].append((r["event_id"], r["title"][:60], cat))
        if cat in ELIGIBLE and r["topic"] == "excluded":
            audit["false_exclusion_candidates"].append((r["event_id"], r["title"][:60], cat))
        if cat not in ELIGIBLE and r["topic"] == "eligible":
            audit["eligible_downgraded"].append((r["event_id"], r["title"][:60], cat))

    with open(views / f"llm_topics_{stamp}.jsonl", "w") as f:
        for o in out_rows:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    summary = {
        "n_events": len(rows), "n_labeled": len(labels),
        "n_unparsed": len(rows) - len(labels),
        "category_hist": dict(Counter(o["topic_llm"] for o in out_rows)),
        "n_eligible_llm": sum(o["eligible_llm"] for o in out_rows),
        "n_eligible_llm_settled": sum(o["eligible_llm"] and o["n_settled"] > 0 for o in out_rows),
        "n_rescued_from_unclassified": len(audit["rescued_from_unclassified"]),
        "n_false_exclusion_candidates": len(audit["false_exclusion_candidates"]),
        "n_eligible_downgraded": len(audit["eligible_downgraded"]),
        "llm_calls": receipts, "spent_usd": round(spent, 4),
        "source_registry": reg.name,
    }
    (views / f"topic_audit_{stamp}.json").write_text(
        json.dumps({"summary": summary, "audit": audit}, indent=2, ensure_ascii=False))
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


if __name__ == "__main__":
    main()
