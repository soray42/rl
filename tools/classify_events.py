"""LLM topic classification over ALL registry events (user directive: per-event
agent classification; unclassified rescued; tag-based exclusions AUDITED).

R14-1 provenance contract: every label is DERIVED, never asserted —
  raw model output bytes are persisted per call together with the ordered
  (item_index, event_id) coverage; the parser is the frozen module
  src/p1v5/topic_parser.py (its file sha is the parser referent); each topics
  row carries its call_id / item_index / output_sha binding; the G5a gate
  re-runs the frozen parser over the persisted raw outputs and refuses any
  label that does not re-derive. The checkpoint is content-addressed by the
  FULL (registry sha, taxonomy, model, protocol, parser sha) tuple and stores
  complete call rows, so resumed labels keep their receipts (P1-14-1).

Outputs (data/views/):
  llm_topics_calls_<stamp>.jsonl   raw call rows (prompt/output shas + raw text + coverage)
  llm_topics_<stamp>.jsonl         _lineage header + per-event bound labels
  topic_audit_<stamp>.json         tag-vs-LLM disagreement report
Cost cap: $1 (hard abort)."""

import datetime
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
VIEWS = ROOT / "data/views"        # module-level so tests can redirect output

from p1v5.deliberation import OpenRouterBackend  # noqa: E402
from p1v5.topic_parser import (CATS, ELIGIBLE, PROTOCOL, build_prompt,  # noqa: E402
                               parse_reply)

MODEL = "deepseek/deepseek-v4-flash"
BATCH = 40
COST_CAP_USD = 1.0
PRICE_IN, PRICE_OUT = 0.09, 0.18
PARSER_PATH = ROOT / "src/p1v5/topic_parser.py"


def load_rows(reg_path) -> list:
    """Registry rows minus the _lineage header (shadow r3: registries now open
    with a lineage record; event consumers must skip it, never classify it)."""
    return [o for o in (json.loads(l) for l in open(reg_path)) if "_lineage" not in o]


def main() -> dict:
    views = VIEWS
    import os as _os
    reg_path = _os.environ.get("P1V5_REGISTRY")
    if not reg_path:
        raise SystemExit("R12: set P1V5_REGISTRY=<event_registry_*.jsonl>; implicit latest is forbidden")
    reg = Path(reg_path)
    rows = load_rows(reg)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    backend = OpenRouterBackend(MODEL, provider_pin=None)  # 分类≠实验:解钉换吞吐

    reg_sha = hashlib.sha256(reg.read_bytes()).hexdigest()
    parser_sha = hashlib.sha256(PARSER_PATH.read_bytes()).hexdigest()
    # P1-14-1: checkpoint content-addressed by the FULL protocol identity
    ckpt_identity = {"registry_sha256": reg_sha, "taxonomy": CATS, "model": MODEL,
                     "prompt_protocol": PROTOCOL, "parser_sha256": parser_sha,
                     "batch_size": BATCH}
    ckpt_key = hashlib.sha256(json.dumps(ckpt_identity, sort_keys=True).encode()).hexdigest()[:16]
    ckpt_path = views / f"llm_calls_checkpoint_{ckpt_key}.jsonl"

    call_rows, labels, binding = [], {}, {}

    def absorb_call(row):
        """Derive labels from one persisted call row (checkpoint or fresh)."""
        if hashlib.sha256(row["raw_text"].encode()).hexdigest() != row["output_sha"]:
            raise SystemExit(f"checkpoint call {row['call_id']} raw_text/output_sha mismatch; "
                             f"refusing corrupted provenance")
        idxs = {i for i, _ in row["items"]}
        parsed = parse_reply(row["raw_text"], idxs)
        for i, _eid in row["items"]:
            if i in parsed:
                labels[i] = parsed[i]
                binding[i] = {"call_id": row["call_id"], "item_index": i,
                              "output_sha": row["output_sha"]}

    if ckpt_path.exists():
        lines = [json.loads(l) for l in open(ckpt_path)]
        if not lines or lines[0].get("_checkpoint") != ckpt_identity:
            raise SystemExit("checkpoint identity mismatch (registry/taxonomy/model/parser "
                             "changed); refusing to resume across protocols")
        for row in lines[1:]:
            call_rows.append(row)
            absorb_call(row)
        print(f"resume: {len(labels)} labels re-derived from {len(call_rows)} "
              f"checkpointed calls", flush=True)
    else:
        ckpt_path.parent.mkdir(parents=True, exist_ok=True)
        with open(ckpt_path, "w") as f:
            f.write(json.dumps({"_checkpoint": ckpt_identity}) + "\n")

    todo = [(idx, rows[idx]["title"] or rows[idx]["series_key"])
            for idx in range(len(rows)) if idx not in labels]
    spent = 0.0
    ckpt_f = open(ckpt_path, "a")

    import threading
    from concurrent.futures import ThreadPoolExecutor
    lock = threading.Lock()

    def run_batch(batch, seed):
        nonlocal spent
        prompt = build_prompt(batch)
        text, rec = backend.complete(prompt, seed=seed, purpose="topic_classify", max_tokens=600)
        row = {"call_id": rec.prompt_sha[:16], "seed": seed, "model": rec.model,
               "provider": rec.provider, "prompt_sha": rec.prompt_sha,
               "output_sha": rec.output_sha,
               "prompt_tokens": rec.prompt_tokens, "completion_tokens": rec.completion_tokens,
               "raw_text": text,
               "items": [[i, rows[i]["event_id"]] for i, _ in batch]}
        with lock:
            call_rows.append(row)
            ckpt_f.write(json.dumps(row, ensure_ascii=False) + "\n")
            ckpt_f.flush()
            absorb_call(row)
            spent += (rec.prompt_tokens * PRICE_IN + rec.completion_tokens * PRICE_OUT) / 1e6
            if spent > COST_CAP_USD:
                raise SystemExit(f"classification cost cap ${COST_CAP_USD} hit")

    def worker(b0):
        batch = todo[b0:b0 + BATCH]
        try:
            run_batch(batch, seed=9000 + b0)
            missing = [it for it in batch if it[0] not in labels]
            if missing:
                for h0 in range(0, len(missing), max(1, BATCH // 2)):
                    run_batch(missing[h0:h0 + BATCH // 2], seed=9500 + b0 + h0)
        except SystemExit:
            raise
        except Exception as exc:
            print(f"  batch@{b0} failed: {exc}", flush=True)
            return
        if (b0 // BATCH) % 20 == 0:
            print(f"batch {b0 // BATCH}: labeled {len(labels)} spent=${spent:.3f}", flush=True)

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(worker, range(0, len(todo), BATCH)))
    ckpt_f.close()

    out_rows, audit = [], {"rescued_from_unclassified": [], "false_exclusion_candidates": [],
                           "eligible_downgraded": []}
    for idx, r in enumerate(rows):
        cat = labels.get(idx, "unparsed")
        row = {"event_id": r["event_id"], "title": r["title"],
               "topic_tags": r["topic"], "topic_llm": cat,
               "eligible_llm": cat in ELIGIBLE, "n_settled": r["n_settled"]}
        # R14-1: each derived label names its call / item / output binding;
        # unparsed rows are typed failures with no binding, never defaults
        row.update(binding.get(idx, {}))
        out_rows.append(row)
        if cat in ELIGIBLE and r["topic"] == "unclassified":
            audit["rescued_from_unclassified"].append((r["event_id"], r["title"][:60], cat))
        if cat in ELIGIBLE and r["topic"] == "excluded":
            audit["false_exclusion_candidates"].append((r["event_id"], r["title"][:60], cat))
        if cat not in ELIGIBLE and r["topic"] == "eligible":
            audit["eligible_downgraded"].append((r["event_id"], r["title"][:60], cat))

    calls_name = f"llm_topics_calls_{stamp}.jsonl"
    with open(views / calls_name, "w") as f:
        for row in call_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    calls_sha = hashlib.sha256((views / calls_name).read_bytes()).hexdigest()
    with open(views / f"llm_topics_{stamp}.jsonl", "w") as f:
        f.write(json.dumps({"_lineage": {
            "registry_sha256": reg_sha, "model": MODEL, "taxonomy": CATS,
            "prompt_protocol": PROTOCOL, "parser_sha256": parser_sha,
            "calls_file": calls_name, "calls_sha256": calls_sha,
            "n_llm_calls": len(call_rows), "n_labeled": len(labels),
            "batch_size": BATCH}}) + "\n")
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
        "llm_calls": len(call_rows), "spent_usd": round(spent, 4),
        "source_registry": reg.name,
    }
    (views / f"topic_audit_{stamp}.json").write_text(
        json.dumps({"summary": summary, "audit": audit}, indent=2, ensure_ascii=False))
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


if __name__ == "__main__":
    main()
