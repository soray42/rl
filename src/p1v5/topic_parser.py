"""FROZEN topic-classification protocol (R14-1).

This module IS the parser referent: its file bytes are the parser_sha256 that
topics lineage pins and the G5a gate recomputes. Any change to taxonomy,
legend, prompt shape or parsing regex changes the sha and unbinds every label
produced under the old protocol — by design.
"""

import re

CATS = ["macro_indicators", "monetary_policy", "geopolitics", "elections_politics",
        "financial_markets", "crypto", "tech_business", "sports_esports",
        "entertainment_culture", "science_weather", "other"]
ELIGIBLE = set(CATS[:5])
LETTER = {c: chr(97 + i) for i, c in enumerate(CATS)}     # a..k
UNLETTER = {v: k for k, v in LETTER.items()}
PROTOCOL = "compact_letter_v1"


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
