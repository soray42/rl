"""E4: typed team deliberation pipeline with real credit computation.

Design contract (audits E4/A20/r10):
- every LLM call produces a CallReceipt (backend, model, prompt/output sha,
  token estimates, purpose); c3 and sham receipts must match per-prefix;
- prompts are MATERIALIZED bytes (question + evidence + retrieved memory);
  their sha is the commitment-grade prompt hash (r10 §6.6);
- forecasts are parsed strictly; anything else is a typed failure feeding the
  scoring fallback (never a silent default);
- backends: StubBackend (deterministic, zero-cost, for tests/dry-runs) and
  OpenRouterBackend (real; requires OPENROUTER_API_KEY; never called in tests).
"""

import hashlib
import json
import os
import re
import statistics
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from .policy import MemoryState, brier_utility, rank_and_sign, sattolo_derangement, _admit

NEUTRAL_MESSAGE = ("I have no additional evidence to contribute on this question "
                   "and defer to the group's other information.")


@dataclass(frozen=True)
class CallReceipt:
    backend: str
    model: str
    purpose: str
    prompt_sha: str
    output_sha: str
    prompt_chars: int
    output_chars: int
    latency_ms: int
    prompt_tokens: int = 0        # provider-billed actuals (0 for stub)
    completion_tokens: int = 0
    provider: str = ""            # which upstream served the call (routing receipt)


@dataclass(frozen=True)
class Message:
    agent_id: str
    round: int
    content: str


@dataclass
class Transcript:
    question_id: str
    messages: list = field(default_factory=list)
    votes: dict = field(default_factory=dict)          # agent_id -> float|None
    final_q: Optional[float] = None
    receipts: list = field(default_factory=list)
    prompt_shas: list = field(default_factory=list)
    failure_class: Optional[str] = None

    def sha(self) -> str:
        return hashlib.sha256(json.dumps(
            {"q": self.question_id,
             "msgs": [[m.agent_id, m.round, m.content] for m in self.messages],
             "votes": {k: repr(v) for k, v in sorted(self.votes.items())},
             "final": repr(self.final_q)}, sort_keys=True).encode()).hexdigest()


VOTE_RE = re.compile(r"FINAL:\s*(1(?:\.0+)?|0(?:\.\d+)?)\s*$", re.MULTILINE)


def parse_probability(text: str) -> Optional[float]:
    """shadow-audit r1 P0-4 fix: the LAST well-formed FINAL line is the vote —
    a model that states a tentative figure and then revises must be scored on
    its revision, not its draft."""
    ms = VOTE_RE.findall(text or "")
    if not ms:
        return None
    try:
        q = float(ms[-1])
    except ValueError:
        return None
    return q if 0.0 <= q <= 1.0 else None


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

class StubBackend:
    """Deterministic pseudo-agent: forecast derived from sha(prompt+seed).
    Contains a weak signal channel so credit estimators have something real to
    find: prompts containing 'SIGNAL_YES'/'SIGNAL_NO' shift the vote."""
    name = "stub"

    def complete(self, prompt: str, seed: int, purpose: str, model: str = "stub-1") -> tuple:
        h = hashlib.sha256(f"{prompt}|{seed}".encode()).hexdigest()
        base = (int(h[:6], 16) % 1000) / 1000.0
        shift = 0.25 * prompt.count("SIGNAL_YES") - 0.25 * prompt.count("SIGNAL_NO")
        q = min(0.99, max(0.01, 0.3 + 0.4 * base + shift))
        text = f"Deterministic stub reasoning ({h[:8]}).\nFINAL: {q:.3f}"
        receipt = CallReceipt(self.name, model, purpose,
                              hashlib.sha256(prompt.encode()).hexdigest(),
                              hashlib.sha256(text.encode()).hexdigest(),
                              len(prompt), len(text), 0)
        return text, receipt


class OpenRouterBackend:
    """Real backend. Requires OPENROUTER_API_KEY. Deterministic settings."""
    name = "openrouter"
    URL = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(self, model: str, provider_pin: str = "DeepInfra"):
        """provider_pin (E10, replay measurement 2026-07-14): unpinned OpenRouter
        routing scattered 24 calls across 13 providers with vote-agreement 0.25
        and 17% parse failures. Pinning one provider is a frozen design value;
        None disables the pin (measurement only, never the experiment)."""
        self.model = model
        self.provider_pin = provider_pin
        self.key = os.environ.get("OPENROUTER_API_KEY")
        if not self.key:
            raise RuntimeError("OPENROUTER_API_KEY not set; use StubBackend for dry runs")

    def complete(self, prompt: str, seed: int, purpose: str, model: str = None) -> tuple:
        model = model or self.model
        payload = {"model": model, "temperature": 0, "seed": seed,
                   "max_tokens": 400,
                   "messages": [{"role": "user", "content": prompt}]}
        if self.provider_pin:
            payload["provider"] = {"order": [self.provider_pin], "allow_fallbacks": False}
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.URL, data=body, method="POST",
            headers={"Authorization": f"Bearer {self.key}",
                     "Content-Type": "application/json",
                     "HTTP-Referer": "https://p1v5.local", "X-Title": "p1v5-micropilot"})
        t0 = time.monotonic()
        out = None
        for attempt, backoff in enumerate((0, 5, 15, 30)):
            if backoff:
                time.sleep(backoff)
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    out = json.loads(resp.read())
                break
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 3:   # pinned provider rate limit: back off
                    continue
                raise
        # providers occasionally return content=None (empty/refusal/reasoning-only);
        # that is a typed empty output, NOT a crash — parse_probability(None-safe "")
        # will yield no vote and the scoring fallback handles it honestly
        text = out["choices"][0]["message"].get("content") or ""
        usage = out.get("usage") or {}
        receipt = CallReceipt(self.name, model, purpose,
                              hashlib.sha256(prompt.encode()).hexdigest(),
                              hashlib.sha256(text.encode()).hexdigest(),
                              len(prompt), len(text),
                              int((time.monotonic() - t0) * 1000),
                              usage.get("prompt_tokens", 0),
                              usage.get("completion_tokens", 0),
                              out.get("provider", ""))
        return text, receipt


# ---------------------------------------------------------------------------
# Team deliberation
# ---------------------------------------------------------------------------

def materialize_prompt(question: dict, evidence_slice: str, memory_items: list,
                       history: list, agent_id: str, stage: str) -> str:
    mem_block = "\n".join(f"- [{i.rank}|{i.ratio:+.3f}] {i.text}" for i in memory_items) or "(empty)"
    hist_block = "\n".join(f"{m.agent_id} (r{m.round}): {m.content}" for m in history) or "(none)"
    return (f"You are forecaster {agent_id} in a team.\n"
            f"QUESTION: {question['question']}\n"
            f"YOUR PRIVATE EVIDENCE: {evidence_slice}\n"
            f"YOUR EXPERIENCE MEMORY:\n{mem_block}\n"
            f"TEAM DISCUSSION SO FAR:\n{hist_block}\n"
            f"STAGE: {stage}. Reason briefly, then output exactly one line "
            f"'FINAL: <probability between 0 and 1>' for the YES outcome.")


class TeamDeliberation:
    def __init__(self, backend, n_agents: int = 3):
        self.backend = backend
        self.n_agents = n_agents

    def _agent_ids(self):
        return [f"agent-{i}" for i in range(self.n_agents)]

    def run(self, question: dict, evidence_slices: list, memory: MemoryState,
            seed: int) -> Transcript:
        assert len(evidence_slices) == self.n_agents, "one private slice per agent"
        t = Transcript(question_id=question["question_id"])
        retrieved = memory.retrieve()
        # round 1: independent estimates
        for i, aid in enumerate(self._agent_ids()):
            prompt = materialize_prompt(question, evidence_slices[i], retrieved,
                                        [], aid, "independent estimate")
            t.prompt_shas.append(hashlib.sha256(prompt.encode()).hexdigest())
            text, rec = self.backend.complete(prompt, seed + i, "round1")
            t.receipts.append(rec)
            t.messages.append(Message(aid, 1, text))
        # round 2: discussion + final vote
        r1 = [m for m in t.messages if m.round == 1]
        for i, aid in enumerate(self._agent_ids()):
            prompt = materialize_prompt(question, evidence_slices[i], retrieved,
                                        r1, aid, "final vote after discussion")
            t.prompt_shas.append(hashlib.sha256(prompt.encode()).hexdigest())
            text, rec = self.backend.complete(prompt, seed + 100 + i, "round2")
            t.receipts.append(rec)
            t.messages.append(Message(aid, 2, text))
            t.votes[aid] = parse_probability(text)
        valid = [v for v in t.votes.values() if v is not None]
        if valid:
            t.final_q = statistics.median(valid)
        else:
            t.failure_class = "invalid_parse"
        return t

    # -- counterfactual machinery (real rollouts, receipted) -----------------
    def revote_with_replacement(self, question: dict, evidence_slices: list,
                                memory: MemoryState, transcript: Transcript,
                                replaced_agent: str, seed: int) -> Optional[float]:
        """Fixed history with replaced_agent's ROUND-1 message swapped for the
        canned neutral message; every agent re-votes (continuation rollout)."""
        retrieved = memory.retrieve()
        history = [Message(m.agent_id, 1, NEUTRAL_MESSAGE if m.agent_id == replaced_agent
                           else m.content)
                   for m in transcript.messages if m.round == 1]
        votes = []
        for i, aid in enumerate(self._agent_ids()):
            prompt = materialize_prompt(question, evidence_slices[i], retrieved,
                                        history, aid, "counterfactual re-vote")
            text, rec = self.backend.complete(prompt, seed + 200 + i, "c3_rollout")
            transcript.receipts.append(rec)
            v = parse_probability(text)
            if v is not None:
                votes.append(v)
        return statistics.median(votes) if votes else None


# ---------------------------------------------------------------------------
# Real-transcript credits (mirror the toy estimands exactly)
# ---------------------------------------------------------------------------

def credit_shared_surplus_t(transcript: Transcript, y: int) -> dict:
    if transcript.final_q is None:
        return {}
    surplus = brier_utility(transcript.final_q, y) - brier_utility(0.5, y)
    return {aid: surplus for aid in transcript.votes}


def credit_diff_agent_t(transcript: Transcript, y: int) -> dict:
    """Vote-level LOO on the median aggregator: no extra LLM calls."""
    if transcript.final_q is None:
        return {}
    full = brier_utility(transcript.final_q, y)
    out = {}
    for aid in transcript.votes:
        rest = [v for a, v in transcript.votes.items() if a != aid and v is not None]
        out[aid] = (full - brier_utility(statistics.median(rest), y)) if rest else 0.0
    return out


def credit_c3_action_t(team: TeamDeliberation, question: dict, evidence_slices: list,
                       memory: MemoryState, transcript: Transcript, y: int,
                       seed: int) -> dict:
    if transcript.final_q is None:
        return {}
    base = brier_utility(transcript.final_q, y)
    out = {}
    for aid in sorted(transcript.votes):
        q_repl = team.revote_with_replacement(question, evidence_slices, memory,
                                              transcript, aid, seed)
        out[aid] = (base - brier_utility(q_repl, y)) if q_repl is not None else 0.0
    return out


def credit_c3_sham_t(team: TeamDeliberation, question: dict, evidence_slices: list,
                     memory: MemoryState, transcript: Transcript, y: int,
                     seed: int, batch_id: str) -> dict:
    """IDENTICAL rollout pattern to c3 (receipts match by construction), then
    attribution deranged within the batch; singleton neutralized."""
    real = credit_c3_action_t(team, question, evidence_slices, memory,
                              transcript, y, seed)
    keys = sorted(real)
    if len(keys) < 2:
        return {k: 0.0 for k in keys}
    dseed = int(hashlib.sha256(batch_id.encode()).hexdigest()[:8], 16)
    mapping = sattolo_derangement(keys, dseed)
    return {k: real[mapping[k]] for k in keys}


def update_memory_from_credits(memory: MemoryState, credits: dict,
                               feedback_clock: float, batch_id: str,
                               texts: dict = None) -> MemoryState:
    """Same normalization/admission pipeline as the toy arms (R2 single interface)."""
    if not credits:
        return memory.write_batch(batch_id, [])
    norm = rank_and_sign(credits)
    items = _admit(norm, feedback_clock)
    if texts:
        items = [type(i)(key=i.key, text=texts.get(i.key, i.text), rank=i.rank,
                         sign=i.sign, ratio=i.ratio, feedback_clock=i.feedback_clock)
                 for i in items]
    return memory.write_batch(batch_id, items)
