"""Attach a plain-language description, and a publisher where it's missing, to every change.

Description, first match wins:
  1. your tag                (source = "yours")     — known_software.toml, always wins
  2. curated rule            (source = "rule")      — accurate, offline
  3. cached AI answer        (source = "ai" / "ai-low" / "ai-web" / "ai-web-low")
  4. software's own text     (source = "publisher") — pip/npm/Store/extension/Windows Update metadata
  5. AI provider             (source = "ai" / "ai-low") — Claude or local Ollama, when AI is enabled
  6. Claude + web search     (source = "ai-web")    — only when SYSSCAN_AI_WEB is on (Claude only)
  7. nothing                 (source = "none")

Publisher: your tag, else the software's own, else (AI on) the provider in the same requests. AI publishers
are only used when the model is confident; they're marked "ai" (publisher_source).

Every AI answer is cached per product, including "don't know", so nothing is sent twice. A product that
the plain AI pass couldn't identify is retried with web search once, the next time web search is on.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from sysscan.config import AIConfig
from sysscan.describe.ai import (
    AIAnswer,
    AIItem,
    MissingAPIKey,
    build_describer,
    normalize_provider,
)
from sysscan.describe.rules import describe_by_rule
from sysscan.known import KnownSoftware
from sysscan.models import Change
from sysscan.store import CachedAnswer, Store
from sysscan.winutil import utcnow

log = logging.getLogger(__name__)

_BOILERPLATE = re.compile(
    r"^(install this update|a security issue has been identified|this update|for a complete listing)",
    re.I,
)


def usable_publisher_text(text: str | None) -> str | None:
    if not text:
        return None
    t = " ".join(text.split())
    if len(t) < 12 or _BOILERPLATE.match(t) or t.lower().startswith(("http://", "https://")):
        return None
    if len(t) > 260:
        cut = t[:260].rsplit(". ", 1)[0]
        t = (cut if len(cut) > 60 else t[:257]) + "…"
    return t


def cache_key(change: Change) -> str:
    return f"{change.category}:{change.norm_name or change.name.lower()}"


def publisher_unknown(change: Change) -> bool:
    return change.provider == "Unknown"


@dataclass
class _Pending:
    change: Change
    needs: list[str] = field(default_factory=list)


class DescriptionPipeline:
    def __init__(self, store: Store, ai: AIConfig, use_ai: bool,
                 describer_factory: Callable[[AIConfig], object] | None = None,
                 known: KnownSoftware | None = None):
        self.store = store
        self.ai = ai
        self.use_ai = use_ai
        self.known = known or KnownSoftware()
        self.describer_factory = describer_factory or build_describer
        self.messages: list[str] = []
        self.stats = {"descriptions": 0, "publishers": 0, "web": 0, "yours": 0}

    # ------------------------------------------------------------------ main entry

    def run(self, changes: list[Change]) -> None:
        pending: list[_Pending] = []
        for c in changes:
            own_text = usable_publisher_text(c.description)  # the software's own description, if any
            c.description = None
            tag = self.known.find(c)
            cached = self.store.get_description(cache_key(c))

            if tag and tag.publisher:
                c.publisher, c.publisher_source = tag.publisher, "yours"
            if tag and tag.description:
                c.description, c.description_source = tag.description, "yours"
            elif text := describe_by_rule(c):
                c.description, c.description_source = text, "rule"
            elif cached and cached.description:
                c.description, c.description_source = cached.description, cached.source
                c.source_url = cached.source_url
            elif own_text:
                c.description, c.description_source = own_text, "publisher"
            if tag:
                self.stats["yours"] += 1

            if publisher_unknown(c) and cached and cached.publisher:
                c.publisher, c.publisher_source = cached.publisher, "ai"

            needs = []
            if not c.description and not self._asked(cached, "description"):
                needs.append("description")
            if publisher_unknown(c) and not self._asked(cached, "publisher"):
                needs.append("publisher")
            if not needs and self.ai.web and self._web_retry_due(c, cached):
                needs = [n for n, missing in (("description", c.description_source == "ai-low"),
                                              ("publisher", publisher_unknown(c))) if missing]
            if needs:
                pending.append(_Pending(c, needs))
            c._own_text = own_text  # type: ignore[attr-defined]  # hint for the AI prompt

        if pending and self.use_ai:
            self._run_ai(pending)

        for c in changes:
            c.__dict__.pop("_own_text", None)
            if not c.description:
                c.description_source = "none"

        if self.use_ai and (self.stats["descriptions"] or self.stats["publishers"]):
            web = f" ({self.stats['web']} using web search)" if self.stats["web"] else ""
            who = "Ollama" if normalize_provider(self.ai.provider) == "ollama" else "Claude"
            self.messages.append(
                f"{who} filled in {self.stats['descriptions']} description(s) and "
                f"{self.stats['publishers']} publisher(s) that weren't available on this PC{web}. "
                "They're marked AI in the report."
            )

    @staticmethod
    def _asked(cached: CachedAnswer | None, what: str) -> bool:
        """True if the AI was already asked for this field (answers, including 'unknown', are cached)."""
        if cached is None:
            return False
        if what == "publisher":
            return cached.publisher is not None
        return True  # a cache row always means the description was asked for

    @staticmethod
    def _web_retry_due(c: Change, cached: CachedAnswer | None) -> bool:
        """A product the plain AI pass couldn't pin down, and that hasn't been web-searched yet."""
        if cached is None or cached.source.startswith("ai-web"):
            return False
        unsure = c.description_source == "ai-low" or (publisher_unknown(c) and cached.publisher == "")
        return unsure and c.description_source != "yours"

    # ------------------------------------------------------------------ AI

    def _run_ai(self, pending: list[_Pending]) -> None:
        try:
            describer = self.describer_factory(self.ai)
        except MissingAPIKey as exc:
            self.messages.append(str(exc))
            return
        except ImportError:
            self.messages.append('AI is enabled but the Anthropic SDK is missing: pip install "sysscan[ai]"')
            return
        except ValueError as exc:
            self.messages.append(str(exc))
            return

        # One request per product, even if several changes share it.
        unique: dict[str, _Pending] = {}
        for p in pending:
            ck = cache_key(p.change)
            if ck in unique:
                unique[ck].needs = sorted(set(unique[ck].needs) | set(p.needs))
            else:
                unique[ck] = _Pending(p.change, list(p.needs))

        first_pass = {ck: p for ck, p in unique.items()
                      if not self._web_retry_due(p.change, self.store.get_description(ck))}
        answers = self._ask(describer, first_pass, web=False)

        use_web = self.ai.web and normalize_provider(self.ai.provider) == "claude"
        if self.ai.web and not use_web:
            self.messages.append("Web search is only available with Claude; skipped for Ollama.")
        if use_web:
            still = {ck: p for ck, p in unique.items()
                     if ck not in answers or self._unresolved(p, answers[ck])}
            if still:
                answers.update(self._ask(describer, still, web=True))

        for p in pending:
            ans = answers.get(cache_key(p.change))
            if ans is None:
                continue
            c = p.change
            web = bool(getattr(ans, "_web", False))
            high = ans.confidence == "high"
            source = ("ai-web" if high else "ai-web-low") if web else ("ai" if high else "ai-low")
            if "description" in p.needs and ans.description and (
                    not c.description or c.description_source in ("ai-low", "ai-web-low") or high):
                c.description, c.description_source = ans.description, source
                c.source_url = ans.source_url
                self.stats["descriptions"] += 1
                self.stats["web"] += int(web)
            if "publisher" in p.needs and ans.publisher and ans.confidence == "high":
                c.publisher, c.publisher_source = ans.publisher, "ai"
                self.stats["publishers"] += 1

    @staticmethod
    def _unresolved(p: _Pending, ans: AIAnswer) -> bool:
        return ans.confidence != "high" or ("publisher" in p.needs and not ans.publisher)

    def _ask(self, describer, todo_map: dict[str, _Pending], web: bool) -> dict[str, AIAnswer]:
        limit = self.ai.web_max_items if web else self.ai.max_items_per_run
        todo = list(todo_map.items())[:limit]
        if len(todo_map) > len(todo):
            what = "SYSSCAN_AI_WEB_MAX_ITEMS" if web else "SYSSCAN_AI_MAX_ITEMS"
            self.messages.append(f"AI {'web search ' if web else ''}limit reached: {len(todo_map) - len(todo)} "
                                 f"item(s) were not sent (raise {what}).")
        batch_size = 5 if web else self.ai.batch_size
        answers: dict[str, AIAnswer] = {}
        for start in range(0, len(todo), batch_size):
            batch = todo[start:start + batch_size]
            items = [AIItem(id=i, name=p.change.name, publisher=p.change.publisher,
                            version=p.change.version_to or p.change.version_from,
                            category=p.change.category.label, hint=getattr(p.change, "_own_text", None),
                            needs=p.needs, hints=dict(p.change.hints))
                     for i, (_, p) in enumerate(batch)]
            try:
                result = describer.describe(items, web=web) if web else describer.describe(items)  # type: ignore[attr-defined]
            except Exception as exc:  # network, auth, rate limit, web search disabled …
                log.exception("AI request failed")
                self.messages.append(f"AI {'web search ' if web else ''}request failed "
                                     f"({exc.__class__.__name__}): {exc}")
                break
            for i, (ck, p) in enumerate(batch):
                ans = result.get(i, AIAnswer(None, None, "low"))
                ans._web = web  # type: ignore[attr-defined]
                answers[ck] = ans
                self._cache(ck, p, ans, web)
        return answers

    def _cache(self, ck: str, p: _Pending, ans: AIAnswer, web: bool) -> None:
        prev = self.store.get_description(ck)
        prev_desc = prev.description if prev else ""
        description = (ans.description or prev_desc) if "description" in p.needs else prev_desc
        if "publisher" in p.needs:
            publisher = ans.publisher if ans.confidence == "high" and ans.publisher else ""
        else:
            publisher = prev.publisher if prev else None
        # A web pass is recorded as ai-web(-low) even when unsure, so it isn't searched again.
        high = ans.confidence == "high"
        source = ("ai-web" if high else "ai-web-low") if web else ("ai" if high else "ai-low")
        self.store.put_description(ck, description or "", source, self.ai.model, utcnow(),
                                   publisher=publisher, source_url=ans.source_url)
