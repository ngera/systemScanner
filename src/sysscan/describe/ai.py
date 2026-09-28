"""Claude-powered enrichment: a plain-language description and/or the publisher for software that
the built-in rules and the software's own metadata couldn't explain.

Privacy: only the display name, publisher (if known), version, category and (if present) the
publisher's own one-line description are sent. Nothing else about the machine leaves it.

API key lookup order: ANTHROPIC_API_KEY (environment or a .env file) → Windows Credential Manager.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

SYSTEM_PROMPT = """You identify Windows software for non-technical people.
Each item lists the fields it "needs": "description", "publisher", or both.

description: ONE or TWO short sentences (max ~35 words) in plain language saying what it is and, if
useful, why it might have been installed (e.g. "usually installed by another program").
No marketing language, no version numbers, no URLs.

publisher: the company, organisation or open-source project that makes it, as people usually write
it (e.g. "Microsoft", "Intel", "Python Software Foundation"). Give it ONLY if you are confident;
otherwise use null. Never invent one from the product name alone.

Items may include "hints" found on the PC: install_folder, vendor_website, executable. These are strong
clues: a vendor website domain or a Program Files folder usually names the maker.

If you do not recognise the item, do not guess specifics: describe only what the name and hints make
clear, set publisher to null and "confidence" to "low".

Output ONLY a JSON array, one object per item:
[{"id": <int>, "description": "<text or null>", "publisher": "<name or null>", "confidence": "high"|"low"}]"""

WEB_SYSTEM_PROMPT = SYSTEM_PROMPT.replace(
    "You identify Windows software for non-technical people.",
    "You identify Windows software for non-technical people. A first attempt could not identify these "
    "items, so use the web_search tool (at most 2 searches per item) to find what each one is and who makes "
    "it. Prefer the vendor's own site, Microsoft, or well-known references. Set confidence to \"high\" only "
    "when a search result clearly confirms it.",
).replace(
    '"confidence": "high"|"low"}]',
    '"confidence": "high"|"low", "source_url": "<the page that confirmed it, or null>"}]',
)

WEB_TOOL_TYPE = "web_search_20250305"

KEYRING_SERVICE = "sysscan"
KEYRING_USER = "anthropic_api_key"


@dataclass
class AIItem:
    id: int
    name: str
    publisher: str | None
    version: str | None
    category: str
    hint: str | None = None
    needs: list[str] = field(default_factory=lambda: ["description"])
    hints: dict[str, str] = field(default_factory=dict)


@dataclass
class AIAnswer:
    description: str | None
    publisher: str | None
    confidence: str = "high"
    source_url: str | None = None


def get_api_key() -> str | None:
    if key := os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return key
    try:
        import keyring

        return keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
    except Exception:
        return None


def set_api_key(key: str) -> None:
    import keyring

    keyring.set_password(KEYRING_SERVICE, KEYRING_USER, key)


def build_user_message(items: list[AIItem]) -> str:
    payload = [
        {k: v for k, v in {
            "id": it.id, "name": it.name, "publisher": it.publisher, "version": it.version,
            "category": it.category, "publisher_description": it.hint, "needs": it.needs,
            "hints": it.hints or None,
        }.items() if v}
        for it in items
    ]
    return "Identify these items:\n" + json.dumps(payload, ensure_ascii=False, indent=1)


def _clean(value: object) -> str | None:
    if value is None:
        return None
    s = " ".join(str(value).split())
    return None if not s or s.lower() in ("null", "none", "unknown", "n/a") else s


def _json_arrays(text: str):
    """Yield every top-level JSON array in the text, last one first (web answers put it at the end)."""
    starts = [i for i, ch in enumerate(text) if ch == "["]
    decoder = json.JSONDecoder()
    for i in reversed(starts):
        try:
            value, _ = decoder.raw_decode(text[i:])
        except ValueError:
            continue
        if isinstance(value, list) and all(isinstance(v, dict) for v in value) and value:
            yield value


def parse_response(text: str) -> dict[int, AIAnswer]:
    """Extract {id: AIAnswer} from the model output, tolerating code fences and surrounding prose."""
    rows = next(_json_arrays(text), [])
    out: dict[int, AIAnswer] = {}
    for r in rows:
        try:
            url = _clean(r.get("source_url"))
            ans = AIAnswer(description=_clean(r.get("description")), publisher=_clean(r.get("publisher")),
                           confidence=str(r.get("confidence", "high")).lower(),
                           source_url=url if url and url.startswith(("http://", "https://")) else None)
            if ans.description or ans.publisher:
                out[int(r["id"])] = ans
        except (AttributeError, KeyError, TypeError, ValueError):
            continue
    return out


class ClaudeDescriber:
    def __init__(self, api_key: str, model: str):
        import anthropic

        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.web_searches = 0

    def describe(self, items: list[AIItem], web: bool = False) -> dict[int, AIAnswer]:
        messages: list[dict] = [{"role": "user", "content": build_user_message(items)}]
        kwargs: dict = {"model": self.model, "max_tokens": 4000,
                        "system": WEB_SYSTEM_PROMPT if web else SYSTEM_PROMPT, "messages": messages}
        if web:
            kwargs["tools"] = [{"type": WEB_TOOL_TYPE, "name": "web_search",
                                "max_uses": min(2 * len(items), 10)}]
        text = ""
        for _ in range(4):  # the API may pause long search turns; continue them a few times
            msg = self.client.messages.create(**kwargs)
            text += "".join(getattr(b, "text", "") or "" for b in msg.content)
            usage = getattr(getattr(msg, "usage", None), "server_tool_use", None)
            self.web_searches += int(getattr(usage, "web_search_requests", 0) or 0)
            if getattr(msg, "stop_reason", None) != "pause_turn":
                break
            messages.append({"role": "assistant", "content": msg.content})
        return parse_response(text)
