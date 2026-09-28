"""AI enrichment: plain-language descriptions and publishers for software that the built-in rules
and the software's own metadata couldn't explain.

Providers:
  - claude  — Anthropic Messages API (optional web-search second pass)
  - ollama  — local Ollama HTTP API (nothing leaves the machine)

Privacy (Claude): only the display name, publisher (if known), version, category and (if present) the
publisher's own one-line description / local hints are sent. Nothing else about the machine leaves it.

API key lookup (Claude only): ANTHROPIC_API_KEY (environment or a .env file) → Windows Credential Manager.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sysscan.config import AIConfig

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

DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "llama3.2"


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


class MissingAPIKey(Exception):
    """Claude is selected but no Anthropic API key is configured."""


def normalize_provider(name: str | None) -> str:
    raw = (name or "claude").strip().lower()
    if raw in ("ollama", "local"):
        return "ollama"
    if raw in ("claude", "anthropic"):
        return "claude"
    return raw or "claude"


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


def ollama_status(base_url: str = DEFAULT_OLLAMA_URL, timeout: float = 2.0) -> tuple[bool, str]:
    """Return (reachable, detail). detail is a short status string for `sysscan collectors`."""
    url = f"{base_url.rstrip('/')}/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        names = [m.get("name", "") for m in data.get("models", []) if isinstance(m, dict)]
        if not names:
            return True, "reachable (no models pulled yet — run `ollama pull …`)"
        shown = ", ".join(names[:5])
        extra = f" (+{len(names) - 5} more)" if len(names) > 5 else ""
        return True, f"reachable ({len(names)} model(s): {shown}{extra})"
    except urllib.error.URLError as exc:
        return False, f"not reachable at {base_url} ({exc.reason})"
    except Exception as exc:
        return False, f"not reachable at {base_url} ({exc})"


def build_describer(ai: AIConfig):
    """Build the configured provider. Raises MissingAPIKey / ImportError for Claude setup problems."""
    provider = normalize_provider(ai.provider)
    if provider == "ollama":
        return OllamaDescriber(ai.model, ai.base_url)
    if provider != "claude":
        raise ValueError(f"Unknown AI provider {ai.provider!r} (use 'claude' or 'ollama')")
    key = get_api_key()
    if not key:
        raise MissingAPIKey(
            "AI is enabled but no API key was found. Put ANTHROPIC_API_KEY in a .env "
            "file (see .env.example) or run `sysscan set-key`."
        )
    return ClaudeDescriber(key, ai.model)


class ClaudeDescriber:
    def __init__(self, api_key: str, model: str):
        import anthropic

        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.web_searches = 0
        self.provider = "claude"

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


class OllamaDescriber:
    """Talk to a local Ollama daemon via /api/chat. No API key; nothing leaves the machine."""

    def __init__(self, model: str, base_url: str = DEFAULT_OLLAMA_URL, timeout: float = 180.0):
        self.model = model or DEFAULT_OLLAMA_MODEL
        self.base_url = (base_url or DEFAULT_OLLAMA_URL).rstrip("/")
        self.timeout = timeout
        self.provider = "ollama"

    def describe(self, items: list[AIItem], web: bool = False) -> dict[int, AIAnswer]:
        if web:
            raise RuntimeError("Web search is only available with the Claude provider.")
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_message(items)},
            ],
            "stream": False,
            "options": {"temperature": 0.1},
        }
        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama HTTP {exc.code}: {body.strip() or exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Cannot reach Ollama at {self.base_url} ({exc.reason}). "
                "Is `ollama serve` running?"
            ) from exc
        text = (data.get("message") or {}).get("content") or ""
        return parse_response(text)
