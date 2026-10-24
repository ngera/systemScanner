"""LLM enrichment for folder cleanup advice.

Looks at a folder's path plus a short sample of its immediate children (names only — no file
contents) and asks Claude or Ollama whether it is Windows-related, a standard app folder, a
cache, etc., then updates the delete recommendation.

Built-in ``keep`` / ``safe`` rules are left alone. AI is used for ``unknown`` and ``caution``
folders (and cached so the same path is not re-asked).
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sysscan.config import AIConfig
from sysscan.describe.ai import MissingAPIKey, _json_arrays, build_describer, normalize_provider
from sysscan.folderadvice import FolderAdvice
from sysscan.foldersize import FolderSize
from sysscan.store import Store
from sysscan.winutil import utcnow

log = logging.getLogger(__name__)

FOLDER_SYSTEM_PROMPT = """You classify Windows folders for a disk-cleanup advisor aimed at non-technical users.

For each folder you get: full path, folder name, size_bytes (optional), and "children" — a sample of
immediate child names prefixed with dir: or file:. These are names only; you never see file contents.

Decide:
- kind: one of windows, app, cache, logs, user_data, oem, developer, other
- safety:
  - safe — temporary/cache/logs that can usually be cleared with little risk of breaking Windows or apps
  - caution — review first; partial cleanup may be OK (e.g. OEM leftovers, installer caches)
  - keep — do not delete (Windows system data, installed app data still needed, user documents)
- reason: ONE short sentence (max ~30 words) explaining the advice in plain language
- confidence: "high" only when the path/children clearly identify it; otherwise "low"

Be conservative. If unsure, prefer caution or keep — never safe.
Do not invent contents that the path and children do not suggest.
Never recommend deleting Windows, Program Files, Users, or active app data as safe.

Output ONLY a JSON array, one object per item:
[{"id": <int>, "kind": "<kind>", "safety": "safe"|"caution"|"keep", "reason": "<text>", "confidence": "high"|"low"}]"""

_VALID_SAFETY = {"safe", "caution", "keep"}
_VALID_KIND = {"windows", "app", "cache", "logs", "user_data", "oem", "developer", "other"}
_CHILD_LIMIT = 40


@dataclass
class FolderAIItem:
    id: int
    path: Path
    bytes: int
    children: list[str]


@dataclass
class FolderAIAnswer:
    safety: str
    reason: str
    kind: str | None = None
    confidence: str = "high"


def cache_key(path: Path) -> str:
    return "folder:" + str(path).replace("\\", "/").lower().rstrip("/")


def sample_children(path: Path, limit: int = _CHILD_LIMIT) -> list[str]:
    """Return up to ``limit`` immediate child labels (``dir:Name`` / ``file:Name``)."""
    out: list[str] = []
    try:
        with os.scandir(path) as it:
            for entry in it:
                if len(out) >= limit:
                    break
                try:
                    kind = "dir" if entry.is_dir(follow_symlinks=False) else "file"
                except OSError:
                    continue
                # Skip very long / odd names
                name = entry.name.replace("\n", " ").strip()
                if not name or len(name) > 120:
                    continue
                out.append(f"{kind}:{name}")
    except OSError:
        pass
    return out


def build_folder_user_message(items: list[FolderAIItem]) -> str:
    payload = [
        {
            "id": it.id,
            "path": str(it.path),
            "name": it.path.name,
            "size_bytes": it.bytes,
            "children": it.children,
        }
        for it in items
    ]
    return "Classify these folders:\n" + json.dumps(payload, ensure_ascii=False, indent=1)


def parse_folder_response(text: str) -> dict[int, FolderAIAnswer]:
    rows = next(_json_arrays(text), [])
    out: dict[int, FolderAIAnswer] = {}
    for r in rows:
        try:
            safety = str(r.get("safety") or "").strip().lower()
            reason = " ".join(str(r.get("reason") or "").split())
            kind = str(r.get("kind") or "").strip().lower() or None
            conf = str(r.get("confidence") or "high").strip().lower()
            if safety not in _VALID_SAFETY or not reason:
                continue
            if kind and kind not in _VALID_KIND:
                kind = "other"
            if conf == "low" and safety == "safe":
                safety = "caution"  # never treat a low-confidence guess as safe
            out[int(r["id"])] = FolderAIAnswer(safety=safety, reason=reason, kind=kind, confidence=conf)
        except (AttributeError, KeyError, TypeError, ValueError):
            continue
    return out


def _needs_ai(folder: FolderSize) -> bool:
    return folder.safety in ("unknown", "caution")


def _advice_from_cache(raw: str, source: str) -> FolderAdvice | None:
    try:
        data = json.loads(raw)
        safety = data.get("safety")
        reason = data.get("reason")
        if safety in _VALID_SAFETY and reason:
            return FolderAdvice(
                safety=safety,
                reason=reason,
                source=source,
                kind=data.get("kind"),
            )
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return None


def enrich_folders_with_ai(
    folders: list[FolderSize],
    ai: AIConfig,
    store: Store | None = None,
    *,
    progress: Callable[[str], None] | None = None,
    describer_factory=None,
) -> tuple[list[FolderSize], list[str]]:
    """Return folders with AI-updated advice, plus status messages for the console."""
    messages: list[str] = []
    factory = describer_factory or build_describer

    pending: list[tuple[int, FolderSize, list[str]]] = []
    updated = list(folders)

    for i, folder in enumerate(folders):
        if not _needs_ai(folder):
            continue
        key = cache_key(folder.path)
        if store:
            cached = store.get_description(key)
            if cached and cached.source.startswith("ai"):
                advice = _advice_from_cache(cached.description, cached.source)
                if advice:
                    updated[i] = FolderSize(folder.path, folder.bytes, folder.errors, advice)
                    continue
        children = sample_children(folder.path)
        pending.append((i, folder, children))

    if not pending:
        return updated, messages

    cap = max(1, ai.max_items_per_run)
    if len(pending) > cap:
        messages.append(f"AI folder classify: capping at {cap} of {len(pending)} folders this run")
        pending = pending[:cap]

    try:
        describer = factory(ai)
    except MissingAPIKey as exc:
        messages.append(str(exc))
        return updated, messages
    except Exception as exc:
        log.exception("folder AI setup failed")
        messages.append(f"AI folder classify unavailable: {exc}")
        return updated, messages

    batch_size = max(1, ai.batch_size)
    answered = 0
    for start in range(0, len(pending), batch_size):
        batch = pending[start:start + batch_size]
        items = [
            FolderAIItem(id=j, path=folder.path, bytes=folder.bytes, children=children)
            for j, (_, folder, children) in enumerate(batch)
        ]
        if progress:
            names = ", ".join(it.path.name for it in items[:4])
            more = f" (+{len(items) - 4})" if len(items) > 4 else ""
            progress(f"AI classifying folders: {names}{more}")
        try:
            text = describer.complete(FOLDER_SYSTEM_PROMPT, build_folder_user_message(items))
            answers = parse_folder_response(text)
        except Exception as exc:
            log.exception("folder AI request failed")
            messages.append(f"AI folder classify failed: {exc}")
            break

        id_to_index = {j: idx for j, (idx, _, _) in enumerate(batch)}
        for j, ans in answers.items():
            if j not in id_to_index:
                continue
            idx = id_to_index[j]
            folder = updated[idx]
            source = "ai-low" if ans.confidence == "low" else "ai"
            # Don't let AI mark something "safe" when the built-in rule said "caution"
            safety = ans.safety
            if folder.safety == "caution" and safety == "safe":
                safety = "caution"
            advice = FolderAdvice(safety=safety, reason=ans.reason, source=source, kind=ans.kind)
            updated[idx] = FolderSize(folder.path, folder.bytes, folder.errors, advice)
            answered += 1
            if store:
                payload = json.dumps({"safety": safety, "reason": ans.reason, "kind": ans.kind},
                                     ensure_ascii=False)
                store.put_description(
                    cache_key(folder.path), payload, source,
                    model=getattr(ai, "model", None), now=utcnow(),
                )

    provider = normalize_provider(ai.provider)
    messages.append(f"AI folder classify ({provider}): updated {answered} folder(s)")
    return updated, messages
