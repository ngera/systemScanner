"""Optional AI lookup for files behind security findings: "what is this program, and is it safe?"

Off unless turned on (``sysscan security --ai``, ``SYSSCAN_SECURITY_AI=true`` or ``[security] ai = true``).
Uses the same provider settings as software descriptions:

  - Claude: researches each file with the web_search tool (``SYSSCAN_SECURITY_AI_WEB``, on by default) and
    returns the pages it used.
  - Ollama: model knowledge only (no web search), so answers on rare files are often "unknown".

Privacy: only facts about the *file* are sent: its name, the folder it's in with your user name replaced by
%USERPROFILE%, digital signature and signer, the version info embedded in the file (company, product,
description, original name, version), its SHA-256 hash, and the finding's title. Never sent: your user name,
computer name, IP addresses, remote-session details, other findings, or the file's contents.

Answers are cached by hash for 30 days (7 days for "unknown"), so the same file isn't looked up every time.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from sysscan.describe.ai import WEB_TOOL_TYPE, MissingAPIKey, _json_arrays, build_describer, normalize_provider
from sysscan.security.analyze import ALERT, WARN, Finding
from sysscan.security.probe import signer_name
from sysscan.winutil import parse_iso, utcnow

log = logging.getLogger(__name__)

VERDICTS = ("legitimate", "potentially_unwanted", "suspicious", "malicious", "unknown")
VERDICT_LABEL = {"legitimate": "Legitimate", "potentially_unwanted": "Potentially unwanted",
                 "suspicious": "Suspicious", "malicious": "Likely malicious", "unknown": "Unknown"}

SYSTEM_PROMPT = """You are a careful Windows security analyst helping a non-technical person understand files that a
local security check flagged (remote access, monitoring/keylogging signs, auto-start programs, open ports).

For each item you get facts about one file: file name, folder (user name replaced by %USERPROFILE%),
digital signature status and signer, the version info embedded in the file, its SHA-256 hash, and why it was
flagged. You never see the file's contents.

For each item decide:
- what: one or two plain sentences: what this program is and what it normally does.
- maker: the company or project that makes it, or null if not confident.
- verdict: one of
    legitimate            a known, genuine program from its real maker
    potentially_unwanted  genuine but often unwanted or abused (remote-admin tools, adware, "PC cleaners")
    suspicious            facts don't fit the genuine program (wrong signer, odd folder, unsigned copy of a known
                          name, random file name) or matches known malware naming
    malicious             known malware, or the hash/name is documented as malware by reputable sources
    unknown               not enough information
- confidence: "high", "medium" or "low".
- why: one or two sentences with the concrete reasons (signer, folder, hash results, sources).
- advice: 1 to 4 short, concrete steps for this file (what to check, how to remove it safely). No generic filler.

Rules: Never call something legitimate just because of its name: impersonators copy names. A valid signature
from the expected company is strong evidence; an unsigned file in a user folder using a famous name is a red
flag. If unsure, say "unknown" with low confidence rather than guessing.

Output ONLY a JSON array, one object per item:
[{"id": <int>, "what": "...", "maker": "..." | null, "verdict": "...", "confidence": "high"|"medium"|"low",
  "why": "...", "advice": ["..."], "sources": ["<url>", ...]}]"""

WEB_ADDENDUM = """

Use the web_search tool (at most 3 searches per item): search the SHA-256 hash, the exact file name with its
signer or folder, and the product name. Prefer the vendor's site, Microsoft, VirusTotal, Hybrid Analysis,
MalwareBazaar, and reputable security vendors' write-ups. List the pages you relied on in "sources"."""

NO_WEB_ADDENDUM = """

You cannot browse the web. Rely only on what you know; set "sources" to []. For files you don't clearly know,
answer "unknown"."""

_USER_DIR = re.compile(r"^[A-Za-z]:\\Users\\(?!(?:Public|Default|All Users)\\)[^\\]+", re.I)
_ANY_USER_DIR = re.compile(r"\\Users\\(?!Public\\|Default\\|All Users\\)[^\\]+", re.I)
_EXECUTABLE = re.compile(r"\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js|msi|cpl|ocx)$", re.I)
CACHE_DAYS, UNKNOWN_CACHE_DAYS = 30, 7


def redact_path(path: str) -> str:
    """Replace the user-profile part of a path: C:\\Users\\neeraj\\AppData → %USERPROFILE%\\AppData."""
    p = _USER_DIR.sub("%USERPROFILE%", path or "")
    return _ANY_USER_DIR.sub(r"\\Users\\<user>", p)


def folder_of(path: str) -> str:
    p = redact_path(path)
    return p.rsplit("\\", 1)[0] if "\\" in p else ""


def file_payload(file: dict[str, Any], finding: Finding) -> dict[str, Any]:
    """Exactly what is sent for one file. Kept small and free of personal details."""
    out = {
        "file": file.get("name"),
        "folder": folder_of(str(file.get("path") or "")),
        "signature": file.get("sig_status") or "unknown",
        "signer": signer_name(str(file.get("signer") or "")) or None,
        "company": file.get("company") or None,
        "product": file.get("product") or None,
        "description": file.get("description") or None,
        "original_name": file.get("original_name") or None,
        "version": file.get("version") or None,
        "sha256": file.get("sha256") or None,
        "flagged_because": finding.title if finding.area != "sessions" else finding.area,
    }
    return {k: v for k, v in out.items() if v}


def cache_key(file: dict[str, Any]) -> str:
    if file.get("sha256"):
        return "secai:sha256:" + str(file["sha256"]).lower()
    return "secai:name:" + str(file.get("name") or "").lower() + "|" + signer_name(str(file.get("signer") or "")).lower()


def candidates(findings: list[Finding]) -> list[tuple[Finding, dict[str, Any]]]:
    """Files worth looking up: real executables behind untrusted alert/warn findings (sessions excluded).
    One entry per distinct file (by hash); see ``groups`` for every finding that shares it."""
    return [items[0] for items in groups(findings).values()]


def groups(findings: list[Finding]) -> dict[str, list[tuple[Finding, dict[str, Any]]]]:
    out: dict[str, list[tuple[Finding, dict[str, Any]]]] = {}
    for f in findings:
        if f.status not in (ALERT, WARN) or f.trusted or f.area == "sessions":
            continue
        for file in f.files:
            if not file.get("exists") or file.get("folder") or not _EXECUTABLE.search(str(file.get("name") or "")):
                continue
            if file.get("sig_status") == "Valid" and signer_name(str(file.get("signer") or "")).startswith("Microsoft"):
                continue  # genuine Windows files: the finding is about how they're used, not what they are
            out.setdefault(cache_key(file), []).append((f, file))
    return out


def _attach(group: list[tuple[Finding, dict[str, Any]]], ans: dict[str, Any]) -> None:
    for f, file in group:
        file["ai"] = dict(ans)
        apply_verdict(f, ans)


def parse_answers(text: str) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for arr in _json_arrays(text):
        for obj in arr:
            if not isinstance(obj, dict) or not isinstance(obj.get("id"), int):
                continue
            verdict = str(obj.get("verdict") or "unknown").strip().lower().replace(" ", "_")
            conf = str(obj.get("confidence") or "low").strip().lower()
            advice = obj.get("advice") or []
            sources = obj.get("sources") or []
            out[obj["id"]] = {
                "what": str(obj.get("what") or "").strip()[:600],
                "maker": (str(obj["maker"]).strip()[:120] or None) if obj.get("maker") else None,
                "verdict": verdict if verdict in VERDICTS else "unknown",
                "confidence": conf if conf in ("high", "medium", "low") else "low",
                "why": str(obj.get("why") or "").strip()[:800],
                "advice": [str(a).strip()[:300] for a in (advice if isinstance(advice, list) else [advice]) if str(a).strip()][:5],
                "sources": [str(s).strip() for s in (sources if isinstance(sources, list) else [sources])
                            if str(s).strip().startswith(("http://", "https://"))][:6],
            }
        if out:
            break
    return out


def _ask(describer, items: list[dict[str, Any]], web: bool) -> tuple[dict[int, dict[str, Any]], int]:
    """Send one batch. Returns answers and the number of web searches used."""
    user = json.dumps(items, ensure_ascii=False, indent=1)
    if not web:
        return parse_answers(describer.complete(SYSTEM_PROMPT + NO_WEB_ADDENDUM, user)), 0
    messages: list[dict] = [{"role": "user", "content": user}]
    kwargs: dict = {"model": describer.model, "max_tokens": 6000, "system": SYSTEM_PROMPT + WEB_ADDENDUM,
                    "messages": messages,
                    "tools": [{"type": WEB_TOOL_TYPE, "name": "web_search", "max_uses": min(3 * len(items), 15)}]}
    text, searches = "", 0
    for _ in range(5):  # long search turns may pause; continue them
        msg = describer.client.messages.create(**kwargs)
        text += "".join(getattr(b, "text", "") or "" for b in msg.content)
        usage = getattr(getattr(msg, "usage", None), "server_tool_use", None)
        searches += int(getattr(usage, "web_search_requests", 0) or 0)
        if getattr(msg, "stop_reason", None) != "pause_turn":
            break
        messages.append({"role": "assistant", "content": msg.content})
    return parse_answers(text), searches


def _cached(store, key: str) -> dict[str, Any] | None:
    if store is None:
        return None
    hit = store.get_description(key)
    if not hit:
        return None
    try:
        data = json.loads(hit.description)
    except (ValueError, TypeError):
        return None
    when = parse_iso(data.get("checked_at"))
    max_age = UNKNOWN_CACHE_DAYS if data.get("verdict") == "unknown" else CACHE_DAYS
    if when is None or utcnow() - when > timedelta(days=max_age):
        return None
    return data | {"cached": True}


def apply_verdict(f: Finding, ai: dict[str, Any]) -> None:
    """A confident "malicious" raises a warning to an alert. AI never lowers a status."""
    if ai.get("verdict") == "malicious" and ai.get("confidence") in ("high", "medium") and f.status == WARN:
        f.status = ALERT
        f.explanation += " The AI lookup rates this file as likely malicious."


def lookup(findings: list[Finding], cfg, store=None, progress: Callable[[str], None] = lambda _m: None,
           describer_factory=None) -> tuple[str | None, list[str]]:
    """Attach ``file["ai"]`` answers to findings. Returns (provider label or None, notes for the report)."""
    notes: list[str] = []
    todo = groups(findings)
    if not todo:
        return None, notes
    provider = normalize_provider(cfg.ai.provider)
    web = provider == "claude" and cfg.security_ai_web
    label = "Claude with web search" if web else ("Claude (no web search)" if provider == "claude"
                                                   else f"Ollama {cfg.ai.model} (no web search)")
    pending = []
    for key, group in todo.items():
        hit = _cached(store, key)
        if hit:
            _attach(group, hit)
        else:
            pending.append(group)
    if not pending:
        return label, notes
    cap = max(1, int(cfg.security_ai_max_items))
    if len(pending) > cap:
        notes.append(f"AI lookup: checked {cap} of {len(pending)} files this time (SYSSCAN_SECURITY_AI_MAX_ITEMS).")
        pending = pending[:cap]
    try:
        describer = (describer_factory or build_describer)(cfg.ai)
    except MissingAPIKey as exc:
        return None, [str(exc)]
    except Exception as exc:
        log.exception("security AI setup failed")
        return None, [f"AI lookup unavailable: {exc}"]

    searches, answered = 0, 0
    for start in range(0, len(pending), 5):
        batch = pending[start:start + 5]
        progress(f"Security: AI looking up {', '.join(str(g[0][1].get('name')) for g in batch)}")
        try:
            answers, used = _ask(describer, [{"id": i} | file_payload(g[0][1], g[0][0]) for i, g in enumerate(batch)],
                                 web)
        except Exception as exc:
            log.exception("security AI request failed")
            notes.append(f"AI lookup failed: {exc}")
            break
        searches += used
        for i, group in enumerate(batch):
            ans = answers.get(i)
            if not ans:
                continue
            ans |= {"checked_at": utcnow().isoformat(), "provider": label}
            _attach(group, ans)
            answered += 1
            file = group[0][1]
            if store is not None:
                store.put_description(cache_key(file), json.dumps(ans, ensure_ascii=False),
                                      "ai-web" if web else "ai", model=getattr(cfg.ai, "model", None), now=utcnow())
    notes.append(f"AI lookup ({label}): {answered} file(s) checked"
                 + (f", {searches} web search(es)" if searches else "") + ".")
    return label, notes
