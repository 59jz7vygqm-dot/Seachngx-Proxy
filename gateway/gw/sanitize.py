"""Hygiene fuer eingehende Suchergebnisse.

Das ist keine Sicherheitsgrenze gegen Prompt Injection. Es entfernt nur
unsichtbare Zeichen und deckelt Laengen, damit Treffer nicht als getarnte
Anweisungen im LLM-Kontext landen oder diesen sprengen.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

# Zero-Width, Bidi-Overrides, Tag-Characters: alles Mittel, um Text zu
# verstecken, der fuer das LLM trotzdem sichtbar ist.
_INVISIBLE = re.compile(
    r"[​-‏‪-‮⁠-⁤⁦-⁯﻿\U000e0000-\U000e007f]"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS = re.compile(r"[ \t]{3,}")


def clean_text(value: Any, max_len: int) -> str:
    if value is None:
        return ""
    text = unicodedata.normalize("NFKC", str(value))
    text = _INVISIBLE.sub("", text)
    text = _CONTROL.sub(" ", text)
    text = _WS.sub("  ", text).strip()
    if len(text) > max_len:
        text = text[:max_len].rstrip() + " […]"
    return text


def clean_url(value: Any) -> str:
    url = clean_text(value, 2048)
    if not url.startswith(("http://", "https://")):
        return ""
    return url


def sanitize_results(payload: dict, max_results: int, max_content_len: int) -> dict:
    """Reduziert die SearXNG-Antwort auf das, was das LLM wirklich braucht."""
    results = []
    for item in (payload.get("results") or [])[:max_results]:
        if not isinstance(item, dict):
            continue
        url = clean_url(item.get("url"))
        if not url:
            continue
        results.append(
            {
                "url": url,
                "title": clean_text(item.get("title"), 300),
                "content": clean_text(item.get("content"), max_content_len),
                "engine": clean_text(item.get("engine"), 64),
                "publishedDate": clean_text(item.get("publishedDate"), 64) or None,
                "score": item.get("score"),
            }
        )

    return {
        "query": clean_text(payload.get("query"), 512),
        "number_of_results": len(results),
        "results": results,
        "answers": [clean_text(a, 1000) for a in (payload.get("answers") or [])[:5]],
        "corrections": [],
        "infoboxes": [],
        "suggestions": [clean_text(s, 200) for s in (payload.get("suggestions") or [])[:5]],
        "unresponsive_engines": payload.get("unresponsive_engines") or [],
    }
