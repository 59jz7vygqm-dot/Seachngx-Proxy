"""Ergebnis-Cache.

Gespeichert wird nur der Hash der *gefilterten* Query als Schluessel und die
bereits bereinigte Antwort als Wert. Die Original-Query landet nie im Cache.
Jeder Treffer spart eine Anfrage ans Internet - der billigste Privacy-Gewinn
im ganzen Stack.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

log = logging.getLogger("gateway.cache")


def cache_key(query: str, params: dict[str, Any]) -> str:
    material = json.dumps(
        {"q": query, **{k: v for k, v in sorted(params.items()) if v not in (None, "")}},
        sort_keys=True,
        ensure_ascii=False,
    )
    return "q:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


class Cache:
    def __init__(self, url: str, ttl: int) -> None:
        self.ttl = ttl
        self._client: Any | None = None
        if ttl > 0:
            # Lazy import: so bleibt cache_key() ohne redis-Paket testbar.
            import redis.asyncio as redis

            self._client = redis.from_url(url, decode_responses=True)

    @property
    def enabled(self) -> bool:
        return self._client is not None and self.ttl > 0

    async def get(self, key: str) -> dict | None:
        if not self.enabled:
            return None
        try:
            raw = await self._client.get(key)  # type: ignore[union-attr]
        except Exception as exc:  # Cache-Ausfall darf die Suche nicht killen
            log.warning(json.dumps({"event": "cache.error", "op": "get", "error": str(exc)}))
            return None
        return json.loads(raw) if raw else None

    async def set(self, key: str, value: dict) -> None:
        if not self.enabled:
            return
        try:
            await self._client.setex(key, self.ttl, json.dumps(value, ensure_ascii=False))  # type: ignore[union-attr]
        except Exception as exc:
            log.warning(json.dumps({"event": "cache.error", "op": "set", "error": str(exc)}))

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
