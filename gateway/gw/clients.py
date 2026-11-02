"""HTTP-Clients fuer Filter und SearXNG."""

from __future__ import annotations

import httpx


class FilterClient:
    def __init__(self, base_url: str, timeout: int) -> None:
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout)

    async def analyze(self, text: str, language: str) -> dict:
        resp = await self._client.post(
            "/analyze", json={"text": text, "language": language}
        )
        resp.raise_for_status()
        return resp.json()

    async def healthy(self) -> bool:
        try:
            resp = await self._client.get("/healthz", timeout=3)
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()


class SearxClient:
    def __init__(self, base_url: str, timeout: int) -> None:
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout)

    async def search(self, query: str, params: dict) -> dict:
        payload = {k: v for k, v in params.items() if v not in (None, "")}
        payload["q"] = query
        payload["format"] = "json"
        resp = await self._client.get("/search", params=payload)
        resp.raise_for_status()
        return resp.json()

    async def healthy(self) -> bool:
        try:
            resp = await self._client.get("/healthz", timeout=3)
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()
