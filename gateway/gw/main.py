"""Privacy-Gateway vor SearXNG.

Spricht nach aussen die SearXNG-JSON-API, damit OpenWebUI es ohne Anpassung
als Suchmaschine verwenden kann. Nach innen: Filter -> Cache -> SearXNG.
Der Container hat selbst keinen Weg ins Internet (siehe docker-compose.yml).
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from .cache import Cache, cache_key
from .clients import FilterClient, SearxClient
from .config import settings
from .logging_setup import emit, query_for_log, setup
from .responses import block_response, empty_response
from .sanitize import sanitize_results

setup()
settings.validate()

state: dict = {}


@asynccontextmanager
async def lifespan(_: FastAPI):
    state["filter"] = FilterClient(settings.filter_url, settings.filter_timeout)
    state["searx"] = SearxClient(settings.searx_url, settings.upstream_timeout)
    state["cache"] = Cache(settings.valkey_url, settings.cache_ttl)
    emit(
        "gateway.start",
        block_response=settings.block_response,
        log_queries=settings.log_queries,
        cache_ttl=settings.cache_ttl,
    )
    yield
    await state["filter"].close()
    await state["searx"].close()
    await state["cache"].close()


app = FastAPI(
    title="SearXNG Privacy Gateway",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


@app.get("/healthz")
async def healthz() -> dict:
    return {
        "status": "ok",
        "filter": await state["filter"].healthy(),
        "searxng": await state["searx"].healthy(),
    }


async def _handle(
    q: str,
    params: dict,
    request_id: str,
) -> JSONResponse:
    t0 = time.perf_counter()

    q = (q or "").strip()
    if not q:
        return JSONResponse(empty_response(""))
    if len(q) > settings.max_query_len:
        emit("gateway.reject", request_id=request_id, reason="query_too_long", length=len(q))
        raise HTTPException(status_code=413, detail="Suchanfrage zu lang")

    language = params.get("language") or settings.default_language
    lang_code = str(language).split("-")[0].lower()

    # 1) Filter. Faellt er aus, wird NICHT gesucht - fail closed.
    try:
        decision = await state["filter"].analyze(q, lang_code)
    except (httpx.HTTPError, ValueError) as exc:
        emit("gateway.filter_unavailable", request_id=request_id, error=str(exc))
        raise HTTPException(
            status_code=503,
            detail="Datenschutzfilter nicht erreichbar - Suche abgebrochen",
        ) from exc

    redacted = decision.get("redacted_text", "")
    log_query = query_for_log(q, redacted, settings.log_queries)
    finding_types = sorted({f["type"] for f in decision.get("findings", [])})

    # 2) Blockieren oder weitergeben.
    if decision.get("action") == "block":
        blocking = decision.get("blocking_types", [])
        emit(
            "gateway.blocked",
            request_id=request_id,
            query=log_query,
            blocking_types=blocking,
            duration_ms=round((time.perf_counter() - t0) * 1000, 1),
        )
        payload = block_response(redacted, blocking, settings.block_response)
        status = 422 if settings.block_response == "error" else 200
        return JSONResponse(
            payload,
            status_code=status,
            headers={"X-Privacy-Filter": "blocked", "X-Request-Id": request_id},
        )

    # Ab hier verlaesst nur noch 'outbound' den Stack. Bei action=redact ist
    # das die geschwaerzte Fassung, nicht das Original.
    outbound = redacted if decision.get("action") == "redact" else q

    # 3) Cache.
    key = cache_key(outbound, params)
    cached = await state["cache"].get(key)
    if cached is not None:
        emit(
            "gateway.hit",
            request_id=request_id,
            query=log_query,
            cache="hit",
            findings=finding_types or None,
            results=cached.get("number_of_results"),
            duration_ms=round((time.perf_counter() - t0) * 1000, 1),
        )
        return JSONResponse(
            cached, headers={"X-Privacy-Filter": "cache", "X-Request-Id": request_id}
        )

    # 4) Upstream.
    try:
        raw = await state["searx"].search(outbound, params)
    except httpx.HTTPError as exc:
        emit("gateway.upstream_error", request_id=request_id, error=str(exc))
        raise HTTPException(status_code=502, detail="SearXNG nicht erreichbar") from exc

    payload = sanitize_results(raw, settings.max_results, settings.max_content_len)
    payload["query"] = outbound
    await state["cache"].set(key, payload)

    emit(
        "gateway.hit",
        request_id=request_id,
        query=log_query,
        cache="miss",
        action=decision.get("action"),
        findings=finding_types or None,
        results=payload["number_of_results"],
        duration_ms=round((time.perf_counter() - t0) * 1000, 1),
    )
    return JSONResponse(
        payload,
        headers={
            "X-Privacy-Filter": decision.get("action", "allow"),
            "X-Request-Id": request_id,
        },
    )


def _collect_params(src) -> dict:
    return {
        "categories": src.get("categories"),
        "engines": src.get("engines"),
        "language": src.get("language"),
        "pageno": src.get("pageno"),
        "time_range": src.get("time_range"),
        "safesearch": src.get("safesearch"),
    }


@app.get("/search")
async def search_get(request: Request, q: str = Query(default="")) -> JSONResponse:
    request_id = uuid.uuid4().hex[:12]
    return await _handle(q, _collect_params(request.query_params), request_id)


@app.post("/search")
async def search_post(request: Request) -> JSONResponse:
    request_id = uuid.uuid4().hex[:12]
    ctype = request.headers.get("content-type", "")
    if ctype.startswith("application/json"):
        body = await request.json()
    else:
        body = dict(await request.form())
    q = str(body.get("q", ""))
    return await _handle(q, _collect_params(body), request_id)
