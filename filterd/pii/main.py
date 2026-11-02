"""PII-Filter-Service.

Nimmt einen Text entgegen, liefert eine Policy-Entscheidung zurueck.
Kennt weder SearXNG noch das Internet und hat keinen Egress-Pfad.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .policy import Policy, evaluate

POLICY_PATH = os.getenv("FILTER_POLICY", "/app/config/policy.yml")
DEFAULT_LANG = os.getenv("FILTER_DEFAULT_LANG", "de")

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("filter")

@asynccontextmanager
async def lifespan(_: FastAPI):
    policy()
    # Modell beim Start laden, damit der erste echte Request nicht haengt.
    from .engine import get_analyzer

    get_analyzer()
    log.info(json.dumps({"event": "filter.ready"}))
    yield


app = FastAPI(
    title="PII Filter",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

_policy: Policy | None = None


def policy() -> Policy:
    global _policy
    if _policy is None:
        _policy = Policy.load(POLICY_PATH)
    return _policy


class AnalyzeRequest(BaseModel):
    text: str = Field(max_length=4096)
    language: str = DEFAULT_LANG




@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
def analyze_endpoint(req: AnalyzeRequest) -> dict:
    from .engine import analyze

    t0 = time.perf_counter()
    findings = analyze(req.text, req.language)
    decision = evaluate(req.text, findings, policy())
    took = (time.perf_counter() - t0) * 1000

    log.info(
        json.dumps(
            {
                "event": "filter.analyze",
                "language": req.language,
                "action": decision.action,
                "types": sorted({f.entity_type for f in decision.findings}),
                "duration_ms": round(took, 1),
            }
        )
    )
    out = decision.to_dict()
    out["duration_ms"] = round(took, 1)
    return out


@app.post("/reload")
def reload_policy() -> dict[str, str]:
    """Policy neu einlesen, ohne das NLP-Modell neu zu laden."""
    global _policy
    _policy = Policy.load(POLICY_PATH)
    log.info(json.dumps({"event": "filter.policy_reloaded"}))
    return {"status": "reloaded"}
