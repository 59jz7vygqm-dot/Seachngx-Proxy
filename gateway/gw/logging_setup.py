from __future__ import annotations

import hashlib
import json
import logging
import sys
from typing import Any


def setup(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    # uvicorn.access loggt die volle Request-Line samt Query-String.
    # Genau das soll hier nicht passieren.
    logging.getLogger("uvicorn.access").disabled = True


def query_for_log(raw: str, redacted: str, mode: str) -> str | None:
    if mode == "none":
        return None
    if mode == "hashed":
        return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    if mode == "raw":
        return raw
    return redacted  # Default


def emit(event: str, **fields: Any) -> None:
    payload = {"event": event, **{k: v for k, v in fields.items() if v is not None}}
    logging.getLogger("gateway").info(json.dumps(payload, ensure_ascii=False))
