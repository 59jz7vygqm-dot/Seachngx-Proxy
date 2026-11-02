from __future__ import annotations

import os
from dataclasses import dataclass

_VALID_BLOCK_RESPONSES = ("inform", "empty", "error")
_VALID_LOG_MODES = ("none", "redacted", "hashed", "raw")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    filter_url: str = os.getenv("FILTER_URL", "http://filter:8001")
    searx_url: str = os.getenv("SEARX_URL", "http://searxng:8080")
    valkey_url: str = os.getenv("VALKEY_URL", "redis://valkey:6379/0")

    block_response: str = os.getenv("GATEWAY_BLOCK_RESPONSE", "inform").lower()
    log_queries: str = os.getenv("GATEWAY_LOG_QUERIES", "redacted").lower()
    default_language: str = os.getenv("GATEWAY_DEFAULT_LANG", "de")

    cache_ttl: int = _int("GATEWAY_CACHE_TTL", 900)
    max_query_len: int = _int("GATEWAY_MAX_QUERY_LEN", 512)
    max_results: int = _int("GATEWAY_MAX_RESULTS", 20)
    max_content_len: int = _int("GATEWAY_MAX_CONTENT_LEN", 2000)
    upstream_timeout: int = _int("GATEWAY_UPSTREAM_TIMEOUT", 20)
    filter_timeout: int = _int("GATEWAY_FILTER_TIMEOUT", 15)

    def validate(self) -> None:
        if self.block_response not in _VALID_BLOCK_RESPONSES:
            raise ValueError(
                f"GATEWAY_BLOCK_RESPONSE={self.block_response!r}, "
                f"erlaubt: {_VALID_BLOCK_RESPONSES}"
            )
        if self.log_queries not in _VALID_LOG_MODES:
            raise ValueError(
                f"GATEWAY_LOG_QUERIES={self.log_queries!r}, erlaubt: {_VALID_LOG_MODES}"
            )


settings = Settings()
