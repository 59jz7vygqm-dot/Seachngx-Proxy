from __future__ import annotations

import os
import socket
from dataclasses import dataclass

VERSION = "1.1.0"

_VALID_BLOCK_RESPONSES = ("inform", "empty", "error")
_VALID_LOG_MODES = ("none", "redacted", "hashed", "raw")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool = False) -> bool:
    """Nur ein ausdrueckliches 'true'/'1'/'yes' schaltet ein.

    Alles andere, auch Tippfehler, bleibt aus. Bei Schaltern, die
    personenbezogene Daten freigeben, ist das die richtige Richtung.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _node_name() -> str:
    name = os.getenv("AIMON_NODE", "").strip()
    return name or socket.gethostname()


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

    version: str = VERSION

    # --- Telemetrie an aimonitor -----------------------------------------
    # Leere URL = Telemetrie komplett aus.
    aimon_url: str = os.getenv("AIMON_URL", "").strip()
    aimon_token: str = os.getenv("AIMON_TOKEN", "").strip()
    aimon_node: str = _node_name()
    aimon_service_key: str = os.getenv("AIMON_SERVICE_KEY", "").strip()
    aimon_base_url: str = os.getenv("AIMON_BASE_URL", "").strip()

    aimon_interval: int = _int("AIMON_INTERVAL", 10)
    aimon_timeout: int = _int("AIMON_TIMEOUT", 5)
    aimon_queue_max: int = _int("AIMON_QUEUE_MAX", 5000)
    aimon_batch_max: int = _int("AIMON_BATCH_MAX", 500)

    # Schalter, die Anfragetext freigeben. Beide stehen bewusst auf aus.
    aimon_send_redacted_queries: bool = _bool("AIMON_SEND_REDACTED_QUERIES", False)
    aimon_send_raw_queries: bool = _bool("AIMON_SEND_RAW_QUERIES", False)

    aimon_send_query_hash: bool = _bool("AIMON_SEND_QUERY_HASH", True)
    aimon_query_hash_salt: str = os.getenv("AIMON_QUERY_HASH_SALT", "")

    def __post_init__(self) -> None:
        if not self.aimon_service_key:
            object.__setattr__(
                self, "aimon_service_key", f"privacy-proxy@{self.aimon_node}:8888"
            )
        if not self.aimon_base_url:
            object.__setattr__(self, "aimon_base_url", f"http://{self.aimon_node}:8888")

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
        if self.aimon_interval < 1:
            raise ValueError("AIMON_INTERVAL muss mindestens 1 Sekunde sein")
        if self.aimon_send_raw_queries and not self.aimon_url:
            raise ValueError(
                "AIMON_SEND_RAW_QUERIES=true ohne AIMON_URL ergibt keinen Sinn"
            )


settings = Settings()
