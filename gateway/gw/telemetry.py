"""Telemetrie an aimonitor.

Grundsaetze, in dieser Reihenfolge:

1. Datenschutz vor Beobachtbarkeit. Dieser Proxy existiert, um
   personenbezogene Daten aus Suchanfragen zu halten. Die Telemetrie darf sie
   nicht durch die Hintertuer wieder einsammeln. Im Zweifel wird ein Feld
   weggelassen, nicht gesendet.
2. Die Suche hat Vorrang. Nichts hier laeuft im Request-Pfad, nichts wartet
   auf HTTP, nichts kann eine Suchanfrage kaputtmachen.
3. Keine erfundenen Zahlen. Was nicht gemessen wurde, wird nicht gemeldet.

Zaehler sind kumulativ seit Prozessstart; aimonitor bildet Raten selbst und
erkennt Neustarts am Ruecksprung. Deltas waeren bei Paketverlust falsch.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .categories import category_for

log = logging.getLogger("gateway.telemetry")


def _httpx() -> Any:
    """Lazy import: so bleibt die Zaehl- und Payload-Logik ohne httpx testbar."""
    import httpx

    return httpx

ACTION_ALLOWED = "allowed"
ACTION_REDACTED = "redacted"
ACTION_BLOCKED = "blocked"
ACTION_ERROR = "error"


# --------------------------------------------------------------------------
# Zaehler
# --------------------------------------------------------------------------

@dataclass
class Counters:
    """Kumulativ und monoton steigend seit Prozessstart."""

    requests_total: int = 0
    allowed_total: int = 0
    blocked_total: int = 0
    redacted_total: int = 0
    errors_total: int = 0
    upstream_errors_total: int = 0
    dropped_total: int = 0
    blocked_by_category: dict[str, int] = field(default_factory=dict)
    redacted_by_category: dict[str, int] = field(default_factory=dict)
    upstream_latency_ms_sum: float = 0.0
    upstream_latency_ms_count: int = 0
    query_len_sum: int = 0
    query_len_count: int = 0

    def bump_category(self, bucket: dict[str, int], category: str) -> None:
        bucket[category] = bucket.get(category, 0) + 1

    def to_dict(self) -> dict:
        return {
            "requests_total": self.requests_total,
            "allowed_total": self.allowed_total,
            "blocked_total": self.blocked_total,
            "redacted_total": self.redacted_total,
            "errors_total": self.errors_total,
            "upstream_errors_total": self.upstream_errors_total,
            "dropped_total": self.dropped_total,
            "blocked_by_category": dict(self.blocked_by_category),
            "redacted_by_category": dict(self.redacted_by_category),
            "upstream_latency_ms_sum": round(self.upstream_latency_ms_sum, 1),
            "upstream_latency_ms_count": self.upstream_latency_ms_count,
            "query_len_sum": self.query_len_sum,
            "query_len_count": self.query_len_count,
        }


# --------------------------------------------------------------------------
# Hilfsfunktionen (rein, damit testbar)
# --------------------------------------------------------------------------

def query_hash(query: str, salt: str = "") -> str:
    """SHA256 der ORIGINALanfrage.

    Wiedererkennungsmerkmal, keine Anonymisierung: eine kurze Suchanfrage
    laesst sich durchprobieren. Mit gesetztem Salt ist das nicht mehr
    moeglich, dafuer sind Hashes zwischen zwei Installationen nicht
    vergleichbar. Ohne Salt entspricht das Feld der aimonitor-Spezifikation.
    """
    return hashlib.sha256((salt + query).encode("utf-8")).hexdigest()


def primary_finding(findings: list[dict], types: list[str]) -> dict | None:
    """Der Treffer, der die Entscheidung traegt.

    Genau einer, damit die Summe ueber blocked_by_category dem Gesamtzaehler
    entspricht. Hoechster Score gewinnt, bei Gleichstand der fruehere.
    """
    candidates = [f for f in findings if f.get("type") in set(types)]
    if not candidates:
        return None
    return sorted(candidates, key=lambda f: (-float(f.get("score", 0)), f.get("start", 0)))[0]


def matched_spans(findings: list[dict], types: list[str]) -> list[dict]:
    """Nur Offsets und Typ. Nie der Treffertext."""
    wanted = set(types)
    return [
        {"start": f["start"], "end": f["end"], "type": f["type"]}
        for f in findings
        if f.get("type") in wanted and "start" in f and "end" in f
    ]


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------

class Telemetry:
    def __init__(self, settings) -> None:
        self.s = settings
        self.counters = Counters()
        self._queue: deque[dict] = deque(maxlen=max(1, settings.aimon_queue_max))
        self._pending: list[dict] = []
        self._client: Any | None = None
        self._task: asyncio.Task | None = None
        self._backoff = 0.0
        self._last_error: str | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.s.aimon_url)

    # -- Aufnahme ----------------------------------------------------------

    def record(
        self,
        action: str,
        *,
        query: str,
        decision: dict | None = None,
        upstream_latency_ms: float | None = None,
        upstream_status: int | None = None,
        category: str | None = None,
        rule: str | None = None,
    ) -> None:
        """Wird im Request-Pfad aufgerufen und darf daher nie werfen."""
        try:
            self._record(
                action,
                query=query,
                decision=decision,
                upstream_latency_ms=upstream_latency_ms,
                upstream_status=upstream_status,
                category=category,
                rule=rule,
            )
        except Exception as exc:  # Telemetrie darf keine Suche kaputtmachen
            log.warning(json.dumps({"event": "telemetry.record_failed", "error": str(exc)}))

    def _record(
        self,
        action: str,
        *,
        query: str,
        decision: dict | None,
        upstream_latency_ms: float | None,
        upstream_status: int | None,
        category: str | None,
        rule: str | None,
    ) -> None:
        c = self.counters
        c.requests_total += 1
        c.query_len_sum += len(query)
        c.query_len_count += 1

        if upstream_latency_ms is not None:
            c.upstream_latency_ms_sum += upstream_latency_ms
            c.upstream_latency_ms_count += 1
        findings = (decision or {}).get("findings", []) or []
        types: list[str] = []
        if action == ACTION_BLOCKED:
            types = (decision or {}).get("blocking_types", []) or []
        elif action == ACTION_REDACTED:
            types = (decision or {}).get("redacting_types", []) or []

        primary = primary_finding(findings, types) if types else None
        if category is None and primary is not None:
            category = category_for(primary["type"])
        if rule is None and primary is not None:
            rule = primary.get("rule") or None

        if action == ACTION_ALLOWED:
            c.allowed_total += 1
        elif action == ACTION_BLOCKED:
            c.blocked_total += 1
            c.bump_category(c.blocked_by_category, category or "other")
        elif action == ACTION_REDACTED:
            c.redacted_total += 1
            c.bump_category(c.redacted_by_category, category or "other")
        elif action == ACTION_ERROR:
            c.errors_total += 1
        else:
            raise ValueError(f"unbekannte action: {action!r}")

        # Durchgelassene Anfragen NICHT einzeln melden - dafuer sind die
        # Zaehler da. Einzeln waeren das tausende Eintraege pro Stunde.
        if action == ACTION_ALLOWED or not self.enabled:
            return

        self._enqueue(
            self._entry(
                action,
                query=query,
                decision=decision,
                primary=primary,
                types=types,
                category=category,
                rule=rule,
                upstream_latency_ms=upstream_latency_ms,
                upstream_status=upstream_status,
            )
        )

    def _entry(
        self,
        action: str,
        *,
        query: str,
        decision: dict | None,
        primary: dict | None,
        types: list[str],
        category: str | None,
        rule: str | None,
        upstream_latency_ms: float | None,
        upstream_status: int | None,
    ) -> dict:
        entry: dict = {
            "ts": round(time.time(), 1),
            "action": action,
            "query_len": len(query),
        }
        if category:
            entry["category"] = category
        if rule:
            entry["rule"] = rule

        # Konfidenz nur bei modellbasierter Erkennung. Bei festen Regeln ist
        # der Score auf 1.0 gesetzt und damit keine Aussage.
        if primary is not None and primary.get("source") == "ner":
            entry["confidence"] = round(float(primary.get("score", 0.0)), 3)

        if self.s.aimon_send_query_hash:
            entry["query_sha256"] = query_hash(query, self.s.aimon_query_hash_salt)

        # Standardmaessig AUS. Siehe README: der Filter garantiert nicht,
        # dass die geschwaerzte Fassung frei von Personenbezug ist.
        if self.s.aimon_send_redacted_queries and decision:
            entry["query_redacted"] = decision.get("redacted_text", "")

        # Zweite, bewusste Huerde. Default aus; der Server muss es zusaetzlich
        # erlauben.
        if self.s.aimon_send_raw_queries:
            entry["query_raw"] = query

        if types and decision:
            spans = matched_spans(decision.get("findings", []) or [], types)
            if spans:
                entry["matched_spans"] = spans

        if upstream_latency_ms is not None:
            entry["upstream_latency_ms"] = round(upstream_latency_ms, 1)
        if upstream_status is not None:
            entry["upstream_status"] = upstream_status

        # client_id wird NICHT gesendet: siehe README. Kein Session-Schluessel
        # vorhanden, und eine IP-Adresse waere das Gegenteil eines Pseudonyms.
        return entry

    def upstream_failure(
        self,
        *,
        query: str,
        status: int | None = None,
        latency_ms: float | None = None,
        reason: str | None = None,
    ) -> None:
        """Fehler von SearXNG - eigener Zaehler, eigene Entscheidung.

        Bewusst getrennt von record(): die Anfrage selbst wurde vom Filter
        durchgelassen und zaehlt dort. Wuerde sie zusaetzlich in errors_total
        landen, ginge die Identitaet
        allowed + blocked + redacted + errors = requests nicht mehr auf.
        upstream_errors_total ist eine eigene Dimension, kein vierter Kuebel.

        429 heisst in der Praxis fast immer: eine Suchmaschine hat
        dichtgemacht oder zeigt ein Captcha. Nutzer sehen dann leere
        Ergebnisse und halten den Proxy fuer kaputt - das gehoert sichtbar.
        """
        try:
            self.counters.upstream_errors_total += 1
            if not self.enabled:
                return
            entry: dict = {
                "ts": round(time.time(), 1),
                "action": ACTION_ERROR,
                "category": "upstream",
                "rule": "upstream.searxng",
                "query_len": len(query),
            }
            if status is not None:
                entry["upstream_status"] = status
            if latency_ms is not None:
                entry["upstream_latency_ms"] = round(latency_ms, 1)
            if reason:
                entry["reason"] = reason
            if self.s.aimon_send_query_hash:
                entry["query_sha256"] = query_hash(query, self.s.aimon_query_hash_salt)
            self._enqueue(entry)
        except Exception as exc:
            log.warning(json.dumps({"event": "telemetry.record_failed", "error": str(exc)}))

    def _enqueue(self, entry: dict) -> None:
        if len(self._queue) == self._queue.maxlen:
            self.counters.dropped_total += 1  # aeltester Eintrag faellt raus
        self._queue.append(entry)

    # -- Versand -----------------------------------------------------------

    def payload(self, decisions: list[dict]) -> dict:
        return {
            "node": {"name": self.s.aimon_node},
            "service": {
                "key": self.s.aimon_service_key,
                "kind": "privacy_proxy",
                "name": "SearXNG Privacy Proxy",
                "base_url": self.s.aimon_base_url,
                "version": self.s.version,
            },
            "ts": int(time.time()),
            "counters": self.counters.to_dict(),
            "decisions": decisions,
        }

    async def start(self) -> None:
        if not self.enabled:
            log.info(json.dumps({"event": "telemetry.disabled"}))
            return
        self._client = _httpx().AsyncClient(timeout=self.s.aimon_timeout)
        self._task = asyncio.create_task(self._loop())
        log.info(
            json.dumps(
                {
                    "event": "telemetry.enabled",
                    "url": self.s.aimon_url,
                    "interval": self.s.aimon_interval,
                    "send_redacted_queries": self.s.aimon_send_redacted_queries,
                    "send_raw_queries": self.s.aimon_send_raw_queries,
                }
            )
        )

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        if self._client is not None:
            await self._client.aclose()

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self._backoff or self.s.aimon_interval)
            try:
                await self.flush()
            except Exception as exc:  # darf den Worker nie beenden
                log.warning(json.dumps({"event": "telemetry.loop_error", "error": str(exc)}))
                self._fail(str(exc))

    def _drain(self) -> list[dict]:
        batch = self._pending
        room = self.s.aimon_batch_max - len(batch)
        while room > 0 and self._queue:
            batch.append(self._queue.popleft())
            room -= 1
        return batch

    def _fail(self, reason: str) -> None:
        """Backoff hochsetzen, Jitter drauf."""
        base = max(1.0, min(self._backoff * 2 if self._backoff else 1.0, 60.0))
        self._backoff = base * (0.8 + 0.4 * random.random())
        if reason != self._last_error:
            log.warning(json.dumps({"event": "telemetry.send_failed", "error": reason}))
            self._last_error = reason

    def _succeed(self) -> None:
        if self._last_error is not None:
            log.info(json.dumps({"event": "telemetry.recovered"}))
        self._backoff = 0.0
        self._last_error = None

    async def flush(self) -> None:
        if not self.enabled or self._client is None:
            return
        batch = self._drain()

        try:
            resp = await self._client.post(
                self.s.aimon_url,
                json=self.payload(batch),
                headers=self._headers(),
            )
        except _httpx().HTTPError as exc:
            self._keep(batch)
            self._fail(repr(exc))
            return

        if resp.status_code < 300:
            self._pending = []
            self._succeed()
            return

        # 4xx ausser 429 ist ein Fehler, den Wiederholen nicht heilt:
        # falsches Token, falsches Schema. Batch verwerfen, einmal loggen.
        if 400 <= resp.status_code < 500 and resp.status_code != 429:
            self._pending = []
            self.counters.dropped_total += len(batch)
            if self._last_error != str(resp.status_code):
                log.warning(
                    json.dumps(
                        {
                            "event": "telemetry.rejected",
                            "status": resp.status_code,
                            "dropped": len(batch),
                            "body": resp.text[:300],
                        }
                    )
                )
                self._last_error = str(resp.status_code)
            self._backoff = 0.0
            return

        self._keep(batch)
        self._fail(str(resp.status_code))

    def _keep(self, batch: list[dict]) -> None:
        """Nicht gesendete Entscheidungen fuer den naechsten Versuch halten."""
        limit = self._queue.maxlen or len(batch)
        if len(batch) > limit:
            self.counters.dropped_total += len(batch) - limit
            batch = batch[-limit:]
        self._pending = batch

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.s.aimon_token:
            headers["Authorization"] = f"Bearer {self.s.aimon_token}"
        return headers

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "queued": len(self._queue),
            "pending": len(self._pending),
            "backoff_s": round(self._backoff, 1),
            "last_error": self._last_error,
            "dropped_total": self.counters.dropped_total,
        }


def default_node_name() -> str:
    return socket.gethostname()
