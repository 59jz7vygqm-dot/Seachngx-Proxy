"""Kommandozeile des Gateways.

    python -m gw --aimon-test [--live]

Schickt einen Beispiel-Payload an aimonitor und gibt die Antwort aus.
Standardmaessig mit dry_run=1, damit ein Test die echten Zaehler nicht
verfaelscht - mit --live ohne.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time

import httpx

from .config import settings
from .telemetry import Telemetry, query_hash

# Offensichtlich kuenstlich. Hier darf nichts stehen, was nach einer echten
# Anfrage aussieht - der Payload wird gedruckt und verschickt.
SAMPLE_QUERY = "wohnort von [NAME]"


def sample_decisions() -> list[dict]:
    return [
        {
            "ts": 0,  # wird unten gesetzt
            "action": "blocked",
            "category": "person_name",
            "rule": "presidio.spacy",
            "confidence": 0.93,
            "query_len": len(SAMPLE_QUERY),
            "query_sha256": query_hash(SAMPLE_QUERY, settings.aimon_query_hash_salt),
            "matched_spans": [{"start": 11, "end": 17, "type": "PERSON"}],
            "upstream_latency_ms": None,
            "upstream_status": None,
            "_selftest": True,
        }
    ]


async def aimon_test(live: bool) -> int:
    if not settings.aimon_url:
        print("AIMON_URL ist leer - Telemetrie ist abgeschaltet.", file=sys.stderr)
        print("Setze AIMON_URL und AIMON_TOKEN in der .env.", file=sys.stderr)
        return 2

    tel = Telemetry(settings)
    decisions = sample_decisions()
    decisions[0]["ts"] = round(time.time(), 1)
    payload = tel.payload(decisions)

    url = settings.aimon_url if live else f"{settings.aimon_url}?dry_run=1"

    print("Ziel:            %s" % url)
    print("Node:            %s" % settings.aimon_node)
    print("Service-Key:     %s" % settings.aimon_service_key)
    print("Token gesetzt:   %s" % ("ja" if settings.aimon_token else "NEIN"))
    print("query_redacted:  %s" % ("AN" if settings.aimon_send_redacted_queries else "aus"))
    print("query_raw:       %s" % ("AN" if settings.aimon_send_raw_queries else "aus"))
    print("query_sha256:    %s" % ("an" if settings.aimon_send_query_hash else "aus"))
    print("client_id:       wird nicht gesendet")
    print()
    print("Payload:")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print()

    try:
        async with httpx.AsyncClient(timeout=settings.aimon_timeout) as client:
            resp = await client.post(url, json=payload, headers=tel._headers())
    except httpx.HTTPError as exc:
        print("Fehlgeschlagen: %r" % exc, file=sys.stderr)
        return 1

    print("Antwort: HTTP %s" % resp.status_code)
    print(resp.text[:4000])
    return 0 if resp.status_code < 300 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gw")
    parser.add_argument(
        "--aimon-test",
        action="store_true",
        help="Beispiel-Payload an aimonitor senden und Antwort ausgeben",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="ohne dry_run senden (veraendert die echten Zaehler)",
    )
    args = parser.parse_args(argv)

    if args.aimon_test:
        return asyncio.run(aimon_test(args.live))

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
