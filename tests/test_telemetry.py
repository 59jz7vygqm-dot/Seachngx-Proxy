"""Telemetrie an aimonitor.

Schwerpunkt: was NICHT gesendet wird. Dieser Proxy haelt personenbezogene
Daten aus Suchanfragen; eine Monitoring-Anbindung, die sie in eine Datenbank
schreibt, waere das Gegenteil seines Zwecks.
"""

from dataclasses import dataclass, field

import pytest

from gw.categories import category_for
from gw.telemetry import (
    ACTION_ALLOWED,
    ACTION_BLOCKED,
    ACTION_ERROR,
    ACTION_REDACTED,
    Telemetry,
    matched_spans,
    primary_finding,
    query_hash,
)


@dataclass
class FakeSettings:
    aimon_url: str = "http://aimon.test/api/v1/ingest/privacy"
    aimon_token: str = "t0ken"
    aimon_node: str = "proxy-host-01"
    aimon_service_key: str = "privacy-proxy@proxy-host-01:8888"
    aimon_base_url: str = "http://proxy-host-01:8888"
    aimon_interval: int = 10
    aimon_timeout: int = 5
    aimon_queue_max: int = 5000
    aimon_batch_max: int = 500
    aimon_send_redacted_queries: bool = False
    aimon_send_raw_queries: bool = False
    aimon_send_query_hash: bool = True
    aimon_query_hash_salt: str = ""
    version: str = "1.1.0"


def tel(**kw) -> Telemetry:
    return Telemetry(FakeSettings(**kw))


def blocked_decision() -> dict:
    """Wie die Filter-Antwort fuer 'wohnort von Thomas Berger' aussieht."""
    return {
        "action": "block",
        "blocking_types": ["PERSON"],
        "redacting_types": [],
        "redacted_text": "wohnort von <PERSON>",
        "findings": [
            {
                "type": "PERSON",
                "start": 12,
                "end": 25,
                "score": 0.93,
                "length": 13,
                "source": "ner",
                "rule": "presidio.spacy",
            }
        ],
    }


RAW = "wohnort von Thomas Berger"


# --- Datenschutz ----------------------------------------------------------

def test_query_redacted_wird_standardmaessig_nicht_gesendet():
    """Der Filter garantiert nicht, dass die geschwaerzte Fassung sauber ist."""
    t = tel()
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    entry = t._queue[0]
    assert "query_redacted" not in entry


def test_query_raw_wird_standardmaessig_nicht_gesendet():
    t = tel()
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    assert "query_raw" not in t._queue[0]


def test_kein_eintrag_enthaelt_je_den_anfragetext():
    t = tel()
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    assert "Thomas" not in repr(t._queue[0])
    assert "Berger" not in repr(t._queue[0])


def test_client_id_wird_nie_gesendet():
    """Kein Session-Schluessel vorhanden - also gar kein Feld."""
    t = tel()
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    assert "client_id" not in t._queue[0]


def test_matched_spans_ohne_treffertext():
    spans = matched_spans(blocked_decision()["findings"], ["PERSON"])
    assert spans == [{"start": 12, "end": 25, "type": "PERSON"}]
    assert all("text" not in s for s in spans)


def test_schalter_gibt_geschwaerzte_fassung_frei():
    t = tel(aimon_send_redacted_queries=True)
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    assert t._queue[0]["query_redacted"] == "wohnort von <PERSON>"


def test_schalter_gibt_rohtext_frei():
    t = tel(aimon_send_raw_queries=True)
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    assert t._queue[0]["query_raw"] == RAW


# --- Hash -----------------------------------------------------------------

def test_hash_ist_ueber_die_originalanfrage():
    t = tel()
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    assert t._queue[0]["query_sha256"] == query_hash(RAW)
    assert t._queue[0]["query_sha256"] != query_hash("wohnort von <PERSON>")


def test_salt_aendert_den_hash():
    assert query_hash(RAW, "pfeffer") != query_hash(RAW)


def test_hash_abschaltbar():
    t = tel(aimon_send_query_hash=False)
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    assert "query_sha256" not in t._queue[0]


# --- Zaehler --------------------------------------------------------------

def test_identitaet_der_zaehler():
    """allowed + blocked + redacted + errors == requests."""
    t = tel()
    for _ in range(5):
        t.record(ACTION_ALLOWED, query="debian release notes")
    for _ in range(3):
        t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    t.record(ACTION_ERROR, query="x" * 900, category="request_rejected")
    c = t.counters
    assert c.requests_total == 9
    assert c.allowed_total + c.blocked_total + c.redacted_total + c.errors_total == 9


def test_kategoriesumme_entspricht_gesamtzaehler():
    t = tel()
    for _ in range(4):
        t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    c = t.counters
    assert sum(c.blocked_by_category.values()) == c.blocked_total == 4
    assert c.blocked_by_category == {"person_name": 4}


def test_upstream_fehler_zaehlt_nicht_als_proxy_fehler():
    """SearXNG-Fehler ist eine eigene Dimension, kein vierter Kuebel."""
    t = tel()
    t.record(ACTION_ALLOWED, query="wetter", upstream_latency_ms=5000.0, upstream_status=429)
    t.upstream_failure(query="wetter", status=429, latency_ms=5000.0)
    c = t.counters
    assert c.upstream_errors_total == 1
    assert c.errors_total == 0
    assert c.allowed_total == 1
    assert c.requests_total == 1
    assert c.allowed_total + c.blocked_total + c.redacted_total + c.errors_total == 1


def test_upstream_fehler_wird_als_entscheidung_gemeldet():
    t = tel()
    t.upstream_failure(query="wetter", status=429, latency_ms=5000.0, reason="ReadTimeout")
    entry = t._queue[0]
    assert entry["action"] == ACTION_ERROR
    assert entry["category"] == "upstream"
    assert entry["rule"] == "upstream.searxng"
    assert entry["upstream_status"] == 429


def test_latenz_als_summe_und_anzahl():
    t = tel()
    t.record(ACTION_ALLOWED, query="a", upstream_latency_ms=100.0)
    t.record(ACTION_ALLOWED, query="b", upstream_latency_ms=300.0)
    t.record(ACTION_ALLOWED, query="c")  # Cache-Treffer, kein Upstream
    c = t.counters
    assert c.upstream_latency_ms_sum == 400.0
    assert c.upstream_latency_ms_count == 2
    assert c.query_len_count == 3


def test_zaehler_sind_kumulativ():
    t = tel()
    t.record(ACTION_ALLOWED, query="a")
    erste = t.counters.to_dict()["requests_total"]
    t.record(ACTION_ALLOWED, query="b")
    assert t.counters.to_dict()["requests_total"] == erste + 1


def test_unbekannte_aktion_wird_abgelehnt():
    t = tel()
    with pytest.raises(ValueError):
        t._record(
            "vielleicht",
            query="x",
            decision=None,
            upstream_latency_ms=None,
            upstream_status=None,
            category=None,
            rule=None,
        )


def test_record_schluckt_fehler():
    """Im Request-Pfad darf nichts werfen."""
    t = tel()
    t.record("vielleicht", query="x")  # kein raise
    assert t.counters.requests_total == 1


# --- Warteschlange --------------------------------------------------------

def test_durchgelassene_anfragen_werden_nicht_einzeln_gemeldet():
    t = tel()
    for _ in range(50):
        t.record(ACTION_ALLOWED, query="debian")
    assert len(t._queue) == 0
    assert t.counters.allowed_total == 50


def test_queue_verwirft_aelteste_und_zaehlt_mit():
    t = tel(aimon_queue_max=3)
    for i in range(5):
        t.record(ACTION_BLOCKED, query=f"{RAW} {i}", decision=blocked_decision())
    assert len(t._queue) == 3
    assert t.counters.dropped_total == 2


def test_abgeschaltete_telemetrie_zaehlt_weiter_sendet_aber_nichts():
    t = tel(aimon_url="")
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    assert t.enabled is False
    assert t.counters.blocked_total == 1
    assert len(t._queue) == 0


# --- Entscheidungen -------------------------------------------------------

def test_konfidenz_nur_bei_modellbasierter_erkennung():
    t = tel()
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    assert t._queue[0]["confidence"] == pytest.approx(0.93)


def test_keine_konfidenz_bei_fester_regel():
    """Score 1.0 einer Regex ist keine Aussage ueber Sicherheit."""
    d = {
        "action": "block",
        "blocking_types": ["RELATIONAL_PERSON"],
        "redacting_types": [],
        "redacted_text": "was verdient <RELATIONAL_PERSON>",
        "findings": [
            {
                "type": "RELATIONAL_PERSON",
                "start": 13,
                "end": 22,
                "score": 1.0,
                "length": 9,
                "source": "denylist",
                "rule": "denylist.relational_person",
            }
        ],
    }
    t = tel()
    t.record(ACTION_BLOCKED, query="was verdient mein chef", decision=d)
    entry = t._queue[0]
    assert "confidence" not in entry
    assert entry["rule"] == "denylist.relational_person"


def test_regel_landet_im_eintrag():
    t = tel()
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    assert t._queue[0]["rule"] == "presidio.spacy"


def test_genau_eine_kategorie_pro_entscheidung():
    """Sonst geht die Summe ueber blocked_by_category nicht auf."""
    d = blocked_decision()
    d["blocking_types"] = ["PERSON", "EMAIL_ADDRESS"]
    d["findings"].append(
        {
            "type": "EMAIL_ADDRESS",
            "start": 30,
            "end": 45,
            "score": 1.0,
            "length": 15,
            "source": "pattern",
            "rule": "presidio.email",
        }
    )
    t = tel()
    t.record(ACTION_BLOCKED, query=RAW + " max@a.de", decision=d)
    assert sum(t.counters.blocked_by_category.values()) == 1


def test_primary_finding_nimmt_hoechsten_score():
    findings = [
        {"type": "PERSON", "start": 0, "end": 5, "score": 0.6},
        {"type": "EMAIL_ADDRESS", "start": 10, "end": 20, "score": 1.0},
    ]
    assert primary_finding(findings, ["PERSON", "EMAIL_ADDRESS"])["type"] == "EMAIL_ADDRESS"


def test_unbekannter_typ_landet_in_other():
    assert category_for("VOELLIG_NEUER_TYP") == "other"
    assert category_for("DE_LICENSE_PLATE") == "id_number"
    assert category_for("PERSON") == "person_name"


# --- Payload --------------------------------------------------------------

def test_payload_aufbau():
    t = tel()
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    p = t.payload(list(t._queue))
    assert p["node"] == {"name": "proxy-host-01"}
    assert p["service"]["kind"] == "privacy_proxy"
    assert p["service"]["key"] == "privacy-proxy@proxy-host-01:8888"
    assert isinstance(p["ts"], int)
    assert p["counters"]["blocked_total"] == 1
    assert len(p["decisions"]) == 1


def test_payload_enthaelt_keinen_anfragetext():
    t = tel()
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    t.record(ACTION_REDACTED, query="ruf 0171 1234567 an", decision={
        "action": "redact",
        "blocking_types": [],
        "redacting_types": ["PHONE_NUMBER"],
        "redacted_text": "ruf <PHONE_NUMBER> an",
        "findings": [{"type": "PHONE_NUMBER", "start": 4, "end": 16, "score": 0.85,
                      "length": 12, "source": "pattern", "rule": "regex.de.phone_number"}],
    })
    blob = repr(t.payload(list(t._queue)))
    assert "Thomas" not in blob
    assert "0171" not in blob


def test_header_enthaelt_token():
    assert tel()._headers()["Authorization"] == "Bearer t0ken"


def test_status_fuer_healthz():
    t = tel()
    t.record(ACTION_BLOCKED, query=RAW, decision=blocked_decision())
    st = t.status()
    assert st["enabled"] is True
    assert st["queued"] == 1
    assert st["last_error"] is None
