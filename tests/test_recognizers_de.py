"""Deterministische deutsche Erkenner.

Laufen ohne Presidio, weil der Scanner bewusst ausserhalb der
Presidio-Registry sitzt - genau das war der Fehler, den diese Tests absichern.
"""

from pathlib import Path

import pytest

from pii.policy import ACTION_BLOCK, Finding, Policy, evaluate
from pii.recognizers_de import scan_de

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "policy.yml"


@pytest.fixture(scope="module")
def policy() -> Policy:
    return Policy.load(str(POLICY_PATH))


def types(text) -> set[str]:
    return {f.entity_type for f in scan_de(text)}


def one(text, entity_type) -> Finding:
    hits = [f for f in scan_de(text) if f.entity_type == entity_type]
    assert hits, f"{entity_type} nicht gefunden in {text!r}"
    return hits[0]


# --- Kfz-Kennzeichen ------------------------------------------------------

def test_kennzeichen_mit_kontext():
    f = one("kennzeichen KH-AB 1234 halter ermitteln", "DE_LICENSE_PLATE")
    assert f.text == "KH-AB 1234"
    assert f.score == pytest.approx(0.85)


def test_kennzeichen_ohne_kontext_feuert_trotzdem():
    f = one("KH-AB 1234 besitzer", "DE_LICENSE_PLATE")
    assert f.score == pytest.approx(0.5)


def test_normbezeichnung_ist_kein_kennzeichen():
    """Der Bindestrich ist Pflicht, sonst trifft das Muster 'DIN EN 1234'."""
    assert "DE_LICENSE_PLATE" not in types("DIN EN 1234 norm")


def test_kennzeichen_schlaegt_location_in_der_policy(policy):
    """Der Produktivfehler: spaCy meldet LOCATION, die feste Regel verliert."""
    text = "kennzeichen KH-AB 1234 halter ermitteln"
    ner = [Finding("LOCATION", 12, 22, 0.85, "KH-AB 1234")]
    d = evaluate(text, ner + scan_de(text), policy)
    assert d.action == ACTION_BLOCK
    assert d.blocking_types == ["DE_LICENSE_PLATE"]


# --- Anschrift ------------------------------------------------------------

def test_strasse_mit_hausnummer():
    f = one("Musterstrasse 12 55543 Bad Kreuznach", "DE_STREET_ADDRESS")
    assert f.text == "Musterstrasse 12"


def test_strasse_mit_eszett_und_zusatzbuchstabe():
    assert one("Hauptstraße 5a", "DE_STREET_ADDRESS").text == "Hauptstraße 5a"


def test_strasse_schluckt_kein_nachfolgendes_wort():
    """Ohne Zusatzbuchstabe darf das Leerzeichen nicht mitgenommen werden."""
    assert one("Hauptstrasse 5 Berlin", "DE_STREET_ADDRESS").text == "Hauptstrasse 5"


def test_plz_allein_bleibt_unter_der_schwelle(policy):
    f = one("55543 Bad Kreuznach", "DE_STREET_ADDRESS")
    assert f.score < policy.threshold_for("DE_STREET_ADDRESS")


def test_plz_mit_kontext_greift(policy):
    f = one("anschrift 55543 Bad Kreuznach", "DE_STREET_ADDRESS")
    assert f.score >= policy.threshold_for("DE_STREET_ADDRESS")


# --- Nummern --------------------------------------------------------------

def test_steuer_id_nur_mit_kontext(policy):
    schwelle = policy.threshold_for("DE_TAX_ID")
    assert one("12 345 678 901 pruefen", "DE_TAX_ID").score < schwelle
    assert one("steuer identifikationsnummer 12 345 678 901", "DE_TAX_ID").score >= schwelle


def test_ausweisnummer_erreicht_mit_kontext_die_schwelle(policy):
    """Basis 0.3 + Boost 0.5 muss ueber thresholds.DE_IDCARD (0.75) kommen."""
    f = one("personalausweis CF1234567 gueltig", "DE_IDCARD")
    assert f.score >= policy.threshold_for("DE_IDCARD")


def test_rentenversicherungsnummer():
    assert one("rvnr 12345678A123", "DE_SOCIAL_SECURITY").text == "12345678A123"


def test_versichertennummer_nur_mit_kontext(policy):
    schwelle = policy.threshold_for("DE_HEALTH_INSURANCE")
    assert one("A123456789 pruefen", "DE_HEALTH_INSURANCE").score < schwelle
    assert one("versichertennummer A123456789", "DE_HEALTH_INSURANCE").score >= schwelle


def test_telefon_international():
    assert one("tel +49 671 1234567", "PHONE_NUMBER").text.startswith("+49")


def test_telefon_national():
    assert one("rufnummer 0671 1234567", "PHONE_NUMBER").text == "0671 1234567"


# --- keine Fehlalarme -----------------------------------------------------

@pytest.mark.parametrize(
    "harmlos",
    [
        "debian 13 release notes",
        "Landkreis Bad Kreuznach einwohnerzahl",
        "oeffnungszeiten buergeramt pankow",
        "wetter morgen",
        "docker compose internal network",
    ],
)
def test_keine_treffer_bei_harmlosen_anfragen(harmlos):
    assert scan_de(harmlos) == []
