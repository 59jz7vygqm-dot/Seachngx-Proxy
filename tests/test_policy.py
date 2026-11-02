"""Policy-Logik - ohne Presidio, daher ohne NLP-Image lauffaehig."""

from pathlib import Path

import pytest

from pii.policy import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_REDACT,
    Finding,
    Policy,
    evaluate,
    redact,
    scan_denylist,
)

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "policy.yml"


@pytest.fixture(scope="module")
def policy() -> Policy:
    return Policy.load(str(POLICY_PATH))


def f(entity_type, start, end, text, score=0.9):
    return Finding(entity_type, start, end, score, text)


def test_policy_file_loads(policy):
    assert policy.action_for("PERSON") == ACTION_BLOCK
    assert policy.action_for("LOCATION") == ACTION_ALLOW
    assert policy.action_for("VOELLIG_UNBEKANNT") == ACTION_REDACT
    assert policy.threshold_for("PERSON") == 0.6
    assert policy.threshold_for("EMAIL_ADDRESS") == policy.threshold


def test_location_allein_blockiert_nicht(policy):
    """Der Zielkonflikt: ohne Orte waere die Suche wertlos."""
    text = "Oeffnungszeiten Buergeramt Pankow"
    d = evaluate(text, [f("LOCATION", 25, 31, "Pankow")], policy)
    assert d.action == ACTION_ALLOW
    assert d.allowed


def test_person_blockiert(policy):
    text = "Adresse von Thomas Berger"
    d = evaluate(text, [f("PERSON", 12, 25, "Thomas Berger")], policy)
    assert d.action == ACTION_BLOCK
    assert d.blocking_types == ["PERSON"]
    assert "Thomas Berger" not in d.redacted_text
    assert "<PERSON>" in d.redacted_text


def test_person_unter_schwellwert_faellt_raus(policy):
    """0.55 < thresholds.PERSON (0.6) -> kein Treffer."""
    d = evaluate("berger pullover kaufen", [f("PERSON", 0, 6, "berger", score=0.55)], policy)
    assert d.action == ACTION_ALLOW
    assert d.findings == []


def test_allowlist_unterdrueckt_false_positive(policy):
    d = evaluate("docker netzwerk internal", [f("ORGANIZATION", 0, 6, "Docker")], policy)
    assert d.findings == []
    assert d.action == ACTION_ALLOW


def test_denylist_greift_ohne_ner(policy):
    """Personenbezug, der gar keine Named Entity ist."""
    d = evaluate("was verdient mein chef im schnitt", [], policy)
    assert d.action == ACTION_BLOCK
    assert "RELATIONAL_PERSON" in d.blocking_types


def test_denylist_credential(policy):
    d = evaluate("fehler bei api_key=sk-abc123 was tun", [], policy)
    assert d.action == ACTION_BLOCK
    assert "CREDENTIAL" in d.blocking_types
    assert "sk-abc123" not in d.redacted_text


def test_denylist_privater_hostname(policy):
    d = evaluate("nas.fritz.box nicht erreichbar", [], policy)
    assert d.action == ACTION_BLOCK
    assert "PRIVATE_HOSTNAME" in d.blocking_types


def test_redact_mehrere_treffer_offsets_stabil():
    text = "a@b.de und c@d.de"
    out = redact(
        text,
        [f("EMAIL_ADDRESS", 0, 6, "a@b.de"), f("EMAIL_ADDRESS", 11, 17, "c@d.de")],
    )
    assert out == "<EMAIL_ADDRESS> und <EMAIL_ADDRESS>"


def test_ueberlappung_hoechster_score_gewinnt(policy):
    d = evaluate(
        "Thomas Berger",
        [f("PERSON", 0, 13, "Thomas Berger", 0.85), f("LOCATION", 7, 13, "Berger", 0.7)],
        policy,
    )
    assert len(d.findings) == 1
    assert d.findings[0].entity_type == "PERSON"


def test_to_dict_enthaelt_keinen_klartext(policy):
    """Die Antwort wird geloggt - sie darf die Fundstelle nicht enthalten."""
    d = evaluate("mail an max@example.com", [f("EMAIL_ADDRESS", 8, 23, "max@example.com")], policy)
    blob = repr(d.to_dict())
    assert "max@example.com" not in blob
    assert "<EMAIL_ADDRESS>" in d.to_dict()["redacted_text"]


def test_unbekannte_aktion_wird_abgelehnt():
    with pytest.raises(ValueError):
        Policy.from_dict({"actions": {"PERSON": "vielleicht"}})


def test_scan_denylist_findet_mehrfach(policy):
    text = "mein chef und meine kollegin"
    found = scan_denylist(text, policy)
    assert len(found) == 2


# --- Ueberlappung: deterministische Regel schlaegt NER ---------------------
# Beide Faelle sind echte Fehlentscheidungen aus einem Produktivlauf gewesen.

def test_kennzeichen_schlaegt_location(policy):
    """'kennzeichen KH-AB 1234' wurde vom Modell als LOCATION durchgelassen."""
    text = "kennzeichen KH-AB 1234 halter ermitteln"
    d = evaluate(
        text,
        [
            f("LOCATION", 12, 22, "KH-AB 1234", 0.85),
            f("DE_LICENSE_PLATE", 12, 22, "KH-AB 1234", 0.85),
        ],
        policy,
    )
    assert d.action == ACTION_BLOCK
    assert d.blocking_types == ["DE_LICENSE_PLATE"]


def test_anschrift_schlaegt_location_trotz_niedrigerem_score(policy):
    """LOCATION 0.85 darf DE_STREET_ADDRESS 0.7 nicht verdraengen."""
    text = "Musterstrasse 12 55543 Bad Kreuznach"
    d = evaluate(
        text,
        [
            f("LOCATION", 0, 13, "Musterstrasse", 0.85),
            f("DE_STREET_ADDRESS", 0, 16, "Musterstrasse 12", 0.7),
            f("LOCATION", 23, 36, "Bad Kreuznach", 0.85),
        ],
        policy,
    )
    assert d.action == ACTION_BLOCK
    assert d.blocking_types == ["DE_STREET_ADDRESS"]
    assert d.redacted_text.startswith("<DE_STREET_ADDRESS>")
    # Der Ort dahinter ist erlaubt und bleibt stehen.
    assert d.redacted_text.endswith("Bad Kreuznach")


def test_ort_allein_bleibt_erlaubt(policy):
    """Die Verschaerfung darf reine Ortsangaben nicht mitreissen."""
    d = evaluate(
        "Landkreis Bad Kreuznach einwohnerzahl",
        [f("LOCATION", 0, 23, "Landkreis Bad Kreuznach", 0.85)],
        policy,
    )
    assert d.action == ACTION_ALLOW
