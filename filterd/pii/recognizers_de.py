"""Deterministische Erkenner fuer deutsche PII.

Bewusst NICHT als Presidio-PatternRecognizer registriert: die AnalyzerEngine
loest Ueberlappungen intern nach Score auf, bevor der Aufrufer die Treffer
sieht. Ein spaCy-LOCATION mit 0.85 verdraengt dort eine feste Regel mit 0.5 -
"kennzeichen KH-AB 1234" ging so ungefiltert durch. Deterministische Regeln
duerfen einem probabilistischen Modell nicht untergeordnet sein.

Dieser Scanner laeuft daher getrennt; die Policy entscheidet anschliessend,
wer bei Ueberlappung gewinnt (block schlaegt allow, unabhaengig vom Score).

Modul ohne Presidio-/spaCy-Import und damit direkt testbar.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .policy import Finding


@dataclass(frozen=True)
class Rule:
    entity_type: str
    pattern: re.Pattern[str]
    score: float
    # Kontextwoerter irgendwo in der Anfrage heben den Score. Noetig, weil
    # mehrere Muster fuer sich genommen sehr unspezifisch sind.
    context: tuple[str, ...] = ()
    context_boost: float = 0.35


def _r(entity_type, pattern, score, context=(), boost=0.35, flags=0) -> Rule:
    return Rule(entity_type, re.compile(pattern, flags), score, tuple(context), boost)


RULES: list[Rule] = [
    # Steuerliche Identifikationsnummer: 11 Ziffern. Ohne Kontextwort bleibt
    # der Score unter der Policy-Schwelle (0.55) und feuert nicht.
    _r(
        "DE_TAX_ID",
        r"\b\d{2} ?\d{3} ?\d{3} ?\d{3}\b",
        0.35,
        ("steuer", "identifikationsnummer", "steuernummer", "finanzamt"),
    ),

    # Rentenversicherungsnummer: 8 Ziffern, Buchstabe, 3 Ziffern.
    _r(
        "DE_SOCIAL_SECURITY",
        r"\b\d{8}[A-Z]\d{3}\b",
        0.75,
        ("rentenversicherung", "sozialversicherung", "versicherungsnummer", "rvnr"),
    ),

    # Versichertennummer der gesetzlichen Krankenkassen: Buchstabe + 9 Ziffern.
    _r(
        "DE_HEALTH_INSURANCE",
        r"\b[A-Z]\d{9}\b",
        0.4,
        ("krankenkasse", "versichertennummer", "kvnr", "krankenversicherung"),
    ),

    # Kfz-Kennzeichen. Der Bindestrich nach dem Unterscheidungszeichen ist
    # Pflicht, sonst trifft das Muster auch Normbezeichnungen wie "DIN EN 1234".
    _r(
        "DE_LICENSE_PLATE",
        # (?:\s?[EH])? statt \s?[EH]? - sonst wird das Leerzeichen auch dann
        # mitgenommen, wenn gar kein E- oder H-Kennzeichen folgt.
        r"\b[A-ZÄÖÜ]{1,3}-[A-ZÄÖÜ]{1,2}[ -]?\d{1,4}(?:\s?[EH])?\b",
        0.5,
        ("kennzeichen", "kfz", "nummernschild", "zulassung", "halter", "auto"),
    ),

    # Personalausweis-/Passnummer. Fuer sich genommen kaum von einer
    # beliebigen Zeichenkette zu unterscheiden, daher nur mit Kontext.
    _r(
        "DE_IDCARD",
        r"\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b",
        0.3,
        ("personalausweis", "ausweisnummer", "perso", "reisepass", "passnummer"),
        boost=0.5,
    ),

    # Strasse mit Hausnummer. Eindeutig genug, um ohne Kontextwort zu greifen.
    # Die Gruppe um den Zusatzbuchstaben verhindert, dass ein Leerzeichen
    # mitgeschluckt wird, wenn kein Buchstabe folgt.
    _r(
        "DE_STREET_ADDRESS",
        r"\b[A-ZÄÖÜ][a-zäöüß\-]{2,}"
        r"(?:stra(?:ss|ß)e|str\.|weg|gasse|allee|platz|ring|damm|ufer)"
        r"\s+\d{1,4}(?:\s?[a-zA-Z])?\b",
        0.7,
        ("adresse", "anschrift", "wohnhaft", "wohne"),
    ),

    # PLZ + Ort. Allein zu unspezifisch, mit Kontextwort aussagekraeftig.
    _r(
        "DE_STREET_ADDRESS",
        r"\b\d{5}\s+[A-ZÄÖÜ][a-zäöüß\-]{2,}\b",
        0.3,
        ("adresse", "anschrift", "wohnhaft", "wohne", "postleitzahl", "plz"),
    ),

    # Telefonnummern. Presidio hat einen eigenen PhoneRecognizer; diese Regeln
    # ergaenzen ihn um deutsche Schreibweisen.
    _r(
        "PHONE_NUMBER",
        r"\+49[\s\-/]?\(?0?\)?[\s\-/]?\d{2,5}[\s\-/]?\d{3,9}",
        0.7,
        ("telefon", "tel", "handy", "mobil", "rufnummer", "durchwahl"),
    ),
    _r(
        "PHONE_NUMBER",
        r"\b0\d{2,5}[\s\-/]\d{3,9}\b",
        0.5,
        ("telefon", "tel", "handy", "mobil", "rufnummer", "durchwahl"),
    ),
]


def scan_de(text: str) -> list[Finding]:
    """Wendet alle festen Regeln an und liefert Treffer mit Score."""
    lowered = text.lower()
    out: list[Finding] = []
    for rule in RULES:
        score = rule.score
        if rule.context and any(word in lowered for word in rule.context):
            score = min(1.0, score + rule.context_boost)
        for m in rule.pattern.finditer(text):
            out.append(
                Finding(
                    entity_type=rule.entity_type,
                    start=m.start(),
                    end=m.end(),
                    score=score,
                    text=m.group(0),
                )
            )
    return out
