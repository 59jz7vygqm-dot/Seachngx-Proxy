"""Deterministische Erkenner fuer deutsche PII.

NER allein reicht nicht: Steuer-ID, Kfz-Kennzeichen oder Versichertennummern
sind keine Named Entities. Umgekehrt faengt Regex keine Namen. Beides noetig.
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

# Kontextwoerter heben den Score, wenn sie in der Naehe stehen. Das ist noetig,
# weil mehrere dieser Muster fuer sich genommen sehr unspezifisch sind.

DE_TAX_ID = PatternRecognizer(
    supported_entity="DE_TAX_ID",
    supported_language="de",
    patterns=[Pattern("de_tax_id", r"\b\d{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{3}\b", 0.35)],
    context=["steuer", "steuerid", "identifikationsnummer", "steuernummer", "finanzamt"],
)

DE_SOCIAL_SECURITY = PatternRecognizer(
    supported_entity="DE_SOCIAL_SECURITY",
    supported_language="de",
    patterns=[Pattern("de_rvnr", r"\b\d{2}\d{6}[A-Z]\d{3}\b", 0.75)],
    context=["rentenversicherung", "sozialversicherung", "versicherungsnummer", "rvnr"],
)

DE_HEALTH_INSURANCE = PatternRecognizer(
    supported_entity="DE_HEALTH_INSURANCE",
    supported_language="de",
    patterns=[Pattern("de_kvnr", r"\b[A-Z]\d{9}\b", 0.4)],
    context=["krankenkasse", "versichertennummer", "kvnr", "krankenversicherung", "aok", "tk"],
)

DE_LICENSE_PLATE = PatternRecognizer(
    supported_entity="DE_LICENSE_PLATE",
    supported_language="de",
    patterns=[
        Pattern(
            "de_kfz",
            r"\b[A-ZÄÖÜ]{1,3}[- ][A-ZÄÖÜ]{1,2][- ]?\d{1,4}\s?[EH]?\b",
            0.5,
        )
    ],
    context=["kennzeichen", "kfz", "auto", "nummernschild", "zulassung"],
)

DE_IDCARD = PatternRecognizer(
    supported_entity="DE_IDCARD",
    supported_language="de",
    patterns=[Pattern("de_perso", r"\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b", 0.2)],
    context=["personalausweis", "ausweisnummer", "perso", "reisepass", "passnummer"],
)

DE_STREET_ADDRESS = PatternRecognizer(
    supported_entity="DE_STREET_ADDRESS",
    supported_language="de",
    patterns=[
        Pattern(
            "de_street",
            r"\b[A-ZÄÖÜ][a-zäöüß\-]{2,}(?:stra(?:ss|ß)e|str\.|weg|gasse|allee|platz|ring|damm|ufer)"
            r"\s+\d{1,4}\s?[a-zA-Z]?\b",
            0.7,
        ),
        Pattern("de_plz_ort", r"\b\d{5}\s+[A-ZÄÖÜ][a-zäöüß\-]{2,}\b", 0.35),
    ],
    context=["adresse", "anschrift", "wohnhaft", "wohne", "plz", "postleitzahl"],
)

DE_PHONE = PatternRecognizer(
    supported_entity="PHONE_NUMBER",
    supported_language="de",
    patterns=[
        Pattern("de_phone_intl", r"\+49[\s\-/]?\(?0?\)?[\s\-/]?\d{2,5}[\s\-/]?\d{3,9}", 0.7),
        Pattern("de_phone_nat", r"\b0\d{2,5}[\s\-/]\d{3,9}\b", 0.5),
    ],
    context=["telefon", "tel", "handy", "mobil", "rufnummer", "durchwahl"],
)

DE_RECOGNIZERS = [
    DE_TAX_ID,
    DE_SOCIAL_SECURITY,
    DE_HEALTH_INSURANCE,
    DE_LICENSE_PLATE,
    DE_IDCARD,
    DE_STREET_ADDRESS,
    DE_PHONE,
]
