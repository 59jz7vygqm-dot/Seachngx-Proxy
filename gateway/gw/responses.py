"""Antwortformen des Gateways (SearXNG-kompatibel)."""

from __future__ import annotations

BLOCK_URL = "about:blocked"

_TYPE_LABELS_DE = {
    "PERSON": "Personenname",
    "EMAIL_ADDRESS": "E-Mail-Adresse",
    "PHONE_NUMBER": "Telefonnummer",
    "IBAN_CODE": "IBAN",
    "CREDIT_CARD": "Kreditkartennummer",
    "CRYPTO": "Krypto-Adresse",
    "IP_ADDRESS": "IP-Adresse",
    "US_SSN": "Sozialversicherungsnummer",
    "MEDICAL_LICENSE": "Approbations-/Lizenznummer",
    "DE_TAX_ID": "Steuer-Identifikationsnummer",
    "DE_SOCIAL_SECURITY": "Rentenversicherungsnummer",
    "DE_HEALTH_INSURANCE": "Versichertennummer",
    "DE_LICENSE_PLATE": "Kfz-Kennzeichen",
    "DE_IDCARD": "Ausweisnummer",
    "DE_STREET_ADDRESS": "Anschrift",
    "CUSTOM_DENYLIST": "Angabe aus der Sperrliste",
}


def label(entity_type: str) -> str:
    return _TYPE_LABELS_DE.get(entity_type, entity_type)


def empty_response(query: str) -> dict:
    return {
        "query": query,
        "number_of_results": 0,
        "results": [],
        "answers": [],
        "corrections": [],
        "infoboxes": [],
        "suggestions": [],
        "unresponsive_engines": [],
    }


def block_message(blocking_types: list[str]) -> str:
    kinds = ", ".join(label(t) for t in blocking_types) or "personenbezogene Daten"
    return (
        f"Diese Suchanfrage wurde vom Datenschutzfilter blockiert und NICHT an das "
        f"Internet weitergegeben. Erkannt wurde: {kinds}. "
        f"Formuliere die Anfrage ohne diese Angaben neu - zum Beispiel allgemein "
        f"statt auf eine konkrete Person bezogen - und suche erneut. "
        f"Gib die blockierten Angaben nicht erneut in einer Suchanfrage an."
    )


def block_response(redacted_query: str, blocking_types: list[str], mode: str) -> dict:
    """Antwort, wenn die Policy blockt.

    'inform' liefert bewusst HTTP 200 mit einem Pseudo-Treffer: OpenWebUI
    reicht Treffer an das Modell weiter, Fehlerstatus dagegen nicht. So
    erfaehrt das LLM den Grund und kann die Anfrage selbst entschaerfen.
    """
    payload = empty_response(redacted_query)
    if mode == "inform":
        payload["results"] = [
            {
                "url": BLOCK_URL,
                "title": "Suchanfrage blockiert (Datenschutzfilter)",
                "content": block_message(blocking_types),
                "engine": "privacy-filter",
                "publishedDate": None,
                "score": 1.0,
            }
        ]
        payload["number_of_results"] = 1
        payload["answers"] = [block_message(blocking_types)]
    return payload
