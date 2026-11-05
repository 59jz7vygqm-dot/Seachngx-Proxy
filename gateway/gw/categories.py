"""Abbildung der Erkenner-Typen auf die Kategorien des Monitorings.

Das Monitoring kennt grobe Kategorien (person_name, email, ...), der Filter
feine Typen (DE_SOCIAL_SECURITY, RELATIONAL_PERSON, ...). Unbekannte Typen
landen in 'other' statt zu verschwinden - eine neue Policy-Regel soll im
Dashboard auffallen, nicht stillschweigend fehlen.
"""

from __future__ import annotations

CATEGORY_BY_TYPE: dict[str, str] = {
    # Personenbezug
    "PERSON": "person_name",
    "RELATIONAL_PERSON": "person_name",
    "SELF_DISCLOSURE": "person_name",
    # Kontaktdaten
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "DE_STREET_ADDRESS": "address",
    "LOCATION": "location",
    # Finanzen
    "IBAN_CODE": "bank_account",
    "CREDIT_CARD": "credit_card",
    "CRYPTO": "crypto_address",
    "US_BANK_NUMBER": "bank_account",
    # Kennungen
    "DE_TAX_ID": "id_number",
    "DE_SOCIAL_SECURITY": "id_number",
    "DE_HEALTH_INSURANCE": "id_number",
    "DE_IDCARD": "id_number",
    "DE_LICENSE_PLATE": "id_number",
    "US_SSN": "id_number",
    "US_PASSPORT": "id_number",
    "US_DRIVER_LICENSE": "id_number",
    "MEDICAL_LICENSE": "id_number",
    # Technisches
    "IP_ADDRESS": "ip_address",
    "PRIVATE_HOSTNAME": "private_host",
    "CREDENTIAL": "credential",
    "URL": "url",
}

OTHER = "other"


def category_for(entity_type: str) -> str:
    return CATEGORY_BY_TYPE.get(entity_type.upper(), OTHER)
