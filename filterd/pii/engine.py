"""Presidio-Analyzer: Aufbau und Aufruf."""

from __future__ import annotations

import logging
import os
from functools import lru_cache

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from .policy import Finding
from .recognizers_de import scan_de

log = logging.getLogger("filter.engine")

SPACY_DE = os.getenv("FILTER_SPACY_DE", "de_core_news_md")
SPACY_EN = os.getenv("FILTER_SPACY_EN", "en_core_web_md")
SUPPORTED_LANGUAGES = ("de", "en")


@lru_cache(maxsize=1)
def get_analyzer() -> AnalyzerEngine:
    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [
                {"lang_code": "de", "model_name": SPACY_DE},
                {"lang_code": "en", "model_name": SPACY_EN},
            ],
        }
    )
    nlp_engine = provider.create_engine()

    # supported_languages MUSS hier gesetzt werden: die Registry defaultet auf
    # ["en"], load_predefined_recognizers() aendert das nicht, und die
    # AnalyzerEngine prueft beide Listen auf Gleichheit.
    registry = RecognizerRegistry(supported_languages=list(SUPPORTED_LANGUAGES))
    registry.load_predefined_recognizers(
        languages=list(SUPPORTED_LANGUAGES), nlp_engine=nlp_engine
    )
    analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine,
        registry=registry,
        supported_languages=list(SUPPORTED_LANGUAGES),
        default_score_threshold=0.0,  # Schwellwerte macht die Policy, nicht Presidio
    )
    log.info("analyzer ready (de=%s, en=%s)", SPACY_DE, SPACY_EN)
    return analyzer


def analyze(text: str, language: str) -> list[Finding]:
    if language not in SUPPORTED_LANGUAGES:
        language = SUPPORTED_LANGUAGES[0]
    results = get_analyzer().analyze(text=text, language=language)
    findings = [
        Finding(
            entity_type=r.entity_type,
            start=r.start,
            end=r.end,
            score=float(r.score),
            text=text[r.start : r.end],
        )
        for r in results
    ]
    # Die festen Regeln laufen GETRENNT und werden absichtlich nicht in die
    # Presidio-Registry gehaengt: deren interne Konfliktaufloesung geht nach
    # Score und wuerde sie gegen NER-Treffer verlieren lassen. Die
    # Rangfolge entscheidet die Policy.
    findings.extend(scan_de(text))
    return findings
