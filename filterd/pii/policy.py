"""Policy-Auswertung fuer den PII-Filter.

Dieses Modul ist bewusst frei von Presidio-/spaCy-Importen: es enthaelt nur
reine Funktionen und laesst sich dadurch ohne das schwere NLP-Image testen.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

import yaml

ACTION_ALLOW = "allow"
ACTION_REDACT = "redact"
ACTION_BLOCK = "block"
_ACTIONS = (ACTION_ALLOW, ACTION_REDACT, ACTION_BLOCK)

# Rangfolge: block schlaegt redact schlaegt allow.
_RANK = {ACTION_ALLOW: 0, ACTION_REDACT: 1, ACTION_BLOCK: 2}


@dataclass(frozen=True)
class Finding:
    """Ein Treffer im Eingabetext."""

    entity_type: str
    start: int
    end: int
    score: float
    text: str

    def overlaps(self, other: "Finding") -> bool:
        return self.start < other.end and other.start < self.end


@dataclass
class Policy:
    threshold: float = 0.45
    default_action: str = ACTION_REDACT
    actions: dict[str, str] = field(default_factory=dict)
    thresholds: dict[str, float] = field(default_factory=dict)
    allowlist: set[str] = field(default_factory=set)
    denylist: list[tuple[str, re.Pattern[str]]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Policy":
        actions = {}
        for entity, action in (raw.get("actions") or {}).items():
            action = str(action).strip().lower()
            if action not in _ACTIONS:
                raise ValueError(
                    f"policy: unbekannte Aktion {action!r} fuer {entity!r}; "
                    f"erlaubt sind {_ACTIONS}"
                )
            actions[str(entity).strip().upper()] = action

        default_action = str(raw.get("default_action", ACTION_REDACT)).lower()
        if default_action not in _ACTIONS:
            raise ValueError(f"policy: unbekannte default_action {default_action!r}")

        denylist: list[tuple[str, re.Pattern[str]]] = []
        for item in raw.get("denylist") or []:
            if isinstance(item, str):
                name, pattern, action = "CUSTOM_DENYLIST", item, ACTION_BLOCK
            else:
                name = str(item.get("name", "CUSTOM_DENYLIST")).upper()
                pattern = str(item["pattern"])
                action = str(item.get("action", ACTION_BLOCK)).lower()
                if action not in _ACTIONS:
                    raise ValueError(
                        f"policy: unbekannte Aktion {action!r} in denylist-Eintrag {name!r}"
                    )
            denylist.append((name, re.compile(pattern)))
            # Denylist-Regeln sind deterministisch und blockieren per Default.
            # Ein expliziter actions-Eintrag hat Vorrang.
            actions.setdefault(name, action)

        return cls(
            threshold=float(raw.get("threshold", 0.45)),
            default_action=default_action,
            actions=actions,
            thresholds={
                str(k).upper(): float(v)
                for k, v in (raw.get("thresholds") or {}).items()
            },
            allowlist={str(t).strip().lower() for t in (raw.get("allowlist") or []) if str(t).strip()},
            denylist=denylist,
        )

    @classmethod
    def load(cls, path: str) -> "Policy":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh) or {})

    def action_for(self, entity_type: str) -> str:
        return self.actions.get(entity_type.upper(), self.default_action)

    def threshold_for(self, entity_type: str) -> float:
        return self.thresholds.get(entity_type.upper(), self.threshold)


@dataclass
class Decision:
    """Ergebnis der Policy-Auswertung."""

    action: str
    findings: list[Finding]
    blocking_types: list[str]
    redacted_text: str

    @property
    def allowed(self) -> bool:
        return self.action != ACTION_BLOCK

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "blocking_types": self.blocking_types,
            "redacted_text": self.redacted_text,
            # Bewusst ohne Klartext der Fundstelle: diese Antwort wird geloggt.
            "findings": [
                {
                    "type": f.entity_type,
                    "start": f.start,
                    "end": f.end,
                    "score": round(f.score, 3),
                    "length": f.end - f.start,
                }
                for f in self.findings
            ],
        }


def scan_denylist(text: str, policy: Policy) -> list[Finding]:
    """Deterministische Regeln, die unabhaengig vom NER-Modell greifen."""
    out: list[Finding] = []
    for name, pattern in policy.denylist:
        for m in pattern.finditer(text):
            out.append(
                Finding(
                    entity_type=name,
                    start=m.start(),
                    end=m.end(),
                    score=1.0,
                    text=m.group(0),
                )
            )
    return out


def filter_findings(findings: Iterable[Finding], policy: Policy) -> list[Finding]:
    """Wirft Treffer unter Schwellwert und Allowlist-Treffer weg."""
    kept: list[Finding] = []
    for f in findings:
        if f.score < policy.threshold_for(f.entity_type):
            continue
        if f.text.strip().lower() in policy.allowlist:
            continue
        kept.append(f)
    return _dedupe(kept)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Bei Ueberlappung gewinnt der Treffer mit hoeherem Score, dann der laengere."""
    ordered = sorted(findings, key=lambda f: (-f.score, -(f.end - f.start), f.start))
    kept: list[Finding] = []
    for f in ordered:
        if any(f.overlaps(k) for k in kept):
            continue
        kept.append(f)
    return sorted(kept, key=lambda f: f.start)


def redact(text: str, findings: Iterable[Finding]) -> str:
    """Ersetzt Fundstellen durch <TYP>. Von hinten, damit Offsets stabil bleiben."""
    out = text
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        out = f"{out[: f.start]}<{f.entity_type}>{out[f.end :]}"
    return out


def evaluate(text: str, findings: Iterable[Finding], policy: Policy) -> Decision:
    """Setzt Treffer und Policy zu einer Entscheidung zusammen."""
    all_findings = filter_findings(list(findings) + scan_denylist(text, policy), policy)

    action = ACTION_ALLOW
    blocking: list[str] = []
    to_redact: list[Finding] = []

    for f in all_findings:
        a = policy.action_for(f.entity_type)
        if a == ACTION_BLOCK:
            blocking.append(f.entity_type)
        if a in (ACTION_BLOCK, ACTION_REDACT):
            to_redact.append(f)
        if _RANK[a] > _RANK[action]:
            action = a

    # Fuer Logs und Fehlermeldungen wird immer vollstaendig geschwaerzt,
    # auch wenn die Policy nur 'allow' sagt.
    return Decision(
        action=action,
        findings=all_findings,
        blocking_types=sorted(set(blocking)),
        redacted_text=redact(text, to_redact),
    )
