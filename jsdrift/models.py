"""Shared data model."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def sev_at_least(sev: str, floor: str) -> bool:
    return SEV_RANK.get(sev, 0) >= SEV_RANK.get(floor, 0)


def min_sev(a: str, b: str) -> str:
    return a if SEV_RANK[a] <= SEV_RANK[b] else b


def mask(value: str) -> str:
    """Redact a secret for display. Full values stay in the local DB only."""
    if "PRIVATE KEY" in value:
        m = re.match(r"-----BEGIN ([A-Z ]+)-----", value)
        return f"-----BEGIN {m.group(1) if m else 'PRIVATE KEY'}----- [{len(value)} chars redacted]"
    if len(value) <= 8:
        return f"{value[:1]}***({len(value)})"
    keep = 4 if len(value) < 24 else 6
    return f"{value[:keep]}…{value[-2:]} ({len(value)} chars)"


@dataclass
class Finding:
    kind: str                 # endpoint | route | param | host | secret | graphql | sourcemap
    value: str                # canonical value; identity = (kind, value)
    confidence: int = 50      # 0-100: how sure are we this is real, not noise
    severity: str = "low"     # info | low | medium | high | critical
    rule: str = ""
    hint: str = ""            # human hint (e.g. "open-redirect candidate")
    context: str = ""         # code snippet (secrets are masked)
    source: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    why: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.kind}\x00{self.value}".encode()).hexdigest()[:20]

    @property
    def display(self) -> str:
        return mask(self.value) if self.kind == "secret" else self.value

    def bump(self, delta: int, reason: str | None = None) -> None:
        self.confidence = max(0, min(99, self.confidence + delta))
        if reason:
            self.why.append(f"{'+' if delta >= 0 else ''}{delta} {reason}")
