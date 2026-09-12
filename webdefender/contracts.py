from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class Observation:
    sensor: str
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    family: str
    producer: str
    confidence: float
    payload: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class ExpertResult:
    family: str
    score: int
    confidence: float
    evidence_ids: tuple[str, ...] = ()

@dataclass(frozen=True)
class EngineDecision:
    score: int
    verdict: str
    categories: dict[str, int]
    evidence_ids: tuple[str, ...] = ()
    blind_spots: tuple[str, ...] = ()
