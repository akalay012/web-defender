"""Canonical evidence contract."""
from dataclasses import dataclass
from typing import Any
@dataclass(frozen=True)
class CanonicalEvidence:
    evidence_id:str
    family:str
    producer:str
    independent_group:str
    score_eligible:bool
    derived:bool
    payload:Any=None
