"""Independent family expert contract."""
from dataclasses import dataclass
from typing import Sequence
@dataclass(frozen=True)
class ExpertResult:
    family:str
    score:int
    decisive:bool
    evidence_ids:Sequence[str]
    independent_groups:Sequence[str]
