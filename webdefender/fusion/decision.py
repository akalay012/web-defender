"""Immutable final decision contract."""
from dataclasses import dataclass
from typing import Mapping
@dataclass(frozen=True)
class EngineDecision:
    engine_score:int
    category_scores:Mapping[str,int]
    final_score_owner:str="EngineDecision"
    def as_dict(self):
        return {"engine_score":int(self.engine_score),"category_scores":dict(self.category_scores),"final_score_owner":self.final_score_owner}
