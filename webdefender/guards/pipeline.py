"""Canonical evidence guard pipeline."""
from dataclasses import replace
def reject(evidence, reason:str):
    return replace(evidence,score_eligible=False),reason
