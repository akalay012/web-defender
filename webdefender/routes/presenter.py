"""Presentation never recalculates threat."""
from .policy import decision_payload
def present(result:dict)->dict:
    return decision_payload(result)
