"""Canonical fusion and final-decision policy.

Pure functions only. Sensors and guards cannot mutate final scores here.
"""
from typing import Mapping, Any

FINAL_SCORE_OWNER = "EngineDecision"
HISTORICAL_CONTEXT_IS_CURRENT_THREAT = False

def compute_final_decision(
    canonical: Mapping[str, Any],
    phishing_hypothesis: Mapping[str, Any],
    temporal_history: Mapping[str, Any] | None = None,
    feed_off: bool = False,
) -> dict:
    cats=dict((canonical or {}).get("category_scores") or {})
    phishing_score=max(0,min(100,int((phishing_hypothesis or {}).get("score") or 0)))
    legacy_phishing=int(cats.get("phishing") or 0)
    temporal=temporal_history or {}
    temporal_context=bool(temporal.get("score_eligible") and temporal.get("prior_hard_evidence"))

    # Historical context never manufactures a fresh phishing score.
    cats["phishing"]=phishing_score
    threat=max([int(v or 0) for v in cats.values()] or [0])

    return {
        "engine_score": threat,
        "category_scores": cats,
        "phishing_engine_score": phishing_score,
        "historical_threat_context": temporal_context,
        "legacy_phishing_diagnostic_score": legacy_phishing,
        "legacy_phishing_can_decide": False,
        "feed_off": bool(feed_off),
        "final_score_owner": FINAL_SCORE_OWNER,
    }
