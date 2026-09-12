"""Temporal evidence policy."""
MAX_RECENT_HARD_DAYS=30
RULES=(
    "prediction_is_not_ground_truth",
    "external_feed_only_history_is_not_internal_hard_authority",
    "historical_context_does_not_manufacture_current_threat",
    "hard_history_requires_verified_ioc_hash_or_settled_causal_evidence",
)
def may_influence_context(provenance: str, verified: bool) -> bool:
    p=(provenance or "").lower()
    external=any(x in p for x in ("openphish","phishtank","urlhaus","threatfox","external_feed"))
    return bool(verified and not external)
