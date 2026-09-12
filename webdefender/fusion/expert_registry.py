"""Independent threat-family expert registry."""
FAMILIES=(
    "phishing","credential_theft","malware","javascript",
    "redirect","privacy","social_engineering",
)
RULES=(
    "experts_consume_canonical_evidence_only",
    "expert_results_are_not_evidence",
    "derived_fusion_cannot_vote",
    "independence_is_by_provenance_not_label",
)
