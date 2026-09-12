"""Non-negotiable evidence pipeline invariants."""
INVARIANTS=(
 "rejected_evidence_never_resurrects",
 "derived_findings_never_vote_as_independent_experts",
 "feed_off_external_ioc_has_zero_vote_and_zero_score_weight",
 "trust_context_never_erases_independent_hard_threat_evidence",
 "zero_observed_surface_never_renders_clean",
 "severity_label_alone_never_creates_hard_evidence",
 "brand_mention_without_first_party_claim_and_sensitive_action_is_not_phishing_proof",
)
