"""Learning safety invariants."""
INVARIANTS=(
 "discovery_candidate_is_not_prediction",
 "prediction_is_not_verified_ground_truth",
 "only_verified_ground_truth_can_train_or_calibrate",
 "feedback_cannot_create_automatic_allowlists",
 "learned_weights_cannot_override_hard_safety_rules",
 "campaign_expansion_is_bounded_and_rate_limited",
)
