"""Canonical analysis pipeline contract."""
PIPELINE_STAGES=("acquisition","raw_observations","evidence_guards","canonical_evidence",
                 "family_experts","fusion","decision_authority","presentation")
def validate_pipeline_order(stages=PIPELINE_STAGES):
    return tuple(stages) == PIPELINE_STAGES
