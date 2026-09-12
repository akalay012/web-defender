"""Architecture ownership map for the modular engine."""
OWNERS = {
    "database": "webdefender.database",
    "url_domain": "webdefender.analyzer.url_domain",
    "browser_process_entrypoint": "webdefender.browser_worker.worker",
    "evidence_contracts": "webdefender.evidence.models",
    "pipeline_contract": "webdefender.analyzer.pipeline",
    "guard_policy": "webdefender.guards.policy",
    "fusion_policy": "webdefender.fusion.policy",
}
PIPELINE = (
    "sensors", "raw_observations", "guards", "canonical_evidence",
    "family_experts", "fusion", "decision_authority", "ui",
)
