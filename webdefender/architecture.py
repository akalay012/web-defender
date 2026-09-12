"""V34 canonical ownership map."""
OWNERS={
 "application":"webdefender.application",
 "engine":"webdefender.engine",
 "analyzer_base":"webdefender.analyzer.base",
 "orchestrator":"webdefender.analyzer.orchestrator",
 "acquisition_sensors":"webdefender.analyzer.acquisition",
 "context_sensors":"webdefender.analyzer.context_sensors",
 "runtime_guards":"webdefender.guards.runtime",
 "family_experts":"webdefender.fusion.family_experts",
 "fusion_policy":"webdefender.fusion.policy",
 "decision_pipeline":"webdefender.fusion.decision_pipeline",
 "temporal_policy":"webdefender.evidence.temporal",
 "operational_learning":"webdefender.analyzer.operations",
 "routes":"webdefender.routes.web",
 "presentation":"webdefender.routes.template",
 "browser_worker":"webdefender.browser_worker.runtime",
 "compatibility_only":"webdefender.compatibility_core",
}
PIPELINE="Sensors -> Raw Observations -> Guards -> Canonical Evidence -> Independent Family Experts -> ONE Fusion -> ONE Decision -> UI"
