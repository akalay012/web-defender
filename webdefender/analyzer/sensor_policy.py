"""Sensor semantics."""
THREAT_EVIDENCE_SENSORS=("malware_intelligence","runtime_behavior","causal_dataflow")
CONTEXT_ONLY_SENSORS=("rdap","asn","email_dns","trust_context","technology")
POSTURE_ONLY_SENSORS=("security_headers","csp","cookies")
INVARIANTS=(
 "configuration_weakness_is_not_threat_evidence",
 "tls_identity_is_not_brand_or_safety_proof",
 "domain_age_popularity_and_asn_are_context_only",
 "feed_miss_is_not_safe",
)
