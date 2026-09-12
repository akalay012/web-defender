"""Temporary compatibility-shell contract."""
ALLOWED_RESPONSIBILITIES=(
 "legacy_import_compatibility",
 "analyzer_state_initialization",
 "finding_collection_primitive",
 "check_exception_boundary",
 "worker_environment_bootstrap",
)
FORBIDDEN_RESPONSIBILITIES=(
 "new_detection_rules",
 "new_scoring_authority",
 "new_final_verdict_logic",
 "new_http_routes",
)
