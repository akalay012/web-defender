"""Canonical evidence guard policy."""
INVARIANTS=(
 "not_observed_is_not_safe",
 "feed_miss_is_not_safe",
 "trust_never_erases_hard_threat_evidence",
 "derived_evidence_never_votes_as_independent_expert",
 "prediction_is_not_ground_truth",
 "feed_off_external_intelligence_has_zero_decision_weight",
)

def is_hard_evidence_text(text: str) -> bool:
    text=(text or "").lower()
    if any(x in text for x in (
        "urlhaus","threatfox","sha-256","sha256","known malicious",
        "malware family","c2","command and control","exact ioc"
    )):
        return True
    source=any(x in text for x in (
        "password","parola","otp","cvv","cvc","cookie","token","credential"
    ))
    sink=any(x in text for x in (
        "cross-origin","cross origin","external destination","harici hedef",
        "sendbeacon","websocket","xhr post","fetch post","form action",
        "destination_host","sink_host"
    ))
    generic=(
        "storage/cookie + network + obfuscation" in text or
        "input events + network + obfuscation" in text
    )
    return bool(source and sink and not generic)

def external_intelligence_score_eligible(feed_off: bool, producer: str = "") -> bool:
    if not feed_off:
        return True
    p=(producer or "").lower()
    return not any(x in p for x in ("openphish","phishtank","urlhaus","threatfox","external_feed"))
