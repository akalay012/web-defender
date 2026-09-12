"""Threat-intelligence boundary policy.

Feeds are sensors. They never become the engine or ground truth merely by matching.
"""
EXTERNAL_PRODUCERS=("openphish","phishtank","urlhaus","threatfox","external_feed")

def is_external_producer(name: str) -> bool:
    n=(name or "").lower()
    return any(x in n for x in EXTERNAL_PRODUCERS)

def decision_weight(feed_off: bool, producer: str) -> int:
    return 0 if feed_off and is_external_producer(producer) else 1
