"""Semantic intelligence service."""
from .sync import sync_all_threat_intel, sync_urlhaus_recent, sync_threatfox_recent, sync_tranco_v21
from .policy import decision_weight

def sync_sources():
    return sync_all_threat_intel()

def score_weight(feed_off: bool, producer: str) -> int:
    return decision_weight(feed_off, producer)
