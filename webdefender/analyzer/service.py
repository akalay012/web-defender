"""Application analysis service."""
from ..engine import WebDefenderAnalyzer
def analyze(url: str) -> dict:
    return WebDefenderAnalyzer().analyze(url)
