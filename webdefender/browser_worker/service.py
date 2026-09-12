"""Browser observation service."""
from .policy import browser_policy
def safety_contract():
    return browser_policy()
