"""Passive browser-observation safety contract."""
PASSIVE_ONLY=True
FORBIDDEN_ACTIONS=("click","type","submit","credential_entry","challenge_bypass","execute_extracted_code")
def browser_policy():
    return {"passive_only":True,"forbidden_actions":list(FORBIDDEN_ACTIONS),
            "ephemeral_context":True,"private_network_blocked":True}
