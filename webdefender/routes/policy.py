"""Presentation boundary. Never recomputes threat."""
def decision_payload(result: dict) -> dict:
    r=result or {}
    authority=r.get("decision_authority_v32321") or {}
    return {"engine_score":int(authority.get("engine_score",r.get("risk_score",0)) or 0),
            "category_scores":dict(authority.get("category_scores") or {}),
            "final_score_owner":authority.get("final_score_owner","EngineDecision")}
