"""Canonical evidence normalization rules."""
import hashlib, re

def stable_evidence_id(value) -> str:
    raw=re.sub(r"\s+"," ",str(value or "")).strip().lower()
    return hashlib.sha256(raw.encode("utf-8","ignore")).hexdigest()[:24]

def is_derived_evidence(finding: dict) -> bool:
    return bool((finding or {}).get("derived_evidence"))

def independent_group(finding: dict) -> str:
    f=finding or {}
    return str(f.get("independent_group") or f.get("source_expert") or f.get("producer") or "").strip().lower()
