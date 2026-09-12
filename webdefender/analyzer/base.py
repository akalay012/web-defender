"""Analyzer lifecycle and finding collection primitives."""
from ..metadata import RUNNING_ON_PYTHONANYWHERE
from ..metadata import APP_VERSION
import shutil
import uuid
import os, sys, json, subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse
from ..state import LEARNING_ENGINE, THREAT_INTEL_STORE

class AnalyzerBase:
    def __init__(self, url=None, feed_off=False):
        self.feed_off_v3231 = bool(feed_off)
        self.initial_url = str(url or "").strip()
        self.results = {
            "analyzed_url": "",
            "final_url": "",
            "scan": {
                "status": "started", "started_at": "", "finished_at": "",
                "scan_id": uuid.uuid4().hex,
                "duration_seconds": 0, "coverage": 0,
            },
            "http": {
                "status_code": None, "reason": "", "response_time_ms": None,
                "content_type": "", "content_length": 0,
                "server": "", "powered_by": "",
                "redirects": [], "redirect_count": 0,
                "reachable": False, "body_analyzed": False, "content_trusted_for_analysis": False, "access_restricted": False, "https_reached": False, "https_transport_failed": False, "decision": "not_run", "network_mode": "direct",
                "failure_kind": "", "connection_attempts": [], "used_http_fallback": False,
            },
            "network_probe": {"host": "", "ports": {}, "summary": "not_run"},
            "domain_info": {
                "domain": "", "hostname": "", "protocol": "", "port": None,
                "ips": [], "is_ip": False, "root_domain": "",
            },
            "url_intelligence": {
                "path": "", "query_count": 0, "parameters": [],
                "encoded_parameters": [], "tracking_parameters": [],
                "redirect_parameters": [], "sensitive_parameter_names": [],
                "double_encoded": False, "brand_in_path": [],
                "brand_in_params": [], "login_page": False,
                "suspicious_tld": False, "typosquatting_signals": [],
            },
            "dns": {"resolved": False, "addresses": [], "error": ""},
            "ssl_info": {
                "checked": False, "valid": False, "version": "",
                "issuer": {}, "subject": {}, "not_before": "", "not_after": "",
                "days_remaining": None, "error": "",
            },
            "security_headers": {},
            "cookies": [],
            "cors": {},
            "csp": {"present": False, "value": "", "directives": {}, "issues": []},
            "technology": [],
            "threat_intelligence": {"sources": [], "matches": [], "errors": [], "checked": False},
            "cve_intelligence": {"products": [], "candidates": [], "kev_matches": [], "note": "CVE eşlemesi yalnızca gözlenen ürün/sürüm parmak izlerine dayanır; exploit testi yapılmaz."},
            "scripts": [],
            "forms": [],
            "iframes": [],
            "links": [],
            "mixed_content": [],
            "suspicious_patterns": [],
            "phishing_signals": [],
            "defender": {
                "engine": f"Web Defender Local {APP_VERSION}", "external_davranış analizi": False,
                "content_status": "not_attempted", "passive_only": False,
                "threat_types": [], "correlations": [], "behavior_score": 0,
                "recommendations": [], "feature_vector": {},
                "passive_analysis": {"score": 0, "signals": [], "classification": "not_run"},
                "assessment": {"primary": {}, "categories": [], "evidence": [], "plain_summary": "", "action": ""},
                "fusion": {"score": 0, "verdict": "no_evidence", "primary": "", "categories": [], "experts": [], "chains": [], "independent_experts": 0},
            },
            "browser": {
                "attempted": False, "available": None, "success": False,
                "status_code": None, "final_url": "", "title": "",
                "dom_length": 0, "requests": [], "blocked_requests": [],
                "console_errors": [], "error": "", "duration_ms": None, "decision": "not_run", "failure_kind": "", "proxy_mode": "", "proxy_server": ""
            },
            "downloads": [],
            "learning": {"active": False, "probability": None, "sample_count": 0, "stats": {}},
            "well_known": {"robots_txt": {}, "security_txt": {}, "sitemap": {}},
            "findings": [],
            "errors": [],
            "scores": {"security_posture": None, "threat": 0, "confidence": 0},
            "risk_level": "✅ BELİRLİ TEHDİT SİNYALİ YOK",
            "risk_score": 0,
        }

    def add_finding(self, title, severity, description, category,
                    evidence=None, confidence=1.0):
        self.results["findings"].append({
            "title": title,
            "severity": severity,
            "description": description,
            "category": category,
            "evidence": evidence or "",
            "confidence": round(confidence, 2),
        })

    def run_check(self, name, fn, *args):
        try:
            fn(*args)
        except Exception as exc:
            self.results["errors"].append({"module": name, "error": str(exc)})

    def detect_hosting_environment(self):
        is_pa = bool(RUNNING_ON_PYTHONANYWHERE)
        proxy_present = any(os.environ.get(k) for k in (
            "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"
        ))
        chromium = "/usr/bin/chromium" if os.path.exists("/usr/bin/chromium") else None
        return {
            "provider": "pythonanywhere" if is_pa else "generic",
            "pythonanywhere": is_pa,
            "outbound_policy": "pythonanywhere-proxy/allowlist-account-dependent" if is_pa else "normal",
            "proxy_env_present": proxy_present,
            "chromium_path": chromium,
            "raw_tcp_authoritative": not is_pa,
        }

    def resolve_worker_python(self):
        """Gerçek Python interpreter'ını bul; uWSGI/Gunicorn launcher kullanma."""
        candidates = []
        explicit = os.environ.get("WEB_DEFENDER_PYTHON_BIN", "").strip()
        if explicit:
            candidates.append(explicit)
        base_exe = getattr(sys, "_base_executable", None)
        if base_exe:
            candidates.append(base_exe)
        if sys.executable:
            candidates.append(sys.executable)
        for name in ("python3", "python"):
            found = shutil.which(name)
            if found:
                candidates.append(found)
        for ver in ("3.13", "3.12", "3.11", "3.10", "3.9"):
            candidates += [f"/usr/local/bin/python{ver}", f"/usr/bin/python{ver}"]

        seen=set()
        for candidate in candidates:
            if not candidate:
                continue
            candidate=os.path.realpath(candidate)
            if candidate in seen:
                continue
            seen.add(candidate)
            base=os.path.basename(candidate).lower()
            if "uwsgi" in base or "gunicorn" in base:
                continue
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return None

