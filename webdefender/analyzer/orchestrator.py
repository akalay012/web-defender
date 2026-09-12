"""Main scan orchestration and zero-day behavior coordination.

The orchestrator orders sensors, guards, experts and final decision authority.
It does not redefine their evidence semantics.
"""
from ..state import DB_PATH
from ..state import LEARNING_ENGINE
from ..state import THREAT_INTEL_STORE
from ..database import db_connect
from ..analyzer.url_domain import read_limited_response
from ..analyzer.url_domain import registrable_domain_v21
from ..metadata import USER_AGENT
import requests
from ..analyzer.url_domain import host_is_private
from ..analyzer.url_domain import get_root_domain
from ..analyzer.url_domain import host_is_raw_ip
from ..analyzer.url_domain import normalize_url
from ..metadata import RUNNING_ON_PYTHONANYWHERE
from ..metadata import APP_VERSION
import os, re, json, time, hashlib, math, uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

class ScanOrchestratorMixin:
    def analyze_url(self, url):
        # V32.3.1 regression mode may be set by the Flask route or tests.
        self.results["_feed_off_v3231"] = bool(getattr(self, "feed_off_v3231", False))
        self.results["timings_v19"]={"started":datetime.now(timezone.utc).isoformat()}
        _v19_started=time.perf_counter()
        try: self.run_fast_pipeline_v19(normalize_url(url))
        except Exception: self.results["fast_pipeline_v19"]={"sensors":[],"state":"error"}
        self.results["hosting_environment"] = self.detect_hosting_environment()
        started = time.perf_counter()
        self.results["scan"]["started_at"] = datetime.now().isoformat()

        try:
            url = normalize_url(url)
        except Exception as exc:
            return {"error": str(exc), "risk_level": "GEÇERSİZ URL"}

        self.results["analyzed_url"] = url
        p = urlparse(url)
        host = p.hostname
        is_ip = host_is_raw_ip(host)
        root = get_root_domain(host) if not is_ip else host

        self.results["domain_info"].update({
            "domain": p.netloc, "hostname": host,
            "protocol": p.scheme,
            "port": p.port or (443 if p.scheme == "https" else 80),
            "is_ip": is_ip, "root_domain": root,
        })

        if host_is_private(host):
            self.results["errors"].append({
                "module": "target_validation",
                "error": "Yerel/private hedefler analiz edilmiyor.",
            })
            self.results["scan"]["status"] = "blocked"
# ── Katman 1: Bağlantısız kontroller ──────────────────────────────
        self.run_check("url_intelligence", self.check_url_intelligence, url)
        self.run_check("phishing_heuristics", self.check_phishing_heuristics, url)
        self.run_check("dns", self.check_dns, host)
        self.run_check("network_probe", self.probe_network, host)

        # ── Katman 2: HTTP ────────────────────────────────────────────────
        session = requests.Session()
        # Hosting profiline göre ağ yolu seçilir.
        if RUNNING_ON_PYTHONANYWHERE:
            session.trust_env = True
            self.results["http"]["network_mode"] = "pythonanywhere-env-proxy"
        else:
            session.trust_env = False
            self.results["http"]["network_mode"] = "direct-no-env-proxy"
        session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8",
            "Connection": "close",
        })

        try:
            t0 = time.perf_counter()
            response, redirect_chain, final_url, connection_attempts, used_http_fallback = self.fetch_with_scheme_fallback(session, url)

            # V32.3.15 — generic observation recovery for a common hostname-shape failure.
            # Some tenant/hosted applications exist at tenant.platform.tld but a user
            # (or phishing feed) supplies www.tenant.platform.tld. The extra `www` may
            # return a synthetic 4xx even though the actual tenant content is available.
            # We do NOT assume equivalence and never use this as a trust signal. We only
            # adopt the no-www observation when it independently returns a real 2xx body.
            # safe_get keeps the existing SSRF/redirect guards in force.
            _orig_status = int(getattr(response, "status_code", 0) or 0)
            _orig_host = (urlparse(final_url or url).hostname or "").lower()
            if 400 <= _orig_status < 500 and _orig_host.startswith("www."):
                try:
                    _fp = urlparse(final_url or url)
                    _alt_host = _orig_host[4:]
                    _alt_netloc = _alt_host + ((":" + str(_fp.port)) if _fp.port else "")
                    _alt_url = _fp._replace(netloc=_alt_netloc).geturl()
                    _ar, _ah, _af = self.safe_get(session, _alt_url)
                    _ast = int(_ar.status_code)
                    connection_attempts.append({"url": _alt_url, "ok": True, "status": _ast, "purpose": "no_www_observation_recovery"})
                    self.results["observation_recovery_v32315"] = {
                        "attempted": True, "original_url": final_url or url,
                        "original_status": _orig_status, "alternate_url": _alt_url,
                        "alternate_status": _ast, "adopted": bool(200 <= _ast < 300),
                        "rule": "alternate hostname observation is content recovery only; never a trust/safety override"
                    }
                    if 200 <= _ast < 300:
                        try: response.close()
                        except Exception: pass
                        response, redirect_chain, final_url = _ar, _ah, _af
                    else:
                        _ar.close()
                except Exception as _alt_exc:
                    self.results["observation_recovery_v32315"] = {
                        "attempted": True, "original_url": final_url or url,
                        "original_status": _orig_status, "adopted": False,
                        "error": str(_alt_exc)[:300]
                    }
            elapsed = (time.perf_counter() - t0) * 1000
            self.results["http"]["connection_attempts"] = connection_attempts
            self.results["http"]["used_http_fallback"] = used_http_fallback

            requested_scheme = urlparse(url).scheme.lower()
            https_attempt = next((a for a in connection_attempts
                                  if urlparse(a.get("url","")).scheme.lower() == "https"), None)
            if requested_scheme == "https" and https_attempt:
                self.results["http"]["https_reached"] = bool(https_attempt.get("ok"))
                self.results["http"]["https_transport_failed"] = not bool(https_attempt.get("ok"))

            # Only call this an HTTPS transport failure when HTTPS truly failed and
            # HTTP fallback returned an actual response. A 403 over HTTPS is still
            # HTTPS reachability, just access denial.
            if used_http_fallback and self.results["http"]["https_transport_failed"]:
                self.add_finding(
                    "HTTPS transport kurulamadı; HTTP fallback yanıtı alındı", "medium",
                    "İstenen HTTPS bağlantısı taşıma katmanında kurulamadı. Aynı host/path için HTTP yanıtı alındı. "
                    "Bu bulgu erişilebilirlik/transport bilgisidir; tek başına phishing veya malware kanıtı değildir.",
                    "network", final_url, 0.95,
                )
            content = read_limited_response(response)
            text = content.decode(response.encoding or "utf-8", errors="replace")
            status = int(response.status_code)
            is_2xx = 200 <= status < 300
            is_restricted = status in (401, 403, 429)
            is_5xx = 500 <= status < 600
            decision = ("content_analyzable" if is_2xx else
                        "access_restricted" if is_restricted else
                        "target_content_unavailable" if 400 <= status < 500 else
                        "upstream_error" if is_5xx else
                        "http_non_success")

            self.results["http"].update({
                "reachable": True,
                "body_analyzed": is_2xx,
                "content_trusted_for_analysis": is_2xx,
                "access_restricted": is_restricted,
                "decision": decision,
                "failure_kind": "" if is_2xx else decision,
                "status_code": status,
                "reason": response.reason,
                "response_time_ms": round(elapsed, 2),
                "content_type": response.headers.get("Content-Type", ""),
                "content_length": len(content),
                "server": response.headers.get("Server", ""),
                "powered_by": response.headers.get("X-Powered-By", ""),
            })
            self.results["final_url"] = final_url
            self.results["http"]["redirects"] = redirect_chain
            self.results["source_analysis_v32315"] = {
                "body_observed": bool(is_2xx),
                "bytes_observed": len(content) if is_2xx else 0,
                "static_code_analysis_available": bool(is_2xx),
                "reason": "target_body_available" if is_2xx else decision,
                "recovery": self.results.get("observation_recovery_v32315") or {"attempted": False},
                "rule": "HTML/JS/source-code claims are emitted only from the actual observed target body, never from a 4xx/WAF/challenge page."
            }
            self.results["http"]["redirect_count"] = len(redirect_chain)

            # Error/challenge headers may belong to CDN/WAF/proxy, not the app.
            self.results["http"]["response_headers_metadata"] = {
                str(k): str(v)[:1000] for k, v in response.headers.items()
            }

            if is_2xx:
                self.run_check("security_headers", self.check_security_headers, response.headers)
                self.run_check("cookies", self.check_cookies, response)
                self.run_check("cors", self.check_cors, response.headers)
                self.run_check("csp", self.check_csp, response.headers)
                self.run_check("technology", self.check_technology, response, text)
                self.run_check("html", self.check_html, text, final_url)
                self.run_check("patterns", self.check_suspicious_patterns, text)
                self.run_check("mixed_content", self.check_mixed_content, text, final_url)
                self.run_check("page_phishing", self.check_page_phishing_signals, text, final_url)
                self.run_check("static_source_intelligence_v32317", self.static_source_intelligence_v32317, text, final_url)
                self.run_check("web_defender", self.check_advanced_defender, text, final_url)
                self.results["defender"]["content_status"] = "analyzed"
                self.results["defender"]["passive_only"] = False
            elif is_restricted:
                self.results["defender"]["content_status"] = "access_restricted"
                self.results["defender"]["passive_only"] = True
            elif is_5xx:
                self.results["defender"]["content_status"] = "upstream_error"
                self.results["defender"]["passive_only"] = True
            else:
                self.results["defender"]["content_status"] = "http_non_success"
                self.results["defender"]["passive_only"] = True

        except requests.exceptions.SSLError as exc:
            self.results["http"]["failure_kind"] = "tls"
            self.results["defender"]["content_status"] = "unavailable"
            self.results["defender"]["passive_only"] = True
            self.results["errors"].append({"module": "http_tls", "error": str(exc)})
            self.add_finding(
                "TLS/SSL Bağlantı Hatası", "high",
                "Sertifika geçersiz veya sahte olabilir.",
                "tls", str(exc)[:300], 0.95,
            )
        except (requests.exceptions.ConnectionError,
                requests.exceptions.RequestException) as exc:
            msg = str(exc)
            kind = "proxy" if "proxy" in msg.lower() or "tunnel" in msg.lower() else "connection"
            self.results["http"]["failure_kind"] = kind
            self.results["defender"]["content_status"] = "unavailable"
            self.results["defender"]["passive_only"] = True
            if self.results.get("hosting_environment", {}).get("pythonanywhere") and (
                "403" in msg or "Connection refused" in msg or "ProxyError" in msg
            ):
                msg += " | PythonAnywhere outbound allowlist/proxy kısıtı olası; bu hata hedef siteye atfedilmemelidir."
            self.results["errors"].append({"module": "http", "error": msg})

        # Derin analizde Chromium davranış katmanı HER public HTTP(S) hedefte çalışır.
        # SPA/React/Vue/Next sayfalarında statik 200 yanıtı gerçek DOM'u göstermeyebilir.
        # Worker hiçbir formu doldurmaz/göndermez; yalnızca yükleme sırasında oluşan DOM ve ağ davranışını gözlemler.
        self.run_browser_worker(self.results.get("final_url") or url)
        self.run_check("content_acquisition_v32316", self.finalize_content_acquisition_v32316, url)

        # ── Katman 3: TLS ve yardımcı kontroller ──────────────────────────
        self.run_check("ssl", self.check_ssl_certificate,
                       host, self.results["domain_info"]["port"])
        self.run_check("trust_context_v21", self.run_trust_context_v21)
        base = self.results["final_url"] or url
        self.run_check("robots",      self.check_well_known, session, base, "robots.txt",                "robots_txt")
        self.run_check("security_txt",self.check_well_known, session, base, ".well-known/security.txt", "security_txt")
        self.run_check("sitemap",     self.check_well_known, session, base, "sitemap.xml",              "sitemap")
        # Katman 4: İçerik olmasa da URL/DNS/TLS/ağ metadatasından pasif risk çıkar.
        self.run_check("passive_defender", self.check_passive_defender, url)
        # V15: runtime korelasyon + güncel IOC + güvenli CVE zenginleştirme.
        self.run_check("generic_runtime_risk", self.check_generic_runtime_risk, url)
        self.run_check("domain_impersonation_v32313", self.domain_impersonation_guard_v32313, url)
        try:
            _gu=self.results.get("final_url") or url
            _gh=(urlparse(_gu).hostname or "").lower()
            if _gh:
                THREAT_INTEL_STORE.graph_edge("url",_gu,"has-host","domain",_gh,"WebDefender",95,evidence={"scan":True})
                for _ip in (self.results.get("dns",{}).get("ips") or []):
                    THREAT_INTEL_STORE.graph_edge("domain",_gh,"resolves-to","ip",_ip,"WebDefender",90,evidence={"scan":True})
        except Exception: pass
        self.run_check("local_threat_intel", self.check_local_threat_intel, self.results.get("final_url") or url)
        self.run_check("threat_intelligence", self.check_live_threat_intelligence, self.results.get("final_url") or url)
        self.run_check("malware_intelligence", self.check_malware_intelligence, self.results.get("final_url") or url)
        self.run_check("cve_intelligence", self.check_cve_intelligence)
        self.run_check("cisa_kev", self.check_cisa_kev)
        self.run_check("multi_evidence_fusion", self.build_multi_evidence_fusion)
        self.build_feature_vector()
        self.apply_local_learning()
        self.hydrate_semantic_sources_v19_1()
        self.run_identity_semantic_v18()
        self.build_identity_trust_v21()
        self.run_network_behavior_v22()
        self.run_js_payload_v23()
        self.run_visual_impersonation_v24()
        self.run_visual_similarity_v27()
        self.run_check("independent_phishing_v323", self.independent_phishing_engine_v323)
        self.run_check("behavioral_brain_v3234", self.behavioral_brain_v3234)
        self.run_check("phishing_observatory_v3231", self.phishing_sensor_observatory_v3231)
        self.run_check("credential_deep_observatory_v32328", self.credential_flow_deep_observatory_v32328)
        self.run_check("differential_observation_v32331", self.differential_observation_engine_v32331)
        self.run_check("non_executing_interaction_v324", self.non_executing_interaction_analysis_v324)
        self.run_check("javascript_dataflow", self.trace_javascript_dataflow)
        # V32.4.2: temporal_threat_memory moved to post-guard position (see below)
        self.update_threat_graph_v25()
        self.register_evidence_v26()
        self.build_active_learning_v26()
        self.build_calibration_snapshot_v29()
        self.build_self_evolution_guard_v30()
        self.build_v31_status()
        # V32.4.2: V17 is observation-only. It fills behavioral_fusion_v17
        # for diagnostics but no longer calls add_finding(). Score production
        # is the exclusive domain of the post-guard canonical pipeline.
        self.run_behavioral_fusion_v17()
        self.run_check("evidence_semantics_v321", self.apply_evidence_semantics_v321)
        self.run_check("source_level_behavior_guard_v322", self.source_level_behavior_guard_v322)
        self.run_check("identity_claim_guard_v322", self.identity_claim_guard_v322)
        self.run_check("behavioral_intent_gate_v3226", self.behavioral_intent_gate_v3226)
        self.run_check("identity_context_guard_v323", self.identity_and_context_guard_v323)
        self.run_check("legacy_brand_noise_guard_v3234", self.legacy_brand_noise_guard_v3234)
        self.run_check("access_restricted_guard_v3232", self.access_restricted_evidence_guard_v3232)
        self.run_check("feed_off_guard_v3231", self.feed_off_regression_guard_v3231)
        self.run_check("canonical_evidence_v322", self.rebuild_scoring_evidence_v322)
        self.run_check("zero_day_behavior_v32", self.run_zero_day_behavior_v32)
        self.run_check("evidence_bus_v3236", self.build_evidence_bus_v3236)
        self.run_check("causal_destination_graph_v3238", self.causal_destination_ownership_graph_v3238)
        self.run_check("behavior_semantics_gate_v3237", self.behavior_semantics_identity_causality_gate_v3237)
        self.run_check("evidence_independence_ownership_v32325", self.evidence_independence_ownership_guard_v32325)
        self.run_check("post_guard_phishing_fusion_v32310", self.post_guard_phishing_fusion_v32310)
        # V32.4.2: Temporal memory runs post-guard so it reads only settled findings.
        # Its finding (if any) re-enters as historical_evidence provenance, not as a new expert.
        self.run_check("temporal_history", self.analyze_temporal_history)
        self.run_check("canonical_evidence_post_guard_v32310", self.rebuild_scoring_evidence_v322)
        self.run_check("multi_evidence_fusion_post_identity", self.build_multi_evidence_fusion)
        self.apply_provenance_fusion_guard_v26()
        self.calculate_scores()
        self.run_check("causal_evidence_gate_v3224", self.causal_evidence_gate_v3224)
        self.run_check("canonical_scoring_v3222", self.canonical_scoring_authority_v3222)
        self.run_check("decision_authority_v32321", self.decision_authority_v32321)
        self.run_check("single_source_truth_v3223", self.publish_canonical_truth_v3223)
        self.run_check("dual_intelligence_v32320", self.publish_dual_intelligence_v32320)
        self.run_check("evidence_trace_v3231", self.evidence_trace_v3231)
        self.run_check("fusion_trace_v32310", self.fusion_trace_v32310)

        duration = time.perf_counter() - started
        self.results["scan"].update({
            "finished_at": datetime.now().isoformat(),
            "duration_seconds": round(duration, 3),
            "status": "completed",
        })
        self.calculate_coverage()
        try:
            LEARNING_ENGINE.save_scan(
                self.results["scan"]["scan_id"], url, host, self.results["risk_score"],
                self.results["risk_level"], self.results["defender"]["feature_vector"]
            )
            self.results["learning"]["stats"] = LEARNING_ENGINE.stats()
        except Exception as exc:
            self.results["errors"].append({"module":"learning_db", "error":str(exc)})
        self.build_coverage_v19()
        self.build_diagnostics_v19_1()
        self.run_check("pipeline_integrity_v3221", self.pipeline_integrity_v3221)
        self.run_check("verdict_consistency_v321", self.enforce_verdict_consistency_v321)
        self.run_check("assessment_final_v3223", self.build_explainable_assessment)
        self.results["timings_v19"]["total_ms"]=round((time.perf_counter()-_v19_started)*1000)
# ═══════════════════════════════════════════════════════════════════════
    # MODÜL 1 — URL INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════
        self.run_check("serialize_evidence_v3235", self.serialize_evidence_for_ui_v3235)
        self.run_check("target_access_v32313", self.classify_target_access_protection_v32313)
        self.run_check("canonical_verdict_ui_v32361", self.finalize_canonical_verdict_ui_v32361)
        self.run_check("temporal_persist", self.persist_temporal_observation)
        return self.results

    def non_executing_interaction_analysis_v324(self):
        """Fuse passive static handler reconstruction with browser listener registration.

        This module predicts reachable interaction paths without causing the interaction.
        It is deliberately not an exploit/automation engine.
        """
        static=self.results.get("static_source_intelligence_v32317") or {}
        st=static.get("non_executing_interaction_v324") or {}
        browser=self.results.get("browser") or {}
        listeners=browser.get("registered_listeners") or []
        runtime=browser.get("runtime_hooks") or {}
        proven=st.get("proven_paths") or []
        report={
          "mode":"non_executing_interaction_analysis",
          "static_handler_count":int(st.get("handler_count") or 0),
          "registered_listener_count":len(listeners) if isinstance(listeners,list) else 0,
          "registered_listeners":listeners[:100] if isinstance(listeners,list) else [],
          "proven_static_paths":proven[:20],
          "proven_static_path_count":len(proven),
          "observed_runtime_submits":len(runtime.get("form_submits") or []) if isinstance(runtime,dict) else 0,
          "score_eligible":bool(proven),
          "interpretation":"A handler can be inspected without activating it. Potential paths remain context-only; only bounded sensitive-source -> unrelated-sink proof may vote.",
          "safety":"No click, typing, submit, credential entry, challenge bypass, or extracted-code execution is performed."
        }
        if proven:
            self.add_finding("Etkileşim tetiklenmeden kanıtlanan hassas veri → harici hedef yolu","critical",
                "Sayfanın kendi HTML/JavaScript kaynağında, kullanıcı etkileşimiyle çalışacak handler içinde hassas veri okuması ile farklı registrable domaine açık yazma hedefi aynı sınırlı kod yolunda kanıtlandı. Handler çalıştırılmadı.",
                "credential_theft",json.dumps({"paths":proven[:8]},ensure_ascii=False),.98)
            self.results["findings"][-1].update({"producer":"non_executing_interaction_v324","source_expert":"static_submission_exfil","independent_group":"static_source","evidence_lineage_id":"v324-nonexec-sensitive-crossroot"})
        self.results["non_executing_interaction_v324"]=report
        return report

    def _zero_day_behavior_v32(self):
        """Novel-threat behavioral inference. It never requires a reputation/IOC hit."""
        browser=self.results.get("browser") or {}
        http=self.results.get("http") or {}
        ident=self.results.get("identity_semantic_v18") or {}
        net=self.results.get("network_behavior_v22") or {}
        js=self.results.get("js_payload_v23") or {}
        behavior=self.results.get("behavioral_fusion_v17") or {}
        findings=self.results.get("findings") or []

        def blob(*objs):
            parts=[]
            for o in objs:
                try: parts.append(json.dumps(o,ensure_ascii=False,default=str).lower())
                except Exception: parts.append(str(o).lower())
            return " ".join(parts)

        # Never let derived findings/fusion vocabulary feed the detector back into itself.
        btxt=blob(browser,http,ident,net,js)
        evidence=[]

        def ev(group,family,weight,title,detail,confidence=.8):
            evidence.append({"group":group,"family":family,"weight":float(weight),
                             "title":title,"detail":detail,"confidence":float(confidence)})

        # 1) Credential-flow behavior.
        sensitive=any(x in btxt for x in ["password","passwd","otp","one-time","verification code",
                                          "cvv","cvc","card number","iban","pin"])
        writes=any(x in btxt for x in ["post","sendbeacon","xmlhttprequest","fetch","form_action","form action"])
        cross=any(x in btxt for x in ["cross-site","cross_site","cross-origin","cross_origin","external domain"])
        if sensitive and writes and cross:
            ev("credential_flow","credential_theft",28,"Hassas veri + harici yazma akışı",
               "Hassas giriş sinyali ile cross-origin POST/fetch/beacon/form davranışı birlikte gözlendi.",.94)
        elif sensitive and writes:
            ev("credential_flow","credential_theft",13,"Hassas veri gönderim akışı",
               "Hassas giriş ile veri yazma davranışı birlikte gözlendi; hedef bağımsızlığı doğrulanamadı.",.72)

        # 2) Dynamic/obfuscated JS behavior.
        dynamic=any(x in btxt for x in ['"eval_like": true','"eval_like":true',"new function","eval("])
        decoder=any(x in btxt for x in ['"decoder_like": true','"decoder_like":true',"atob(","fromcharcode","decodeuricomponent"])
        anti_blob=blob(browser.get("script_signals") or {})
        anti=any(x in anti_blob for x in ["webdriver","devtools","debugger","anti-analysis","anti_analysis"])
        exfil_api=any(x in blob(browser.get("runtime_hooks") or {}, js) for x in ["sendbeacon","xmlhttprequest","fetch("])
        if dynamic and decoder and (anti or exfil_api):
            ev("dynamic_js","suspicious_script",24,"Dinamik/obfuscated JavaScript zinciri",
               "Decoder + dinamik kod çalıştırma ve anti-analysis/exfil API sinyalleri korelasyon gösterdi.",.90)
        elif dynamic and decoder:
            ev("dynamic_js","suspicious_script",12,"Obfuscated JavaScript bağlamı",
               "Decoder ve dinamik kod sinyalleri birlikte görüldü.",.70)

        # 3) Delayed/staged payload behavior. V32.3.24 strict causal gate.
        # Never infer malware from words such as "stage", "payload", "sha256" found in
        # our own diagnostics/findings. We require two concrete runtime observations:
        #   (a) an observed timer/stage primitive, AND
        #   (b) an observed download/payload artifact from the browser/download sensor.
        # This prevents the detector from reading its own vocabulary and feeding it back.
        script_signals=browser.get("script_signals") or {}
        runtime_hooks=browser.get("runtime_hooks") or {}
        downloads=browser.get("downloads") or self.results.get("downloads") or []
        if not isinstance(downloads,list): downloads=[]
        sig_blob=blob(script_signals,runtime_hooks)
        concrete_timer=any(x in sig_blob for x in ["settimeout","setinterval","timer_created","delayed_execution","second_stage"])
        concrete_download=bool(downloads)
        # A captured malware/download object may live in the dedicated intelligence result.
        mal=self.results.get("malware_intelligence") or {}
        if isinstance(mal,dict):
            concrete_download = concrete_download or bool(mal.get("downloaded_files") or mal.get("observed_downloads") or mal.get("file_hashes"))
        if concrete_timer and concrete_download:
            ev("staged_payload","malware",22,"Gecikmeli/staged payload davranışı",
               "Runtime zamanlayıcı/stage sinyali ile somut indirme/payload artefaktı aynı çalıştırmada gözlendi.",.86)

        # 4) Cloaking / anti-analysis. Must be corroborated to become strong.
        diff=self.results.get("differential_observation_v32331") or {}
        discrepancy=bool(diff.get("conditional_delivery_signal"))
        if anti and discrepancy:
            ev("cloaking","cloaking",23,"Anti-analysis + içerik ayrışması",
               "Headless/devtools/webdriver kontrolü ile HTTP/Browser içerik ayrışması birlikte gözlendi.",.91)
        elif anti:
            ev("cloaking","cloaking",9,"Anti-analysis sinyali",
               "Tarayıcı/analiz ortamını ayırt etmeye yönelik kod sinyali görüldü; tek başına hüküm değildir.",.65)

        # 5) Redirect abuse / navigation chain.
        redirects=browser.get("navigations") or browser.get("redirects") or http.get("redirect_history") or []
        try: rcount=len(redirects)
        except Exception: rcount=0
        redir_cross=any(x in btxt for x in ["cross-site redirect","cross_site_redirect","external redirect"])
        if rcount>=3 and (redir_cross or sensitive):
            ev("redirect_chain","redirect_abuse",17,"Çok aşamalı yönlendirme davranışı",
               f"{rcount} runtime/HTTP navigation ile hassas veya cross-site bağlam korele edildi.",.82)

        # 6) Runtime anomaly: popup/websocket + sensitive/exfil context.
        webs=browser.get("websockets") or []
        popups=browser.get("popups") or browser.get("popup_urls") or []
        if (webs or popups) and (sensitive or exfil_api):
            ev("runtime_anomaly","runtime_anomaly",15,"Runtime kanal anomalisi",
               "WebSocket/popup davranışı hassas veya veri aktarım bağlamıyla birlikte gözlendi.",.78)

        # 7) Derived/canonical findings are intentionally NOT re-consumed here.
        # Rejected/context-only evidence must never resurrect as an independent behavioral vote.

        # Known IOC is deliberately metadata, not a prerequisite and not a zero-day bonus.
        ti_blob=blob(self.results.get("threat_intelligence") or {}, self.results.get("local_threat_intel") or {}, self.results.get("malware_intelligence") or {})
        known_ioc=any(k in ti_blob for k in ["urlhaus","threatfox","openphish","phishtank","known malicious","sha-256 ioc","sha256 ioc"])
        # Dedupe: strongest evidence per independent group contributes to score.
        strongest={}
        for e in evidence:
            if e["group"] not in strongest or e["weight"]>strongest[e["group"]]["weight"]:
                strongest[e["group"]]=e
        selected=list(strongest.values())
        groups=set(strongest)
        raw=sum(e["weight"]*e["confidence"] for e in selected)
        # Independent corroboration is central. One behavioral modality cannot create a critical zero-day verdict.
        bonus=0
        if len(groups)>=2: bonus=10
        if len(groups)>=3: bonus=20
        if len(groups)>=4: bonus=28
        score=min(100,round(raw+bonus))
        confidence=min(.98, round((sum(e["confidence"] for e in selected)/max(1,len(selected))) *
                                  (0.78 if len(groups)<2 else 0.92),3))
        if len(groups)<2:
            score=min(score,39)
        if score>=70 and len(groups)>=3:
            verdict="high_confidence_behavioral_threat"
        elif score>=45 and len(groups)>=2:
            verdict="suspicious_behavior"
        elif score>=20:
            verdict="behavioral_watch"
        else:
            verdict="insufficient_behavioral_evidence"

        families=sorted(set(e["family"] for e in selected))
        return {"score":score,"confidence":confidence,"verdict":verdict,
                "independent_groups":sorted(groups),"behavior_families":families,
                "evidence":selected,"known_ioc":bool(known_ioc),
                "principle":"IOC/reputation hit gerekli değildir; karar yalnız gözlenen bağımsız davranış kanıtlarından oluşur."}

    def run_zero_day_behavior_v32(self):
        z=self._zero_day_behavior_v32()
        if self.results.get("_feed_off_v3231"):
            z["known_ioc"]=False; z["external_intelligence_score_eligible"]=False
        self.results["zero_day_behavior_v32"]=z
        # Feed the canonical finding/fusion system only when at least two independent behavioral modalities corroborate.
        groups=len(z.get("independent_groups") or [])
        if z["score"]>=45 and groups>=2:
            severity="critical" if z["score"]>=70 and groups>=3 else "high"
            desc=("IOC/reputation bağımsız davranış korelasyonu: "+", ".join(z["behavior_families"]) +
                  f". {groups} bağımsız davranış grubu, skor {z['score']}/100.")
            self.add_finding("V32 davranışsal yeni-tehdit korelasyonu",severity,desc,"behavioral_zero_day",
                             evidence=z["evidence"],confidence=z["confidence"])
        # Persist observation for later verified regression. It is NOT ground truth.
        try:
            url=self.results.get("final_url") or self.results.get("analyzed_url") or ""
            oid="zd_"+uuid.uuid4().hex[:20]
            with db_connect(DB_PATH,timeout=10) as con:
                con.execute("""INSERT INTO zero_day_observations_v32
                  (observation_id,created_at,url_hash,registrable_domain,score,confidence,verdict,
                   independent_groups,behavior_families,evidence,known_ioc,scan_version)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (oid,datetime.now(timezone.utc).isoformat(),hashlib.sha256(str(url).encode()).hexdigest(),
                   registrable_domain_v21(urlparse(str(url)).hostname or ""),z["score"],z["confidence"],
                   z["verdict"],groups,json.dumps(z["behavior_families"]),json.dumps(z["evidence"]),
                   1 if z["known_ioc"] else 0,APP_VERSION))
            z["observation_id"]=oid
        except Exception as exc:
            z["persistence_error"]=str(exc)[:300]
        return z

    def hydrate_semantic_sources_v19_1(self):
        """Create canonical title/meta/text fields from captured HTTP/browser HTML."""
        for name in ("http","browser"):
            src=self.results.get(name,{}) or {}
            raw=src.get("html") or src.get("content") or src.get("body")
            if not raw: continue
            try:
                if isinstance(raw,bytes): raw=raw.decode("utf-8","replace")
                soup=BeautifulSoup(raw,"html.parser")
                if not src.get("title") and soup.title:
                    src["title"]=soup.title.get_text(" ",strip=True)
                if not src.get("description"):
                    m=soup.find("meta",attrs={"name":re.compile("^description$",re.I)})
                    if m and m.get("content"): src["description"]=m["content"]
                if not src.get("og_title"):
                    m=soup.find("meta",attrs={"property":"og:title"})
                    if m and m.get("content"): src["og_title"]=m["content"]
                if not src.get("visible_text"):
                    clone=BeautifulSoup(raw,"html.parser")
                    for bad in clone(["script","style","noscript","template"]): bad.decompose()
                    src["visible_text"]=clone.get_text(" ",strip=True)[:120000]
                self.results[name]=src
            except Exception: pass

    def build_diagnostics_v19_1(self):
        h=self.results.get("http",{}) or {}; b=self.results.get("browser",{}) or {}
        i=self.results.get("identity_semantic_v18",{}) or {}; f=self.results.get("behavioral_fusion_v17",{}) or {}
        def clip(x,n=600):
            if x is None:return None
            x=str(x).replace("\n"," ").strip()
            return x[:n]+("…" if len(x)>n else "")
        self.results["diagnostics_v19_1"]={
          "http":{"status_code":h.get("status_code"),"body_analyzed":bool(h.get("body_analyzed")),
                  "final_url":h.get("final_url"),"title":clip(h.get("title")),
                  "description":clip(h.get("description") or h.get("meta_description")),
                  "html_bytes":len(str(h.get("html") or "").encode("utf-8")),
                  "visible_text_sample":clip(h.get("visible_text") or h.get("text"))},
          "browser":{"attempted":bool(b.get("attempted")),"success":bool(b.get("success")),
                     "status_code":b.get("status_code"),"final_url":b.get("final_url"),"title":clip(b.get("title")),
                     "dom_length":b.get("dom_length"),"html_bytes":len(str(b.get("html") or "").encode("utf-8")),
                     "visible_text_sample":clip(b.get("visible_text") or b.get("text"))},
          "brand_engine":{"host":i.get("host"),"root_domain":i.get("root_domain"),"shared_hosting":i.get("shared_hosting"),
                          "detected_brands":i.get("detected_brands"),"brand_mismatches":i.get("brand_mismatches"),
                          "semantic_intents":i.get("semantic_intents"),"score":i.get("score"),"evidence":i.get("evidence")},
          "fusion":{"primary":f.get("primary"),"families":f.get("families")},
          "coverage":self.results.get("coverage_v19"),
          "network_behavior_v22":self.results.get("network_behavior_v22"),
          "js_payload_v23":self.results.get("js_payload_v23"),
          "visual_impersonation_v24":self.results.get("visual_impersonation_v24"),
          "threat_graph_v25":self.results.get("threat_graph_v25"),
          "evidence_provenance_v26":self.results.get("evidence_provenance_v26"),
          "active_learning_v26":self.results.get("active_learning_v26"),
          "visual_similarity_v27":self.results.get("visual_similarity_v27"),
          "decision_graph_v28":self.results.get("decision_graph_v28"),
          "calibration_v29":self.results.get("calibration_v29"),
          "self_evolution_guard_v30":self.results.get("self_evolution_guard_v30"),
          "live_discovery_v301":self.results.get("live_discovery_v301"),
          "v31":self.results.get("v31"),
          "zero_day_behavior_v32":self.results.get("zero_day_behavior_v32"),
          "source_level_behavior_guard_v322":self.results.get("source_level_behavior_guard_v322"),
          "identity_claim_guard_v322":self.results.get("identity_claim_guard_v322"),
          "canonical_evidence_v322":self.results.get("canonical_evidence_v322"),
          "behavioral_intent_gate_v3226":self.results.get("behavioral_intent_gate_v3226"),
          "contextual_findings_v322":self.results.get("contextual_findings_v322"),
          "evidence_semantics_v321":self.results.get("evidence_semantics_v321"),
          "verdict_consistency_v321":self.results.get("verdict_consistency_v321"),
          "pipeline_integrity_v3221":self.results.get("pipeline_integrity_v3221"),
          "canonical_scoring_v3222":self.results.get("canonical_scoring_v3222"),
          "single_source_truth_v3223":self.results.get("single_source_truth_v3223"),
          "identity_trust_v21":self.results.get("identity_trust_v21"),
          "trust_context_v21":self.results.get("trust_context_v21"),
          "safety_gate_v21":self.results.get("safety_gate_v21"),
          "findings":[{"title":x.get("title"),"severity":x.get("severity"),"category":x.get("category"),
                       "description":clip(x.get("description")),"confidence":x.get("confidence")}
                      for x in (self.results.get("findings",[]) or [])[-30:]]
        }

    def calculate_coverage(self):
        # Kapsam, modüllerin var olmasını değil gerçekten veri üretebilmesini ölçer.
        static_ok = bool(self.results["http"].get("content_trusted_for_analysis"))
        browser = self.results.get("browser", {})
        browser_ok = bool(browser.get("success"))
        weights={
            "dns":8,"probe":6,"http":12,"ssl":8,"url":8,"phishing_url":8,
            "static_content":14,"browser_runtime":22,"runtime_network":6,"runtime_dom":8
        }
        done=weights["url"]+weights["phishing_url"]
        if self.results["dns"].get("resolved"): done += weights["dns"]
        probe=self.results.get("network_probe",{})
        if probe.get("ports") and probe.get("authoritative", True): done += weights["probe"]
        if self.results["http"].get("status_code") is not None: done += weights["http"]
        if self.results["ssl_info"].get("valid"): done += weights["ssl"]
        if static_ok: done += weights["static_content"]
        if browser_ok:
            done += weights["browser_runtime"]
            # Successful worker means these surfaces were observed even when zero artifacts exist.
            done += weights["runtime_network"] + weights["runtime_dom"]
        self.results["scan"]["coverage"] = min(100, round(done/sum(weights.values())*100))
        self.results["scan"]["coverage_missing"] = ([] if browser_ok else [
            "browser_runtime", "runtime_network", "runtime_dom"
        ])

