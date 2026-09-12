"""Evidence guards and pipeline-integrity mixin.

Rejected evidence cannot re-enter the pipeline. Context/trust may invalidate an
impersonation hypothesis but cannot erase independent hard malicious evidence.
"""
from ..guards.pipeline import reject
import re, json, hashlib, math
from urllib.parse import urlparse

from ..guards.policy import is_hard_evidence_text
from ..evidence.policy import stable_evidence_id, is_derived_evidence, independent_group
from ..analyzer.url_domain import get_root_domain, get_canonical_root
from ..analyzer.identity import BRAND_KEYWORDS, LEGITIMATE_BRAND_DOMAINS, legitimate_brand_root

class EvidenceGuardsMixin:
    def apply_safety_gate_v21(self):
        """Fail-safe verdict invariant: strong malicious evidence can never be neutralized by trust."""
        findings=self.results.get("findings",[]) or []
        fusion=self.results.get("defender",{}).get("fusion",{}) or {}
        hard=[]
        hard_categories={"malware","credential_theft","data_exfiltration","cloaking"}
        hard_terms=("sha-256 ioc eşleşmesi","urlhaus","threatfox","c2","credential exfil","veri sızdır","known malicious")
        for f in findings:
            cat=str(f.get("category","")).lower()
            sev=str(f.get("severity","")).lower()
            blob=(str(f.get("title",""))+" "+str(f.get("description",""))+" "+str(f.get("evidence",""))).lower()
            if sev=="critical" and (cat in hard_categories or any(x in blob for x in hard_terms)):
                hard.append(f)
        independent=int(fusion.get("independent_experts") or 0)
        score=fusion.get("score")
        forced=None
        if hard:
            forced="🚨 TEHLİKELİ"
        elif isinstance(score,(int,float)) and score>=45 and independent>=2:
            forced="⚠️ ŞÜPHELİ / YÜKSEK RİSK"
        if forced:
            self.results["risk_level"]=forced
        self.results["safety_gate_v21"]={"triggered":bool(forced),"forced_verdict":forced,
            "hard_evidence":[{"title":f.get("title"),"category":f.get("category"),"severity":f.get("severity")} for f in hard[:10]],
            "fusion_score":score,"independent_experts":independent,
            "invariant":"Trust/itibar/domain yaşı/Tranco/TLS güçlü tehdit kanıtını bastıramaz."}

    def apply_evidence_semantics_v321(self):
        """False-positive hardening + event provenance."""
        findings=list(self.results.get("findings") or [])
        browser=self.results.get("browser") or {}
        identity=self.results.get("identity_semantic_v18") or {}
        passive=self._v321_text({"links":self.results.get("links") or [],
          "scripts":self.results.get("scripts") or [],"technology":self.results.get("technology") or {}})
        strong=self._v321_text({"title":browser.get("title"),"description":browser.get("description"),
          "og_title":browser.get("og_title"),"h1":browser.get("h1"),"identity":identity})
        out=[]; seen=set(); generic_n=brand_n=0
        for orig in findings:
            f=dict(orig); text=self._v321_text(f); hard=self._v321_is_hard_evidence(f)
            sensitive=any(x in text for x in ("password","passwd","otp","verification code","cvv","cvc","card number","iban","pin"))
            external=any(x in text for x in ("cross-origin","cross_origin","cross-site","cross_site","external sink","external_sink","harici hedef"))
            generic=((("cookie" in text or "storage" in text or "depolama" in text) and "network" in text)
                     or (("input event" in text or "girdi yakalama" in text or "klavye" in text) and "network" in text))
            if generic and not hard and not (sensitive and external):
                f["severity"]="low"; f["confidence"]=min(float(f.get("confidence") or .5),.30)
                f["description"]="Genel web uygulaması telemetry davranışı; hassas kaynak → harici hedef bağı kurulamadı."
                f["evidence_semantics_v321"]="context_only"; generic_n+=1

            text2=self._v321_text(f); cat=str(f.get("category") or "").lower()
            if not hard and ("marka" in text2 or "brand" in text2 or cat in ("phishing","brand_impersonation")):
                for brand in ("instagram","facebook","linkedin","youtube","twitter","airbnb","paypal","google","microsoft","apple","amazon","github"):
                    if brand in text2 and brand in passive and brand not in strong:
                        f["severity"]="low"; f["confidence"]=min(float(f.get("confidence") or .5),.25)
                        f["description"]=brand+" yalnız pasif link/footer/asset/script bağlamında görüldü; iddia edilen kimlik sayılmadı."
                        f["evidence_semantics_v321"]="passive_brand_mention"; brand_n+=1
                        break

            raw=self._v321_text(f.get("evidence") or f.get("description") or f.get("title") or "")
            eid=hashlib.sha256(re.sub(r"\s+"," ",raw).strip().encode()).hexdigest()[:24]
            f["event_id_v321"]=eid
            if eid in seen and not hard:
                f["duplicate_event_v321"]=True
                f["confidence"]=min(float(f.get("confidence") or .5),.35)
            else: seen.add(eid)
            out.append(f)
        self.results["findings"]=out
        r={"findings":len(out),"unique_events":len(seen),"generic_telemetry_demoted":generic_n,
           "passive_brand_mentions_demoted":brand_n,
           "rule":"mention != identity; telemetry != exfiltration; duplicate event != independent expert"}
        self.results["evidence_semantics_v321"]=r
        return r

    def enforce_verdict_consistency_v321(self):
        """V32.2 final verdict consistency over canonical score-eligible evidence only."""
        integrity=self.results.get("pipeline_integrity_v3221") or {}
        if integrity.get("no_observation") or (
            float(integrity.get("observed_percent") or 0)<=0 and integrity.get("observed_sensor_groups",0)>0
        ):
            return {"pipeline_guard":True,"risk_level":self.results.get("risk_level")}
        fusion=self.results.get("fusion") or {}
        canonical=self.results.get("canonical_scoring_v3222") or {}
        findings=self.results.get("findings") or []
        hard=False
        for f in findings:
            if str(f.get("severity") or "").lower()=="critical":
                try:
                    if self._v321_is_hard_evidence(f): hard=True; break
                except Exception: pass
        try: score=int(canonical.get("threat_score") if canonical.get("threat_score") is not None else (fusion.get("score") if fusion.get("score") is not None else self.results.get("threat_score") or 0))
        except Exception: score=0

        # Synchronize displayed threat score with final fusion when available.
        if fusion.get("score") is not None:
            self.results["threat_score"]=score

        current=str(self.results.get("risk_level") or "")
        if not hard:
            if score < 20:
                self.results["risk_level"]="ℹ️ BELİRGİN TEHDİT KANITI YOK"
            elif score < 45:
                self.results["risk_level"]="⚠️ DİKKAT GEREKTİREN SİNYALLER"
            elif "TEHLİKELİ" in current or "TEHLIKELI" in current:
                # Without hard critical evidence, strong behavioral corroboration is suspicious/high risk, not critical.
                self.results["risk_level"]="⚠️ ŞÜPHELİ / YÜKSEK RİSK"
        r={"hard_critical":hard,"canonical_threat_score":score,"risk_level":self.results.get("risk_level"),
           "eligible_findings":len(findings)}
        self.results["verdict_consistency_v321"]=r
        return r

    def pipeline_integrity_v3221(self):
        """
        Coverage/observation fail-safe.
        Zero observed surface can never render as a completed clean scan.
        Does not invent missing sensor data.
        """
        cov=self.results.get("coverage_v19") or self.results.get("coverage") or {}
        scan=self.results.get("scan") or {}
        # tolerate historical coverage field names
        observed=cov.get("observed_percent")
        if observed is None: observed=cov.get("percent")
        if observed is None: observed=cov.get("coverage_percent")
        try: observed=float(observed or 0)
        except Exception: observed=0.0

        sensor_presence={
          "http":bool(self.results.get("http")),
          "browser":bool(self.results.get("browser")),
          "dns_tls":bool(self.results.get("dns") or self.results.get("tls") or self.results.get("ssl")),
          "identity":bool(self.results.get("identity_semantic_v18")),
          "trust":bool(self.results.get("trust_context_v21")),
          "url_intelligence":bool(self.results.get("url_intelligence"))
        }
        observed_sensors=sum(1 for v in sensor_presence.values() if v)
        no_observation=(observed<=0 and observed_sensors==0)

        if no_observation:
            self.results["risk_level"]="❓ ANALİZ TAMAMLANAMADI / YETERLİ YÜZEY GÖZLENEMEDİ"
            self.results["analysis_message"]="Yeterli analiz yüzeyi gözlemlenemedi. Bu sonuç sitenin güvenli olduğu anlamına gelmez."
            scan["status"]="incomplete"
            self.results["scan"]=scan
        elif observed<=0 and observed_sensors>0:
            # Coverage bookkeeping itself is inconsistent. Do not claim clean completion.
            self.results["risk_level"]="❓ ANALİZ KAPSAMI HESAPLANAMADI / GÖZLEM MEVCUT"
            self.results["analysis_message"]="Sensör verisi mevcut ancak kapsam metriği üretilemedi; güvenli sonucu verilmedi."
            scan["status"]="partial"
            self.results["scan"]=scan

        report={"observed_percent":observed,"sensor_presence":sensor_presence,
                "observed_sensor_groups":observed_sensors,"no_observation":no_observation}
        self.results["pipeline_integrity_v3221"]=report
        return report

    def causal_evidence_gate_v3224(self):
        """Severity is not evidence authority; causality and provenance are."""
        kept=[]; rejected=[]
        for f0 in self.results.get("findings") or []:
            f=dict(f0); text=self._v322_blob(f)
            cat=str(f.get("category") or "").lower()
            generic=("storage/cookie + network + obfuscation" in text or
                     "input events + network + obfuscation" in text or
                     "token/cookie veri sızdırma korelasyonu" in text or
                     "girdi yakalama ve aktarım korelasyonu" in text)
            brand_sensitive=("marka taklidi + hassas işlem" in text or
                             ("domain uyuşmaz" in text and ("login" in text or "hassas" in text)))
            reason=None
            if generic and not self._v3224_explicit_causal_sink(f):
                reason="no_explicit_source_to_sink_chain"
            elif brand_sensitive and not self._v3224_verified_brand_sensitive_chain(f):
                reason="brand_not_claimed_on_first_party_identity_surface"
            elif cat in ("credential_theft","privacy","data_exfiltration","network_exfil") and \
                 str(f.get("severity") or "").lower()=="critical":
                protected=any(x in text for x in ("urlhaus","threatfox","sha-256","sha256",
                                                   "known malicious","malware family","c2",
                                                   "command and control","exact ioc"))
                if not protected and not self._v3224_explicit_causal_sink(f):
                    reason="critical_without_causal_sink"
            if reason:
                f["score_eligible_v322"]=False
                f["causal_reject_v3224"]=reason
                if str(f.get("severity") or "").lower() in ("critical","high"):
                    f["original_severity_v3224"]=f.get("severity"); f["severity"]="info"
                rejected.append(f)
            else:
                kept.append(f)
        self.results["findings"]=kept
        self.results.setdefault("contextual_findings_v322",[]).extend(rejected)
        report={"kept":len(kept),"rejected":len(rejected),"reasons":{}}
        for f in rejected:
            r=f.get("causal_reject_v3224") or "other"
            report["reasons"][r]=report["reasons"].get(r,0)+1
        self.results["causal_evidence_gate_v3224"]=report
        return report

    def identity_claim_guard_v322(self):
        """
        Identity must come from strong first-party surfaces, not footer/social links/assets/scripts.
        This runs before final fusion and removes passive-brand mismatch findings from score input.
        """
        browser=self.results.get("browser") or {}
        http=self.results.get("http") or {}
        strong=self._v322_blob({
            "title":browser.get("title") or http.get("title"),
            "h1":browser.get("h1"),
            "og_title":browser.get("og_title"),
            "description":browser.get("description"),
            "forms":self.results.get("forms") or []
        })
        passive=self._v322_blob({
            "links":self.results.get("links") or [],
            "scripts":self.results.get("scripts") or [],
            "technology":self.results.get("technology") or {},
            "assets":browser.get("assets") or browser.get("resources") or []
        })
        brands=("instagram","facebook","linkedin","youtube","twitter","airbnb","paypal",
                "google","microsoft","apple","amazon","github","netflix","discord","telegram",
                "binance","coinbase","shopee","trendyol","hepsiburada")
        passive_only={b for b in brands if b in passive and b not in strong}

        kept=[]; contextual=list(self.results.get("contextual_findings_v322") or [])
        removed=[]
        for f0 in self.results.get("findings") or []:
            f=dict(f0); text=self._v322_blob(f)
            brand_hit=next((b for b in passive_only if b in text),None)
            mismatch=("marka" in text or "brand" in text or "domain uyuşmaz" in text or
                      str(f.get("category") or "").lower() in ("phishing","brand_impersonation"))
            hard=False
            if hasattr(self,"_v321_is_hard_evidence"):
                try: hard=self._v321_is_hard_evidence(f)
                except Exception: hard=False
            if brand_hit and mismatch and not hard:
                f["severity"]="info"; f["confidence"]=min(float(f.get("confidence") or .5),.20)
                f["score_eligible_v322"]=False
                f["identity_claim_v322"]="passive_mention_only"
                contextual.append(f); removed.append({"brand":brand_hit,"title":f.get("title")})
                continue
            kept.append(f)
        self.results["findings"]=kept
        self.results["contextual_findings_v322"]=contextual
        report={"passive_only_brands":sorted(passive_only),"removed_from_scoring":removed}
        self.results["identity_claim_guard_v322"]=report
        return report

    def _v323_identity_relation(self, brand, root):
        """Identity relation, not a safety decision."""
        b=(brand or "").lower().strip(); r=(root or "").lower().strip()
        if not b or not r: return False
        if legitimate_brand_root(b,r): return True
        # Explicit organization-domain relations may grow independently of verdict logic.
        org={
          "amazon":{"amazon.com","amazon.com.tr","amazon.co.uk","amazon.de","amazon.fr","amazon.it",
                    "amazon.es","amazon.co.jp","amazon.ca","amazon.com.au","amazon.in","amazon.com.br","amazon.com.mx"},
          "facebook":{"facebook.com","fb.com","meta.com","instagram.com","whatsapp.com"},
          "instagram":{"instagram.com","facebook.com","meta.com"},
          "meta":{"meta.com","facebook.com","instagram.com","whatsapp.com"},
          "whatsapp":{"whatsapp.com","facebook.com","meta.com"},
          "paypal":{"paypal.com"},
          "google":{"google.com","google.com.tr","gmail.com"},
          "microsoft":{"microsoft.com","live.com","office.com","outlook.com"},
          "apple":{"apple.com","icloud.com"},
          "github":{"github.com"}
        }
        return r in org.get(b,set())

    def evidence_trace_v3231(self):
        """Trace score-eligible evidence into the canonical/UI path."""
        rows=[]
        for i,f in enumerate(self.results.get("findings") or []):
            rows.append({
              "index":i,
              "id":f.get("canonical_event_id") or f.get("event_id") or f.get("id"),
              "title":f.get("title"),
              "category":f.get("category"),
              "severity":f.get("severity"),
              "producer":f.get("producer"),
              "source_expert":f.get("source_expert"),
              "score_eligible":f.get("score_eligible_v322",True),
              "causal_reject":f.get("causal_reject_v3224"),
              "semantic_reject":f.get("generic_semantic_reject_v3225"),
              "context_reject":f.get("v323_context_reject")
            })
        self.results["evidence_trace_v3231"]={
          "findings":rows,
          "threat_score":(self.results.get("scores") or {}).get("threat"),
          "fusion_score":((self.results.get("defender") or {}).get("fusion") or {}).get("score"),
          "assessment_level":((self.results.get("defender") or {}).get("assessment") or {}).get("level"),
          "invariant":"UI evidence must be a subset of canonical score-eligible findings"
        }
        return self.results["evidence_trace_v3231"]

    def post_guard_phishing_fusion_v32310(self):
        """Rebuild the phishing hypothesis only after ownership/causality guards.

        The early V32.3 phishing pass is observational/provisional. This pass removes
        its derived verdict findings and recomputes from the guarded destination graph,
        preventing rejected cross-origin telemetry from surviving as an expert vote.
        """
        kept=[]; removed=[]
        for f0 in self.results.get("findings") or []:
            f=dict(f0)
            prod=str(f.get("producer") or "")
            src=str(f.get("source_expert") or "")
            derived_summary=(prod=="independent_phishing_v323" or src=="independent_phishing" or
                             str(f.get("title") or "").startswith("Bağımsız phishing motoru:"))
            if derived_summary:
                removed.append(f.get("title")); continue
            kept.append(f)
        self.results["findings"]=kept
        report=self.independent_phishing_engine_v323()
        report["phase"]="post_guard_canonical"
        report["removed_provisional_findings"]=[x for x in removed if x]
        self.results["post_guard_phishing_fusion_v32310"]={
            "score":report.get("score"),"verdict":report.get("verdict"),
            "decisive_experts":report.get("decisive_experts") or [],
            "expert_status":report.get("expert_status") or {},
            "removed_provisional_findings":[x for x in removed if x],
            "principle":"Only post-guard canonical expert evidence may vote in phishing fusion."
        }
        return self.results["post_guard_phishing_fusion_v32310"]

    def access_restricted_evidence_guard_v3232(self):
        """Restricted target content cannot create content-derived phishing proof."""
        h=self.results.get("http") or {}
        restricted=bool(h.get("access_restricted") or h.get("status_code") in (401,403,429))
        if not restricted:
            out={"restricted":False}; self.results["access_restricted_guard_v3232"]=out; return out
        ip=self.results.get("independent_phishing_v323") or {}
        if len(ip.get("decisive_experts") or [])>=2:
            out={"restricted":True,"demoted":0,"core_corroborated":True}
            self.results["access_restricted_guard_v3232"]=out; return out
        kept=[]; ctx=list(self.results.get("contextual_findings_v322") or []); n=0
        for f0 in self.results.get("findings") or []:
            f=dict(f0); text=self._v322_blob(f)
            hard=False
            try: hard=self._v321_is_hard_evidence(f)
            except Exception: pass
            inferred=any(x in text for x in ("marka taklidi","domain impersonation","marka referansı",
                "sahte host","phishing sitesi özellikleri","typosquat","brand impersonation"))
            if inferred and not hard:
                f["score_eligible_v322"]=False
                f["v3232_reject"]="access_restricted_without_observed_content"
                f["original_severity_v3232"]=f.get("severity"); f["severity"]="info"
                ctx.append(f); n+=1
            else: kept.append(f)
        self.results["findings"]=kept
        self.results["contextual_findings_v322"]=ctx
        out={"restricted":True,"demoted":n,"core_corroborated":False}
        self.results["access_restricted_guard_v3232"]=out
        return out

    def legacy_brand_noise_guard_v3234(self):
        """Remove generic/ambiguous brand tokens from legacy URL/identity producers.

        This is producer-class cleanup, not a per-site allowlist.
        """
        ambiguous={"live"}
        kept=[]; demoted=[]
        for f0 in self.results.get("findings") or []:
            f=dict(f0)
            blob=self._v322_blob(f).lower()
            producer=str((f.get("metadata") or {}).get("producer") or f.get("producer") or "").lower()
            brandish=any(x in blob for x in ("marka","brand","impersonation","typosquat"))
            only_ambiguous=brandish and any(re.search(r"(?<![a-z0-9])"+re.escape(t)+r"(?![a-z0-9])", blob) for t in ambiguous)
            hard=False
            try: hard=self._v321_is_hard_evidence(f)
            except Exception: pass
            if only_ambiguous and not hard:
                f["score_eligible_v322"]=False
                f["severity"]="info"
                f["v3234_reject"]="ambiguous_generic_brand_token"
                demoted.append(f)
            else:
                kept.append(f)
        self.results["findings"]=kept
        if demoted:
            self.results.setdefault("contextual_findings_v322",[]).extend(demoted)
        out={"demoted":len(demoted),"tokens":sorted(ambiguous)}
        self.results["legacy_brand_noise_guard_v3234"]=out
        return out

    def feed_off_regression_guard_v3231(self):
        """V32.3.20 decision isolation. External intelligence stays visible but cannot vote.
        In Feed OFF mode OpenPhish/PhishTank/URLhaus/ThreatFox and cached records derived
        from them are display-only. They contribute zero to category score, fusion and verdict.
        """
        enabled=bool(self.results.get("_feed_off_v3231"))
        feed_terms=("openphish","phishtank","urlhaus","threatfox","feed eşleş","feed match","threat intelligence")
        feed_sources={"openphish","phishtank","urlhaus","threatfox"}
        held=[]
        for f in self.results.get("findings") or []:
            text=self._v322_blob(f)
            producer=str(f.get("producer") or "").lower()
            expert=str(f.get("source_expert") or "").lower()
            source=str(f.get("source") or "").lower()
            # Local IOC cache is external intelligence when its provenance is one of the feeds.
            ev=str(f.get("evidence") or "").lower()
            is_feed=(any(x in text for x in feed_terms) or "threat_intel" in producer or
                     "threat_intel" in expert or source in feed_sources or any(x in ev for x in feed_sources))
            if is_feed:
                f["external_intelligence_v32320"]=True
                f["external_intelligence_source_v32320"]=next((x for x in feed_sources if x in text or x in ev or x==source), "external_feed")
                if enabled:
                    f["score_eligible_v322"]=False
                    f["feed_off_held_v3231"]=True
                    f["contribution_policy"]="display_only_external_intelligence"
                    held.append(f)
        self.results["feed_off_v3231"]={
            "enabled":enabled,"held_findings":len(held),
            "mode":"ENGINE_ONLY" if enabled else "COMBINED",
            "warning":"External feed evidence remains visible. In ENGINE_ONLY mode it contributes zero points and zero votes."
        }
        return self.results["feed_off_v3231"]

    def identity_and_context_guard_v323(self):
        """Remove false phishing evidence caused by official identity or context-only urgency.
        This never suppresses malware/IOC/exfil evidence."""
        final=(self.results.get("browser") or {}).get("final_url") or self.results.get("final_url") or self.results.get("url") or ""
        root=get_root_domain(urlparse(final).hostname or "")
        kept=[]; context=list(self.results.get("contextual_findings_v322") or [])
        for f0 in self.results.get("findings") or []:
            f=dict(f0); text=self._v322_blob(f)
            hard=False
            try: hard=self._v321_is_hard_evidence(f)
            except Exception: pass
            reject=None
            # Do not touch independent IOC/malware/exfil hard evidence.
            if not hard:
                # If a brand named by this finding belongs to the current root, it is not impersonation.
                if any(x in text for x in ("marka","brand","phishing","sahte marka","domain uyuşmaz")):
                    for brand in BRAND_KEYWORDS:
                        if brand in text and self._v323_identity_relation(brand,root):
                            reject="official_identity_relation_not_impersonation"; break
                # Urgency language by itself is social-engineering context, not phishing proof.
                if not reject and "sosyal mühendislik içeriği" in text:
                    ip=self.results.get("independent_phishing_v323") or {}
                    decisive=set(ip.get("decisive_experts") or [])
                    if len(decisive)<2:
                        reject="urgency_language_without_independent_phishing_corroboration"
                # Legacy URL summary cannot be critical merely because weak URL heuristics accumulated.
                if not reject and "yüksek risk: phishing sitesi özellikleri" in text:
                    ip=self.results.get("independent_phishing_v323") or {}
                    if int(ip.get("score") or 0)<55:
                        reject="legacy_url_heuristic_summary_without_independent_corroboration"
            if reject:
                f["score_eligible_v322"]=False; f["v323_context_reject"]=reject
                f["original_severity_v323"]=f.get("severity"); f["severity"]="info"
                context.append(f)
            else: kept.append(f)
        self.results["findings"]=kept
        self.results["contextual_findings_v322"]=context
        out={"eligible":len(kept),"contextual":len(context),"root":root}
        self.results["identity_context_guard_v323"]=out
        return out

    def rebuild_scoring_evidence_v322(self):
        """Canonical evidence list after source guards; dedupe by event/provenance before final fusion."""
        eligible=[]
        seen=set()
        for f0 in self.results.get("findings") or []:
            f=dict(f0)
            if f.get("score_eligible_v322") is False:
                continue
            raw=self._v322_blob({
                "category":f.get("category"),
                "evidence":f.get("evidence"),
                "description":f.get("description"),
                "source":f.get("source_expert") or f.get("source")
            })
            eid=f.get("event_id_v321") or hashlib.sha256(re.sub(r"\s+"," ",raw).strip().encode()).hexdigest()[:24]
            f["canonical_event_id_v322"]=eid
            hard=False
            if hasattr(self,"_v321_is_hard_evidence"):
                try: hard=self._v321_is_hard_evidence(f)
                except Exception: hard=False
            if eid in seen and not hard:
                continue
            seen.add(eid); eligible.append(f)
        self.results["findings"]=eligible
        self.results["canonical_evidence_v322"]={
            "eligible_count":len(eligible),"unique_events":len(seen),
            "context_only_count":len(self.results.get("contextual_findings_v322") or [])
        }
        return self.results["canonical_evidence_v322"]

    def classify_target_access_protection_v32313(self):
        """Generic observation classification. Never treats protection as safety.

        This is deliberately provider/site agnostic. It reports what Web Defender
        observed (HTTP restriction/challenge + browser failure), not a claim that
        a specific WAF vendor is present.
        """
        http = self.results.get("http") or {}
        browser = self.results.get("browser") or {}
        status = http.get("status_code")
        try: status = int(status) if status is not None else None
        except Exception: status = None
        bdec = str(browser.get("decision") or browser.get("failure_kind") or "").lower()
        hdec = str(http.get("decision") or http.get("failure_kind") or "").lower()
        server = str(http.get("server") or "").lower()
        # Generic challenge/access hints only. A hint is not proof of a WAF vendor.
        restriction_status = status in {400,401,403,406,409,418,423,425,429,451}
        browser_blocked = any(x in bdec for x in ("timeout","access_restricted","challenge","blocked","deadline"))
        explicit = bool(http.get("access_restricted") or browser.get("access_restricted"))
        acquisition=self.results.get("content_acquisition_v32316") or {}
        protection_hint = explicit or (restriction_status and browser_blocked) or acquisition.get("state")=="access_protection_or_challenge"
        reason = []
        if status is not None and status >= 400: reason.append(f"http_{status}")
        if bdec: reason.append(bdec)
        if explicit: reason.append("explicit_access_restriction")
        out = {
            "suspected": bool(protection_hint),
            "classification": "target_access_protection_or_restriction" if protection_hint else "not_established",
            "display_name": "Hedef erişim koruması / erişim kısıtı" if protection_hint else "",
            "reason_codes": list(dict.fromkeys(reason)),
            "vendor_asserted": False,
            "server_hint": server[:120],
            "safety_rule": "Observation failure never suppresses independent URL/domain/IOC/DNS/TLS threat evidence."
        }
        self.results["target_access_v32313"] = out
        return out

