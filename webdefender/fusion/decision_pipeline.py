"""Canonical evidence, temporal context and final-decision orchestration.

This mixin owns canonicalization/decision orchestration while pure fusion policy
remains in fusion.policy. Historical observations are context, not automatic
current-threat ground truth.
"""
from ..metadata import APP_VERSION
import re
import uuid
import json, hashlib, math, time, sqlite3
from datetime import datetime, timezone

from ..database import db_connect
from ..evidence.policy import stable_evidence_id, is_derived_evidence, independent_group
from ..fusion.policy import compute_final_decision
from ..guards.policy import is_hard_evidence_text

class DecisionEvidenceMixin:
    def build_explainable_assessment(self):
        """Bulguları kullanıcı-dostu tehdit ailelerine ayırır.
        Bu değerler olasılık değildir; gözlenen kanıt gücüdür.
        """
        mapping = {
            "Phishing / Marka Taklidi": {"phishing"},
            "Kimlik Bilgisi Hırsızlığı": {"credential_theft", "forms"},
            "Malware / Zararlı İndirme": {"malware"},
            "Şüpheli JavaScript / Davranış": {"javascript", "behavior"},
            "Yönlendirme Kötüye Kullanımı": {"redirect"},
            "Sosyal Mühendislik": {"social_engineering"},
            "Gizlilik / Veri Sızdırma Riski": {"privacy"},
        }
        sev={"critical":34,"high":22,"medium":11,"low":4,"info":1}
        cats=[]
        findings=self.results.get("findings",[])
        for label, accepted in mapping.items():
            fs=[f for f in findings if f.get("category") in accepted]
            score=min(100, round(sum(sev.get(f.get("severity"),0)*float(f.get("confidence",1)) for f in fs)))
            fs=sorted(fs, key=lambda f: ({"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(f.get("severity"),9), -float(f.get("confidence",0))))
            level="Belirgin sinyal yok" if score<8 else "Düşük sinyal" if score<25 else "Dikkat" if score<50 else "Yüksek risk" if score<75 else "Kritik"
            cats.append({"name":label,"score":score,"level":level,"evidence":fs[:5]})
        # V16: UI kartları ham bulgu toplamını değil Fusion Engine sonucunu gösterir.
        fusion_rows={x.get("name"):x for x in self.results.get("defender",{}).get("fusion",{}).get("categories",[])}
        for c in cats:
            fr=fusion_rows.get(c["name"])
            if fr:
                c["score"]=fr.get("score",c["score"])
                c["evidence"]=fr.get("evidence",c["evidence"])
                c["independent_experts"]=fr.get("independent_experts",0)
                c["experts"]=fr.get("experts",[])
                sc=c["score"]
                c["level"]="Belirgin sinyal yok" if sc<8 else "Düşük sinyal" if sc<25 else "Dikkat" if sc<50 else "Yüksek risk" if sc<75 else "Kritik"
        cats.sort(key=lambda x:x["score"], reverse=True)
        primary=cats[0] if cats else {"name":"Belirgin tehdit türü yok","score":0,"level":"Belirgin sinyal yok","evidence":[]}
        threat=self.results.get("scores",{}).get("threat")
        if threat is None:
            summary="Sayfanın gerçek içeriği yeterince gözlemlenemedi. Güvenli veya zararlı hükmü verilemiyor."
            action="İçerik doğrulanmadan parola, kart bilgisi veya dosya çalıştırma işlemi yapmayın."
        elif primary["score"] >= 50:
            summary=f"En güçlü şüphe: {primary['name']}. Karar, aşağıdaki gözlenmiş kanıtlara dayanıyor."
            action="İşlem yapmadan önce kanıtları inceleyin; hassas bilgi girmeyin ve şüpheli dosya çalıştırmayın."
        elif primary["score"] >= 8:
            summary=f"Bazı sinyaller görüldü. En belirgin alan: {primary['name']}. Bu sinyaller tek başına saldırıyı kesinleştirmez."
            action="Alan adını ve sayfanın istediği işlemi doğrulayın; beklenmeyen giriş/ödeme/indirme taleplerine dikkat edin."
        else:
            summary="Analiz edilen yüzeylerde belirgin zararlı davranış kanıtı bulunmadı. Bu, sitenin mutlak olarak güvenli olduğu anlamına gelmez."
            action="Normal güvenlik kontrollerine devam edin ve beklenmeyen hassas bilgi taleplerini doğrulayın."
        temporal=self.results.get("temporal_history") or self.results.get("temporal_threat_memory_v3241") or {}
        if temporal.get("score_eligible") and temporal.get("prior_hard_evidence"):
            summary += " Aynı URL için yakın geçmişte doğrulanmış dahili zararlı davranış kanıtı var; bu geçmiş bağlam mevcut sayfanın şu anda zararlı olduğunu tek başına kanıtlamaz."
            action="Geçmiş doğrulanmış davranış nedeniyle hassas işlem yapmadan önce URL ve hedefi ayrıca doğrulayın."
        top=[]
        for c in cats:
            for f in c["evidence"][:3]:
                top.append({"type":c["name"],"title":f.get("title",""),"severity":f.get("severity","info"),"description":f.get("description",""),"evidence":self.evidence_text_v32362(f.get("evidence","")),"confidence":f.get("confidence",0)})
        self.results["defender"]["assessment"]={"primary":primary,"categories":cats,"evidence":top[:12],"plain_summary":summary,"action":action}
        # V32.3.6.2: legacy raw findings use the same evidence formatter as assessment cards.
        for _f in self.results.get("findings",[]) or []:
            if isinstance(_f.get("evidence"), (dict,list,tuple,set)):
                _f["evidence"]=self.evidence_text_v32362(_f.get("evidence"))

    def register_evidence_v26(self):
        """Normalize/deduplicate findings and persist provenance. Existing detector output remains intact."""
        now=datetime.now(timezone.utc).isoformat()
        normalized=[]; by_fp={}
        for f in self.results.get("findings",[]) or []:
            sensor=str(f.get("sensor") or self._evidence_sensor_v26(f))
            source=str(f.get("source") or sensor)
            category=str(f.get("category") or "other")
            title=str(f.get("title") or "Kanıt")
            desc=str(f.get("description") or "")
            raw_ev=str(f.get("evidence") or "")
            # Stable fingerprint excludes wording-only confidence/severity changes.
            canonical=json.dumps({
              "sensor":sensor,"category":category.lower(),"title":title.lower().strip(),
              "evidence":raw_ev[:4000].strip()
            },ensure_ascii=False,sort_keys=True)
            fp=hashlib.sha256(canonical.encode("utf-8","replace")).hexdigest()
            eid="ev_"+fp[:20]
            group=self._evidence_group_v26(sensor)
            conf=float(f.get("confidence") or .5)
            item=dict(f)
            item.update({"evidence_id":eid,"sensor":sensor,"source":source,
                         "first_seen":now,"confidence":conf,
                         "independent_group":group,
                         "independent_from":[]})
            # Same evidence fingerprint counts once in this scan.
            if fp in by_fp:
                prev=by_fp[fp]
                prev["confidence"]=max(float(prev.get("confidence") or 0),conf)
                continue
            by_fp[fp]=item; normalized.append(item)
            try:
                with db_connect(DB_PATH, timeout=10) as con:
                    row=con.execute("SELECT first_seen,seen_count FROM evidence_registry WHERE fingerprint=?",(fp,)).fetchone()
                    first=row[0] if row else now
                    count=(row[1]+1) if row else 1
                    con.execute("""INSERT INTO evidence_registry
                      (evidence_id,fingerprint,sensor,source,category,title,confidence,first_seen,last_seen,seen_count,independent_group,payload)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                      ON CONFLICT(fingerprint) DO UPDATE SET
                        confidence=MAX(confidence,excluded.confidence),last_seen=excluded.last_seen,
                        seen_count=excluded.seen_count,payload=excluded.payload""",
                      (eid,fp,sensor,source,category,title,conf,first,now,count,group,
                       json.dumps({"description":desc,"evidence":raw_ev[:5000]},ensure_ascii=False)))
                    item["first_seen"]=first
            except Exception:
                pass

        # Explicit independence is derived only across distinct modality groups.
        for x in normalized:
            x["independent_from"]=[y["evidence_id"] for y in normalized
                if y["evidence_id"]!=x["evidence_id"] and y["independent_group"]!=x["independent_group"]][:30]
        self.results["findings"]=normalized
        groups=sorted(set(x["independent_group"] for x in normalized))
        self.results["evidence_provenance_v26"]={
          "unique_evidence_count":len(normalized),
          "independent_groups":groups,
          "independent_group_count":len(groups),
          "evidence":[{k:x.get(k) for k in ("evidence_id","sensor","source","category","title","confidence","first_seen","independent_group","independent_from")}
                      for x in normalized]
        }

    def build_explainable_decision_graph_v28(self):
        """Build an evidence DAG from V26 provenance and detector correlations."""
        prov=self.results.get("evidence_provenance_v26",{}) or {}
        findings=self.results.get("findings",[]) or []
        nodes=[]; edges=[]; seen=set()
        def node(nid,label,kind,score=None,meta=None):
            if not nid or nid in seen: return
            seen.add(nid); nodes.append({"id":nid,"label":label,"kind":kind,"score":score,"meta":meta or {}})
        for f in findings:
            eid=f.get("evidence_id")
            if not eid: continue
            node(eid,f.get("title") or "Kanıt","evidence",round(float(f.get("confidence") or 0)*100),
                 {"sensor":f.get("sensor"),"category":f.get("category"),"severity":f.get("severity"),
                  "independent_group":f.get("independent_group")})
        # Add semantic intermediate facts that make the path understandable.
        nb=self.results.get("network_behavior_v22",{}) or {}
        if nb.get("sensitive_ui"): node("fact_sensitive_ui","Hassas giriş alanı","fact",None,{"source":"browser"})
        if nb.get("cross_site_write_count",0)>0:
            node("fact_cross_write","Harici domaine veri yazımı","fact",None,{"count":nb.get("cross_site_write_count")})
        vs=self.results.get("visual_similarity_v27",{}) or {}; best=vs.get("best")
        if best:
            node("fact_visual_similarity",f"{best.get('brand')} görsel benzerliği %{best.get('score')}","fact",best.get("score"),best)
        rd=((self.results.get("trust_context_v21",{}) or {}).get("sensors",{}) or {}).get("rdap",{}) or {}
        if isinstance(rd.get("age_days"),int) and rd["age_days"]<30:
            node("fact_young_domain",f"Yeni domain: {rd['age_days']} gün","fact",None,{"age_days":rd["age_days"]})
        mism=(self.results.get("identity_semantic_v18",{}) or {}).get("brand_mismatches") or []
        if mism: node("fact_brand_mismatch","Marka-domain uyuşmazlığı","fact",None,{"count":len(mism)})
        # Correlation edges.
        if "fact_sensitive_ui" in seen and "fact_cross_write" in seen:
            edges.append({"from":"fact_sensitive_ui","to":"fact_cross_write","relation":"correlates_with"})
        if "fact_visual_similarity" in seen and "fact_brand_mismatch" in seen:
            edges.append({"from":"fact_visual_similarity","to":"fact_brand_mismatch","relation":"corroborates"})
        # Link facts to evidence by category/sensor.
        for f in findings:
            eid=f.get("evidence_id")
            if not eid: continue
            cat=str(f.get("category","")).lower(); sensor=str(f.get("sensor",""))
            if cat in ("data_exfiltration","network_exfil") and "fact_cross_write" in seen:
                edges.append({"from":"fact_cross_write","to":eid,"relation":"supports"})
            if cat in ("visual_impersonation","phishing") and "fact_visual_similarity" in seen and sensor=="visual_similarity_v27":
                edges.append({"from":"fact_visual_similarity","to":eid,"relation":"supports"})
            if cat in ("phishing","credential","credential_theft") and "fact_brand_mismatch" in seen:
                edges.append({"from":"fact_brand_mismatch","to":eid,"relation":"supports"})
            if cat=="domain_age" and "fact_young_domain" in seen:
                edges.append({"from":"fact_young_domain","to":eid,"relation":"supports"})
        verdict_id="verdict_final"
        risk=self.results.get("risk_level") or "Belirsiz"
        score=self.results.get("risk_score")
        node(verdict_id,str(risk),"verdict",score,{"threat_score":((self.results.get("defender",{}) or {}).get("fusion",{}) or {}).get("score")})
        # Only unique independent groups get direct verdict edges, avoiding duplicate vote inflation.
        best_by_group={}
        for f in findings:
            g=f.get("independent_group"); eid=f.get("evidence_id")
            if not g or not eid: continue
            if g not in best_by_group or float(f.get("confidence") or 0)>float(best_by_group[g].get("confidence") or 0):
                best_by_group[g]=f
        for g,f in best_by_group.items():
            edges.append({"from":f["evidence_id"],"to":verdict_id,"relation":"independent_support","group":g})
        # Human-readable top paths.
        paths=[]
        for g,f in sorted(best_by_group.items(),key=lambda kv:float(kv[1].get("confidence") or 0),reverse=True)[:6]:
            paths.append({"group":g,"evidence_id":f.get("evidence_id"),"text":f"{f.get('title')} → {risk}"})
        self.results["decision_graph_v28"]={"nodes":nodes[:120],"edges":edges[:220],"top_paths":paths,
            "independent_support_count":len(best_by_group),
            "explanation":"Karar, aynı modalitedeki tekrarlar değil benzersiz bağımsız kanıt grupları üzerinden açıklanır."}

    def canonical_scoring_authority_v3222(self):
        """
        One final source of truth for category scores and verdict inputs.
        Raw sensor/fusion objects remain diagnostic only.
        """
        findings=[]
        seen=set()
        claimed_brand_mismatch=self._v3222_is_claimed_brand()

        for f0 in self.results.get("findings") or []:
            f=dict(f0)
            if f.get("score_eligible_v322") is False: continue
            text=self._v322_blob(f)
            hard=False
            try: hard=self._v321_is_hard_evidence(f)
            except Exception: pass

            # Brand+sensitive correlation is invalid unless the page itself claims the brand.
            if not claimed_brand_mismatch and (
                "marka taklidi + hassas işlem" in text or
                ("marka-domain uyuşmaz" in text and ("login" in text or "hassas" in text))
            ):
                f["score_eligible_v322"]=False
                f["canonical_reject_v3222"]="no_claimed_brand"
                self.results.setdefault("contextual_findings_v322",[]).append(f)
                continue

            # Generic telemetry cannot re-enter through a later producer.
            if (
                "storage/cookie + network + obfuscation" in text or
                "input events + network + obfuscation" in text or
                "token/cookie veri sızdırma korelasyonu" in text or
                "girdi yakalama ve aktarım korelasyonu" in text
            ):
                f["score_eligible_v322"]=False
                f["canonical_reject_v3222"]="generic_telemetry_without_causal_sink"
                self.results.setdefault("contextual_findings_v322",[]).append(f)
                continue

            eid=f.get("canonical_event_id_v322") or f.get("event_id_v321")
            if not eid:
                raw=self._v322_blob({"category":f.get("category"),"evidence":f.get("evidence"),
                    "description":f.get("description"),"source":f.get("source_expert") or f.get("source")})
                eid=hashlib.sha256(re.sub(r"\s+"," ",raw).strip().encode()).hexdigest()[:24]
            if eid in seen and not hard: continue
            seen.add(eid); f["canonical_event_id_v3222"]=eid; findings.append(f)

        self.results["findings"]=findings

        # Canonical category scores, independent of stale V17/V32 category caches.
        aliases={
          "phishing":["phishing","brand_impersonation","visual_impersonation"],
          "credential_theft":["credential","credential_theft"],
          "malware":["malware","download"],
          "javascript":["javascript","suspicious_script"],
          "redirect":["redirect","redirect_abuse"],
          "privacy":["privacy","data_exfiltration","network_exfil"],
          "social_engineering":["social_engineering"]
        }
        cat_scores={k:0 for k in aliases}
        sev_weight={"critical":55,"high":34,"medium":18,"low":8,"info":0}
        for f in findings:
            cat=str(f.get("category") or "").lower()
            text=self._v322_blob(f)
            sev=str(f.get("severity") or "").lower()
            base=0 if f.get("derived_evidence") else sev_weight.get(sev,0)
            conf=max(0.0,min(1.0,float(f.get("confidence") or 1.0)))
            pts=round(base*conf)
            for out,names in aliases.items():
                if cat in names or any(n.replace("_"," ") in text for n in names):
                    cat_scores[out]=min(100,cat_scores[out]+pts)

        # Independent-expert corroboration bonus only from canonical evidence.
        groups=set()
        lineage_groups=set()
        for f in findings:
            if f.get("derived_evidence"):
                continue
            g=f.get("independent_group") or f.get("source_expert") or f.get("source")
            lineage=f.get("evidence_lineage_id") or f.get("canonical_event_id_v3222")
            if g:
                key=(str(g),str(lineage or ""))
                if key not in lineage_groups:
                    lineage_groups.add(key); groups.add(str(g))
        max_cat=max(cat_scores.values()) if cat_scores else 0
        bonus=0 if len(groups)<2 else (10 if len(groups)==2 else 18)
        hard=any(str(f.get("severity") or "").lower()=="critical" and
                 (self._v321_is_hard_evidence(f) if hasattr(self,"_v321_is_hard_evidence") else False)
                 for f in findings)
        threat=min(100,max_cat+bonus)
        bus=self.results.get("evidence_bus_v3236") or {}
        if bus.get("promoted"):
            # This is computed from typed independent observations, not copied from V32 legacy score.
            threat=max(threat,int(bus.get("fusion_score") or 0))
            fams=set(bus.get("expert_families") or [])
            if "credential_theft" in fams:
                cat_scores["credential_theft"]=max(cat_scores["credential_theft"],int(bus.get("fusion_score") or 0))
            elif "malware" in fams:
                cat_scores["malware"]=max(cat_scores["malware"],int(bus.get("fusion_score") or 0))
        if hard: threat=max(threat,70)

        self.results["canonical_category_scores_v3222"]=cat_scores
        # Refresh legacy category-score containers consumed by the dashboard.
        legacy=self.results.get("category_scores")
        if isinstance(legacy,dict):
            mapping={
              "Phishing / Marka Taklidi":"phishing","Kimlik Bilgisi Hırsızlığı":"credential_theft",
              "Malware / Zararlı İndirme":"malware","Şüpheli JavaScript / Davranış":"javascript",
              "Yönlendirme Kötüye Kullanımı":"redirect","Gizlilik / Veri Sızdırma Riski":"privacy",
              "Sosyal Mühendislik":"social_engineering"
            }
            for label,key in mapping.items(): legacy[label]=cat_scores[key]
            self.results["category_scores"]=legacy
        self.results["threat_score"]=threat
        # Replace stale fusion score with canonical score while retaining raw fusion diagnostics.
        oldfusion=self.results.get("fusion") or {}
        self.results["raw_fusion_v3222"]=oldfusion
        self.results["fusion"]={
          "score":threat,"independent_experts":len(groups),
          "canonical":True,"category_scores":cat_scores,
          "evidence_count":len(findings)
        }
        r={"threat_score":threat,"category_scores":cat_scores,"evidence_count":len(findings),
           "independent_groups":sorted(groups),"claimed_brand_mismatch":claimed_brand_mismatch}
        self.results["canonical_scoring_v3222"]=r
        return r

    def decision_authority_v32321(self):
        """Compatibility delegate to canonical fusion/decision policy."""
        canonical=self.results.get("canonical_scoring_v3222") or {}
        ip=(self.results.get("post_guard_phishing_fusion_v32310") or
            self.results.get("independent_phishing_v323") or {})
        temporal=self.results.get("temporal_threat_memory_v3241") or self.results.get("temporal_history") or {}

        decision=compute_final_decision(
            canonical=canonical,
            phishing_hypothesis=ip,
            temporal_history=temporal,
            feed_off=bool(self.results.get("_feed_off_v3231")),
        )
        cats=dict(decision["category_scores"])
        threat=int(decision["engine_score"])

        canonical=dict(canonical)
        canonical["legacy_phishing_diagnostic_score_v32321"]=decision["legacy_phishing_diagnostic_score"]
        canonical["phishing_score"]=decision["phishing_engine_score"]
        canonical["category_scores"]=cats
        canonical["threat_score"]=threat
        canonical["decision_authority"]="canonical_fusion_policy"
        self.results["canonical_scoring_v3222"]=canonical
        self.results["canonical_category_scores_v3222"]=cats
        self.results["threat_score"]=threat
        self.results.setdefault("scores",{})["threat"]=threat
        self.results["risk_score"]=threat

        legacy=self.results.get("category_scores")
        if isinstance(legacy,dict):
            mapping={
              "Phishing / Marka Taklidi":"phishing","Kimlik Bilgisi Hırsızlığı":"credential_theft",
              "Malware / Zararlı İndirme":"malware","Şüpheli JavaScript / Davranış":"javascript",
              "Yönlendirme Kötüye Kullanımı":"redirect","Gizlilik / Veri Sızdırma Riski":"privacy",
              "Sosyal Mühendislik":"social_engineering"
            }
            for label,key in mapping.items():
                legacy[label]=int(cats.get(key) or 0)

        out={
          "engine_score":threat,
          "category_scores":cats,
          "phishing_authority":"post_guard_phishing_fusion_v32310",
          "phishing_engine_score":decision["phishing_engine_score"],
          "historical_threat_context":decision["historical_threat_context"],
          "legacy_phishing_diagnostic_score":decision["legacy_phishing_diagnostic_score"],
          "legacy_phishing_can_decide":False,
          "feed_off":decision["feed_off"],
          "final_score_owner":decision["final_score_owner"],
          "invariant":"Legacy URL/brand summaries are diagnostic evidence only; guarded family hypotheses own category scores and final engine verdict."
        }
        self.results["decision_authority_v32321"]=out
        return out

    def publish_canonical_truth_v3223(self):
        """
        V32.2.3 single source of truth:
        canonical findings -> defender.fusion -> scores -> assessment -> UI.
        No stale V17/V16 fusion/category cache may reach the dashboard.
        """
        canonical=self.results.get("canonical_scoring_v3222") or {}
        findings=self.results.get("findings") or []
        cat_scores=canonical.get("category_scores") or {}
        threat=int(canonical.get("threat_score") or 0)

        labels=[
          ("Phishing / Marka Taklidi","phishing",{"phishing"}),
          ("Kimlik Bilgisi Hırsızlığı","credential_theft",{"credential_theft","forms"}),
          ("Malware / Zararlı İndirme","malware",{"malware"}),
          ("Şüpheli JavaScript / Davranış","javascript",{"javascript","behavior"}),
          ("Yönlendirme Kötüye Kullanımı","redirect",{"redirect"}),
          ("Sosyal Mühendislik","social_engineering",{"social_engineering"}),
          ("Gizlilik / Veri Sızdırma Riski","privacy",{"privacy"}),
        ]
        rows=[]
        for label,key,accepted in labels:
            ev=[f for f in findings if f.get("category") in accepted]
            ev=sorted(ev,key=lambda f:({"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(
                str(f.get("severity") or "").lower(),9),-float(f.get("confidence") or 0)))
            score=int(cat_scores.get(key) or 0)

            # V32.3.24 category-support bridge: a non-zero canonical score must never
            # render as "no evidence". The bridge does NOT add score and does NOT create
            # a new voting finding; it only exposes the already-observed expert evidence
            # that owns the category score.
            support=[]
            if score>0 and not ev:
                ip=(self.results.get("post_guard_phishing_fusion_v32310") or
                    self.results.get("independent_phishing_v323") or {})
                full_ip=self.results.get("independent_phishing_v323") or {}
                brain=self.results.get("behavioral_brain_v3234") or {}
                bus=self.results.get("evidence_bus_v3236") or {}
                if key=="credential_theft":
                    st=(full_ip.get("expert_status") or {}).get("credential_intent") or {}
                    if st.get("active") or brain.get("credential_semantic") or brain.get("sensitive_controls"):
                        support.append({
                          "title":"Hassas kimlik doğrulama / veri giriş yüzeyi gözlendi",
                          "description":"Credential uzmanı hassas giriş kontrolü veya kimlik doğrulama semantiği gözlemledi. Bu açıklama mevcut kategori skorunun kaynağıdır; tek başına veri sızdırma kanıtı değildir.",
                          "severity":"high" if score>=50 else "medium",
                          "category":"credential_theft","diagnostic_support":True,
                          "score_eligible":False,"derived_evidence":True,
                          "source_expert":"credential_intent","producer":"category_support_v32324",
                          "evidence":str(st.get("reason") or ("sensitive_controls="+str(len(brain.get("sensitive_controls") or []))))
                        })
                elif key=="malware":
                    # Malware support is published only for a concrete malware-family event.
                    concrete=[x for x in (bus.get("events") or []) if isinstance(x,dict) and str(x.get("expert_family") or "")=="malware"]
                    if concrete:
                        support.append({"title":"Somut malware/download sensörü kanıtı","description":"Malware kategorisi somut download/hash/payload sensörü tarafından desteklendi.","severity":"high" if score>=50 else "medium","category":"malware","diagnostic_support":True,"score_eligible":False,"derived_evidence":True,"source_expert":"malware","producer":"category_support_v32324"})
                ev=support
            groups=sorted(set(str(f.get("independent_group") or f.get("source_expert") or f.get("source"))
                              for f in ev if (f.get("independent_group") or f.get("source_expert") or f.get("source"))))
            rows.append({"name":label,"score":score,"evidence":ev[:8],
                         "independent_experts":len(groups),"experts":groups})

        rows.sort(key=lambda x:x["score"],reverse=True)
        primary=rows[0] if rows else {"name":"","score":0,"evidence":[]}

        # THIS is the fusion object consumed by calculate/build_explainable_assessment/UI.
        self.results.setdefault("defender",{})["fusion"]={
          "score":threat,
          "verdict":"critical" if threat>=75 else "high" if threat>=50 else "guarded" if threat>=20 else "low" if threat>0 else "no_evidence",
          "primary":primary.get("name") if threat else "",
          "categories":rows,
          "experts":canonical.get("independent_groups") or [],
          "chains":[],
          "independent_experts":len(canonical.get("independent_groups") or []),
          "canonical":True,
          "evidence_count":len(findings)
        }

        # Synchronize every public score field used by the dashboard/API.
        self.results.setdefault("scores",{})["threat"]=threat
        self.results["risk_score"]=threat
        self.results["threat_score"]=threat
        self.results["defender"]["behavior_score"]=threat

        # Every UI evidence item must originate from canonical findings.
        for f in findings:
            if not f.get("canonical_event_id_v3222"):
                raw=self._v322_blob({"category":f.get("category"),"title":f.get("title"),
                                     "evidence":f.get("evidence"),"source":f.get("source")})
                f["canonical_event_id_v3222"]=hashlib.sha256(raw.encode()).hexdigest()[:24]

        self.build_explainable_assessment()
        assessment=self.results["defender"].get("assessment") or {}
        # Strip anything that somehow did not come from canonical evidence.
        valid={f.get("canonical_event_id_v3222") for f in findings}
        clean=[]
        for e in assessment.get("evidence") or []:
            match=next((f for f in findings if f.get("title")==e.get("title")
                        and f.get("category") in {
                          "phishing","credential_theft","forms","malware","javascript","behavior",
                          "redirect","social_engineering","privacy"}),None)
            if match and match.get("canonical_event_id_v3222") in valid:
                e["evidence_id"]=match.get("canonical_event_id_v3222")
                clean.append(e)
        assessment["evidence"]=clean
        self.results["defender"]["assessment"]=assessment

        out={"threat":threat,"category_count":len(rows),"evidence_count":len(findings),
             "ui_evidence_count":len(clean),"canonical":True}
        self.results["single_source_truth_v3223"]=out
        return out

    def fusion_trace_v32310(self):
        """Decision-DNA trace for the post-guard phishing hypothesis.

        Diagnostic only. It never adds threat evidence or changes a score. It records
        exactly which expert was active, the raw observation summary, guard outcome,
        canonical eligibility and whether a finding actually contributes downstream.
        Derived fusion summaries are explicitly non-voting to prevent feedback loops.
        """
        ip=self.results.get("independent_phishing_v323") or {}
        graph=self.results.get("causal_destination_graph_v3238") or {}
        canonical=self.results.get("findings") or []
        rows=[]
        status=ip.get("expert_status") or {}
        details=ip.get("experts") or {}
        reason_map={
            "identity":"brand_claims / registrable-domain relation",
            "credential_intent":"rendered DOM inputs/forms + intent semantics",
            "submission_exfil":"destination ownership graph strong causal edges",
            "visual":"verified visual baseline comparison",
            "runtime_stage":"DOM mutation + staged authentication path",
            "infrastructure":"URL/infrastructure context (context-only)",
            "social_engineering":"pressure/verification semantics (corroboration-only)"
        }
        for name in ("identity","credential_intent","submission_exfil","visual","runtime_stage","infrastructure","social_engineering"):
            st=status.get(name) or {}
            det=details.get(name) or {}
            active=bool(st.get("active") or det)
            decisive=name in set(ip.get("decisive_experts") or [])
            rows.append({
                "expert_family":name,"active":active,"decisive":decisive,
                "raw_observation":det.get("detail") or reason_map.get(name),
                "guard_result":st.get("reason") or ("context_only" if name in ("infrastructure","social_engineering") else "not_observed"),
                "score_eligible":bool(active and decisive),
                "weight":det.get("weight"),
                "vote_policy":"decisive_vote" if active and decisive else "no_vote"
            })
        events=[]
        for f in canonical:
            prod=str(f.get("producer") or "")
            src=str(f.get("source_expert") or "")
            derived=bool(f.get("derived_evidence") or prod=="independent_phishing_v323" or src=="independent_phishing")
            events.append({
                "event_id":f.get("canonical_event_id_v3222") or f.get("canonical_event_id_v322") or f.get("evidence_event_id"),
                "title":f.get("title"),"producer":prod,"expert_family":src,
                "category":f.get("category"),"severity":f.get("severity"),
                "derived":derived,"score_eligible":bool(f.get("score_eligible_v322",True) and not derived),
                "contribution_policy":"blocked_feedback_loop" if derived else "canonical_candidate"
            })
        trace={
            "engine_score":int(ip.get("score") or 0),"engine_verdict":ip.get("verdict"),
            "reasons":ip.get("reasons") or [],"decisive_experts":ip.get("decisive_experts") or [],
            "experts":rows,"canonical_events":events,
            "destination_graph":{
                "concrete_exfil":bool(graph.get("concrete_exfil")),
                "strong_causal_edges":graph.get("strong_causal_edges") or [],
                "rejected_or_context_edges":graph.get("rejected_edges") or graph.get("context_edges") or []
            },
            "feedback_loop_guard":{
                "derived_fusion_can_vote":False,
                "rule":"A fusion/summary finding can never become an input expert or independent corroborator."
            },
            "diagnostic_only":True
        }
        self.results["fusion_trace_v32310"]=trace
        return trace

    def build_evidence_bus_v3236(self):
        """V32.3.6 canonical Evidence Bus.

        Converts producer-specific behavioral observations into typed expert events.
        Events carry lineage so duplicated observations cannot manufacture independent
        corroboration. External feeds are never required by this bus.
        """
        z=self.results.get("zero_day_behavior_v32") or {}
        events=[]; seen=set()

        def norm_family(v):
            x=str(v or "other").strip().lower()
            aliases={"credential":"credential_theft","network_exfiltration":"network_exfil",
                     "data_exfiltration":"network_exfil","suspicious_script":"javascript",
                     "redirect_abuse":"redirect","runtime_anomaly":"runtime"}
            return aliases.get(x,x)

        def emit(expert, modality, title, detail, confidence, weight, source_event=None, causal=False):
            expert=norm_family(expert); modality=str(modality or expert).strip().lower()
            # Lineage is based on the underlying observation, not on the producer that copied it.
            raw=json.dumps({"expert":expert,"modality":modality,"title":title,"detail":detail,
                            "source_event":source_event},ensure_ascii=False,sort_keys=True,default=str)
            lineage=hashlib.sha256(raw.encode()).hexdigest()[:24]
            dedupe=(expert,lineage)
            if dedupe in seen: return None
            seen.add(dedupe)
            eid="EV-"+hashlib.sha256((lineage+"|v3236").encode()).hexdigest()[:20]
            ev={"event_id":eid,"lineage_id":lineage,"producer":"evidence_bus_v3236",
                "source_producer":"zero_day_behavior_v32","expert_family":expert,
                "modality":modality,"title":str(title or expert)[:300],
                "observation":str(detail or "")[:1200],"confidence":round(float(confidence or 0),3),
                "weight":float(weight or 0),"causal":bool(causal),"feed_independent":True,
                "derived":False}
            events.append(ev); return ev

        for item in z.get("evidence") or []:
            if not isinstance(item,dict): continue
            fam=norm_family(item.get("family")); grp=str(item.get("group") or fam).lower()
            emit(fam,grp,item.get("title"),item.get("detail"),item.get("confidence",.5),item.get("weight",0),
                 source_event=item.get("event_id"),causal=(grp=="credential_flow" and "harici" in str(item.get("detail") or "").lower()))

        # Also import concrete V32.3.4 causal chains, but only as their own lineage.
        brain=self.results.get("behavioral_brain_v3234") or {}
        if brain.get("causal_chain"):
            emit("network_exfil","runtime_sink","Hassas kaynak → harici ağ hedefi",
                 json.dumps(brain.get("causal_chain"),ensure_ascii=False,default=str),.94,32,
                 source_event="behavioral_brain_v3234:causal_chain",causal=True)

        # Corroboration uses distinct modalities/lineages. A derived fusion result is never
        # counted as a third independent expert.
        decisive={"credential_theft","network_exfil","identity","malware","redirect","runtime","javascript"}
        by_expert={}; modalities=set()
        for ev in events:
            modalities.add(ev["modality"])
            cur=by_expert.get(ev["expert_family"])
            strength=ev["weight"]*ev["confidence"]
            if cur is None or strength > cur["weight"]*cur["confidence"]: by_expert[ev["expert_family"]]=ev
        decisive_events=[e for k,e in by_expert.items() if k in decisive]
        corroborators=[e for k,e in by_expert.items() if k not in decisive]
        independent_modalities={e["modality"] for e in events}

        # Publish each primary expert observation as canonical evidence. Severity follows
        # observation strength, not a legacy aggregate score.
        created=[]
        catmap={"credential_theft":"credential_theft","network_exfil":"privacy","identity":"phishing",
                "malware":"malware","redirect":"redirect","runtime":"behavior","javascript":"javascript",
                "cloaking":"behavior"}
        for ev in list(by_expert.values()):
            strength=ev["weight"]*ev["confidence"]
            sev="high" if strength>=24 else "medium" if strength>=11 else "low"
            self.add_finding(ev["title"],sev,ev["observation"],catmap.get(ev["expert_family"],"behavior"),
                             evidence=f"{ev['event_id']} • {ev['expert_family']} • {ev['modality']}",
                             confidence=ev["confidence"])
            f=self.results["findings"][-1]
            f.update({"evidence_event_id":ev["event_id"],"evidence_lineage_id":ev["lineage_id"],
                      "producer":"evidence_bus_v3236","source_expert":ev["expert_family"],
                      "independent_group":ev["modality"],"feed_independent":True,
                      "derived_evidence":False,"canonical_event_id_v3222":ev["event_id"]})
            created.append(ev["event_id"])

        # Derived fusion event explains the brain's conclusion but is marked derived and
        # must not inflate independent-expert counting.
        fusion_score=0
        strengths=sorted((e["weight"]*e["confidence"] for e in decisive_events),reverse=True)
        if strengths: fusion_score=round(min(100,sum(strengths[:3]) + (10 if len(independent_modalities)>=2 else 0)))
        if "cloaking" in by_expert and decisive_events: fusion_score=min(100,fusion_score+8)
        promoted=bool(decisive_events and len(independent_modalities)>=2 and fusion_score>=45)
        if promoted:
            primary=max(decisive_events,key=lambda e:e["weight"]*e["confidence"])
            self.add_finding("Evidence Bus: bağımsız davranış korelasyonu","high",
                "Bağımsız gözlem hatları aynı tehdit hipotezini destekliyor: "+", ".join(sorted(independent_modalities)),
                catmap.get(primary["expert_family"],"behavior"),
                evidence=" • ".join(e["event_id"] for e in events[:8]),confidence=min(.96,max(e["confidence"] for e in events)))
            f=self.results["findings"][-1]
            f.update({"producer":"evidence_bus_v3236","source_expert":"fusion_brain",
                      "derived_evidence":True,"score_hint_v3236":fusion_score,"feed_independent":True,
                      "support_event_ids":[e["event_id"] for e in events]})

        out={"events":events,"event_count":len(events),"created_findings":created,
             "independent_modalities":sorted(independent_modalities),"expert_families":sorted(by_expert),
             "fusion_score":fusion_score,"promoted":promoted,"feed_independent":True,
             "zero_day_source_score":z.get("score"),
             "principle":"Producer score is not copied; typed observations with lineage are fused."}
        self.results["evidence_bus_v3236"]=out
        return out

    def fusion_brain_bridge_v3235(self):
        """Bridge explicit feed-independent behavioral experts into canonical evidence."""
        findings=self.results.get("findings") or []
        brain=self.results.get("behavioral_brain_v3234") or {}
        groups=set(); evidence=[]
        for f in findings:
            blob=self._v322_blob(f).lower()
            meta=f.get("metadata") or {}
            producer=str(meta.get("producer") or f.get("producer") or "").lower()
            if ("v32" in producer and ("behavior" in producer or "zero" in producer)) or "davranışsal yeni-tehdit korelasyonu" in blob:
                raw=meta.get("independent_groups") or meta.get("groups") or meta.get("behavior_groups") or []
                if isinstance(raw,str):
                    raw=[x.strip() for x in re.split(r"[,;|]",raw) if x.strip()]
                if isinstance(raw,list):
                    groups.update(str(x).strip().lower() for x in raw)
                for g in ("cloaking","credential_theft","network_exfil","redirect","identity","malware","runtime"):
                    if g in blob: groups.add(g)
                evidence.append({"title":str(f.get("title") or "")[:300],
                                 "producer":str(meta.get("producer") or f.get("producer") or "v32_behavior"),
                                 "evidence_id":f.get("evidence_id") or f.get("canonical_event_id"),
                                 "severity":f.get("severity")})

        # Behavioral Brain contributes only observed credential/causal state.
        if brain.get("causal_chain"):
            groups.update(("credential_theft","network_exfil"))
        elif brain.get("credential_semantic") or brain.get("sensitive_controls"):
            groups.add("credential_theft")

        decisive={g for g in groups if g in {"credential_theft","network_exfil","identity","malware","redirect","runtime"}}
        corroborators=groups-decisive
        score=0
        weights={"credential_theft":29,"network_exfil":32,"identity":24,"malware":45,"redirect":18,"runtime":18}
        score=sum(weights.get(g,0) for g in decisive)
        if "cloaking" in corroborators and decisive: score+=20
        if len(decisive)>=2: score+=14
        score=min(100,score)

        # Cloaking is corroborative only. Never promote it alone.
        promoted=bool(decisive and (len(groups)>=2 or brain.get("causal_chain")))
        report={"score":score,"promoted":promoted,"expert_groups":sorted(groups),
                "decisive_experts":sorted(decisive),"corroborators":sorted(corroborators),
                "evidence":evidence[:30],"feed_independent":True,
                "rule":"legacy score/severity is not copied; independent support is reconstructed"}
        self.results["fusion_brain_v3235"]=report
        if promoted and score>=45:
            self._v323_add(
                "credential" if "credential_theft" in groups else "phishing",
                "Bağımsız davranış uzmanları aynı tehdidi destekliyor",
                "Feed bağımsız davranış uzmanları aynı saldırı hipotezini bağımsız kanıtlarla destekledi.",
                "critical" if score>=80 else "high",
                {"source_expert":"fusion_brain","producer":"fusion_brain_bridge_v3235",
                 "independent_groups":sorted(groups),"bridge_score":score,
                 "feed_independent":True,"causal":bool(brain.get("causal_chain")),
                 "evidence_summary":evidence[:12]})
        return report

    def temporal_threat_memory_v3241(self):
        """Read-only historical sensor. Prediction is never promoted to ground truth.
        Only prior concrete internally observed causal evidence / known IOC may vote.
        External-feed-only history is never engine authority, especially in Feed OFF mode.
        """
        u=normalize_url(self.results.get("analyzed_url") or self.results.get("final_url") or "")
        uh=hashlib.sha256(u.encode()).hexdigest(); root=get_root_domain(urlparse(u).hostname or "")
        now=datetime.now(timezone.utc); rows=[]
        try:
            _ensure_trust_db()
            with db_connect(DB_PATH,timeout=5) as con:
                rows=con.execute("SELECT observed_at,surface_class,credential_surface,proven_sensitive_crossroot,known_ioc,engine_score,authority,title,dom_sha256,scan_version FROM temporal_observations_v3241 WHERE url_hash=? ORDER BY observed_at DESC LIMIT 24",(uh,)).fetchall()
        except Exception as e:
            rep={"state":"unavailable","error":str(e)[:240],"history_count":0,"score_eligible":False}; self.results["temporal_threat_memory_v3241"]=rep; return rep
        cur=self._v3241_surface_snapshot(); hist=[]; hard_recent=[]; material=False
        for r in rows:
            try: dt=datetime.fromisoformat(str(r[0]).replace("Z","+00:00")); dt=dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc); age=max(0,(now-dt.astimezone(timezone.utc)).days)
            except Exception: age=9999
            item={"observed_at":r[0],"surface_class":r[1],"credential_surface":bool(r[2]),"proven_sensitive_crossroot":bool(r[3]),"known_ioc":bool(r[4]),"engine_score":float(r[5] or 0),"authority":r[6],"title":r[7],"age_days":age,"scan_version":r[9]}
            hist.append(item)
            hard=bool((r[3] or r[4]) and str(r[6]) in ("internally_observed_hard","analyst_verified"))
            if hard and age<=30: hard_recent.append(item)
            if str(r[1] or "")!=cur["surface_class"] and (bool(r[2]) or cur["credential_surface"]): material=True
        score_eligible=bool(hard_recent)
        rep={"state":"ok","history_count":len(hist),"current_surface":cur,"recent_history":hist[:8],"prior_hard_evidence":hard_recent[:8],"material_surface_change":material,"score_eligible":score_eligible,
             "policy":"Current observation, engine prediction and verified ground truth remain separate. Only recent concrete internal causal/IOC history may vote; weak predictions are diagnostic only."}
        if score_eligible:
            self.add_finding("Yakın geçmişte aynı URL'de doğrulanabilir zararlı davranış gözlendi","high","Mevcut içerik değişmiş olsa bile aynı URL için son 30 gün içinde Web Defender'ın doğrudan gözlemlediği somut hassas-veri→harici-hedef veya IOC kanıtı bulunuyor.","phishing",json.dumps({"history":hard_recent[:4],"current_surface":cur},ensure_ascii=False),.94)
            self.results["findings"][-1].update({"producer":"temporal_threat_memory_v3241","source_expert":"temporal_behavior","independent_group":"phishing_family_history","evidence_lineage_id":"v3241-temporal-hard-history","historical_evidence":True,"derived_evidence":True})
        self.results["temporal_threat_memory_v3241"]=rep; return rep

    def persist_temporal_observation_v3241(self):
        """Persist compact fingerprints and authority, never full page bodies or credentials."""
        try:
            _ensure_trust_db(); u=normalize_url(self.results.get("analyzed_url") or self.results.get("final_url") or ""); root=get_root_domain(urlparse(u).hostname or "")
            snap=self._v3241_surface_snapshot(); nonex=self.results.get("non_executing_interaction_v324") or {}
            # Static/regex path count is diagnostic only. Hard temporal authority requires
            # a settled concrete causal edge or a non-feed verified IOC/hash.
            graph=self.results.get("causal_destination_graph_v3238") or {}
            jsflow=self.results.get("javascript_dataflow") or self.results.get("js_dataflow_v3244") or {}
            concrete_exfil=bool(
                (graph.get("concrete_exfil") and (graph.get("strong_causal_edges") or []))
                or jsflow.get("proven_sensitive_crossroot_paths")
            )
            proven=concrete_exfil
            known=False
            for f in self.results.get("findings") or []:
                blob=(str(f.get("producer") or "")+" "+str(f.get("source_expert") or "")+" "+str(f.get("title") or "")).lower()
                is_ioc=("known_ioc" in blob or "malware_hash" in blob or "malicious hash" in blob)
                external=bool(f.get("external_intelligence_v32320") or f.get("feed_off_held_v3231"))
                analyst=bool(f.get("analyst_verified") or str(f.get("authority") or "")=="analyst_verified")
                if is_ioc and (not external or analyst): known=True
            authority="internally_observed_hard" if (concrete_exfil or known) else "observation"
            score=float(((self.results.get("defender") or {}).get("assessment") or {}).get("score") or self.results.get("risk_score") or 0)
            oid="TO-"+uuid.uuid4().hex; ts=datetime.now(timezone.utc).isoformat(); uh=hashlib.sha256(u.encode()).hexdigest(); status=int((self.results.get("http") or {}).get("status_code") or 0)
            prov=json.dumps({"concrete_exfil":concrete_exfil,"proven_nonexecuting_path_diagnostic":bool(nonex.get("proven_static_path_count")),"known_ioc":known,"feed_off":bool(self.results.get("_feed_off_v3231")),"external_scripts":(self.results.get("static_source_intelligence_v32317") or {}).get("external_script_inspection_v3241")},ensure_ascii=False)
            with db_connect(DB_PATH,timeout=5) as con:
                con.execute("INSERT INTO temporal_observations_v3241(observation_id,observed_at,url_hash,normalized_url,registrable_domain,final_url,http_status,title,dom_sha256,surface_class,credential_surface,proven_sensitive_crossroot,known_ioc,engine_score,authority,provenance,scan_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(oid,ts,uh,u,root,str(self.results.get("final_url") or u),status,snap["title"],snap["dom_sha256"],snap["surface_class"],int(snap["credential_surface"]),int(proven),int(known),score,authority,prov,APP_VERSION))
            rep={"stored":True,"observation_id":oid,"authority":authority,"surface_class":snap["surface_class"],"stores_full_body":False}
        except Exception as e: rep={"stored":False,"error":str(e)[:240]}
        self.results["temporal_persist_v3241"]=rep; return rep

    def calculate_scores(self):
        http_ok = self.results["http"]["status_code"] is not None
        body_ok = bool(self.results["http"].get("content_trusted_for_analysis"))
        browser_proxy_failed = (
            self.results.get("browser", {}).get("decision") in ("proxy_tunnel_failed", "hosting_access_restricted")
            or self.results.get("browser", {}).get("failure_kind") in ("hosting_proxy_tunnel", "pythonanywhere_proxy_tunnel")
        )

        # 1) SECURITY POSTURE: yalnızca gerçek HTTP cevabı üzerinden hesaplanır.
        if body_ok:
            posture=0
            if self.results["domain_info"]["protocol"] == "http": posture += 25
            for info in self.results["security_headers"].values():
                if not info.get("present"): posture += 3 if info.get("severity")=="low" else 7
            if self.results["domain_info"]["protocol"]=="https" and self.results["ssl_info"].get("checked") and not self.results["ssl_info"].get("valid"):
                posture += 25
            posture += min(sum(len(c.get("issues",[])) for c in self.results["cookies"])*2,20)
            posture += min(len(self.results["mixed_content"])*2,12)
            self.results["scores"]["security_posture"] = min(round(posture),100)
        else:
            self.results["scores"]["security_posture"] = None

        # 2) PASSIVE RISK zaten check_passive_defender tarafından ayrı hesaplanır.
        passive_score = self.results["defender"].get("passive_analysis",{}).get("score",0)
        self.results["scores"]["passive_risk"] = passive_score

        # 3) THREAT EVIDENCE: V32.4.2 — threat score is the EXCLUSIVE output of
        # canonical_scoring_authority_v3222 → decision_authority_v32321.
        # calculate_scores no longer re-derives threat independently.
        # This eliminates the "compute twice / pick one" ambiguity.
        # canonical_scoring_authority runs AFTER this; we plant a sentinel here
        # and let the canonical authority overwrite it.
        threat = self.results.get("scores", {}).get("threat")  # may already be set by fast path
        # ML learning bonus is still useful as a passive signal for diagnostics.
        _ml_bonus = 0
        ml = self.results.get("learning", {})
        if ml.get("active") and ml.get("probability") is not None:
            prob = float(ml["probability"])
            if prob >= .90: _ml_bonus = 12
            elif prob >= .75: _ml_bonus = 6
        self.results["scores"]["_ml_learning_bonus_diagnostic"] = _ml_bonus
        # threat will be written by canonical_scoring_authority_v3222 + decision_authority_v32321
        self.results["scores"]["threat"] = threat  # preserve any existing value; canonical will overwrite
        self.results["risk_score"] = threat if threat is not None else passive_score
        self.results["defender"]["behavior_score"] = threat

        # Confidence: yalnızca gerçekten gözlemlenen katmanları ifade eder.
        # Deep Analysis browser worker başarısızsa statik HTTP 200 tek başına yüksek güven üretemez.
        browser = self.results.get("browser", {})
        browser_attempted = bool(browser.get("attempted"))
        browser_ok = bool(browser.get("success"))
        dynamic_incomplete = browser_attempted and not browser_ok
        self.results["scan"]["dynamic_analysis_complete"] = browser_ok
        self.results["scan"]["dynamic_analysis_status"] = ("completed" if browser_ok else "failed" if browser_attempted else "not_run")

        confidence=15
        if self.results["dns"].get("resolved"): confidence += 10
        probe=self.results.get("network_probe",{})
        probe_ports=probe.get("ports",{})
        if probe_ports and probe.get("authoritative", True): confidence += 10
        if self.results["ssl_info"].get("valid"): confidence += 5
        if http_ok: confidence += 20
        if body_ok: confidence += 20
        if browser_ok: confidence += 25
        if self.results.get("learning",{}).get("active"): confidence += 5
        confidence -= min(len(self.results["errors"])*3,15)
        if dynamic_incomplete: confidence = min(confidence, 64)
        self.results["scores"]["confidence"] = max(0,min(confidence,100))

        critical=sum(1 for f in self.results["findings"] if f.get("score_eligible_v322") is not False and f["severity"]=="critical" and f.get("category") in {"phishing","credential_theft","malware","behavior","javascript","privacy","redirect","forms"})
        types=self.results["defender"].get("threat_types",[])

        if not body_ok:
            restricted = bool(self.results["http"].get("access_restricted") or self.results.get("browser",{}).get("access_restricted"))
            if restricted:
                self.results["risk_level"]="🔒 İÇERİK ERİŞİM KONTROLÜ NEDENİYLE DOĞRULANAMADI"
            elif passive_score >= 55:
                self.results["risk_level"]="⚠️ YÜKSEK PASİF RİSK / İÇERİK DOĞRULANAMADI"
            elif passive_score >= 30:
                self.results["risk_level"]="⚠️ PASİF RİSK SİNYALLERİ / İÇERİK DOĞRULANAMADI"
            elif passive_score >= 15:
                self.results["risk_level"]="🟡 PASİF OLARAK DİKKAT GEREKTİRİYOR / İÇERİK DOĞRULANAMADI"
            else:
                self.results["risk_level"]="❓ İÇERİK DOĞRULANAMADI / PASİF ANALİZ"
            if restricted:
                if browser_proxy_failed:
                    self.results["defender"]["recommendations"]=[
                        "HTTP 401/403/429 erişim kontrolü nedeniyle hedef uygulamanın gerçek içeriği doğrulanamadı.",
                        "Browser Worker PythonAnywhere outbound/proxy kısıtı nedeniyle hedefe ulaşamadı; bu hedef sitenin zararlı olduğuna dair kanıt değildir.",
                        "Gerçek DOM görülmediği için Threat Evidence N/A kalır; pasif URL/domain sinyalleri ayrı değerlendirilir."
                    ]
                else:
                    self.results["defender"]["recommendations"]=[
                        "HTTP 401/403/429 erişim kontrolü nedeniyle hedef uygulamanın gerçek içeriği doğrulanamadı.",
                        "403/challenge sayfası phishing veya malware bulunmadığının kanıtı değildir.",
                        "Browser Worker da erişim kontrolünü aşamazsa Threat Evidence N/A kalır."
                    ]
            else:
                self.results["defender"]["recommendations"]=[
                    "Sayfa içeriğine ulaşılamadığı için phishing/malware hakkında olumlu veya olumsuz hüküm verilemez.",
                    "TCP port durumu erişilebilirlik bilgisidir; tek başına zararlı site kanıtı değildir.",
                    "Pasif risk URL/domain sinyallerini gösterir ve Threat Evidence skorundan ayrıdır."
                ]
        elif threat is not None and (threat >= 75 or critical >= 2):
            self.results["risk_level"]="🚨 TEHLİKELİ"
        elif threat is not None and (threat >= 45 or critical >= 1):
            self.results["risk_level"]="⚠️ ŞÜPHELİ / YÜKSEK RİSK"
        elif threat is not None and threat >= 20:
            self.results["risk_level"]="🟡 DÜŞÜK-ORTA TEHDİT SİNYALİ"
        else:
            if dynamic_incomplete:
                self.results["risk_level"]="❓ DİNAMİK ANALİZ TAMAMLANAMADI / STATİK OLARAK BELİRGİN TEHDİT YOK"
                self.results["defender"]["recommendations"]=[
                    "Statik içerikte belirgin zararlı davranış kanıtı bulunmadı; bu sonuç güvenli hükmü değildir.",
                    "Browser Worker tamamlanamadığı için JavaScript sonrası DOM, runtime ağ trafiği ve dinamik formlar doğrulanamadı.",
                    "Dinamik analiz düzeltilmeden bu hedef için kesin güvenli kararı verilmemelidir."
                ]
            else:
                self.results["risk_level"]="✅ BELİRGİN ZARARLI DAVRANIŞ BULUNMADI"
        # Zayıf bir kategori etiketi tek başına tüm siteyi "şüpheli" yapmaz.
        # Ana karar toplam kanıt gücünden gelir; kategori ayrıntıları ayrıca gösterilir.
        if body_ok and types and 20 <= (threat or 0) < 45:
            self.results["risk_level"]="🟡 DİKKAT GEREKTİREN SİNYALLER"

        self.apply_safety_gate_v21()
        self.build_explainable_decision_graph_v28()
        self.build_explainable_assessment()
        # Every user/live scan may become an observation, but never a training label by itself.
        try: self.record_live_observation_v301()
        except Exception as _obs_exc: self.results["live_discovery_v301"]={"error":str(_obs_exc)[:300]}

    def finalize_canonical_verdict_ui_v32361(self):
        """One final authority for the user-facing verdict label/icon.

        The label is derived from the canonical threat score after all fusion,
        guards and consistency checks. Observation failures keep their N/A-style
        verdict and are never converted into a clean result.
        """
        coverage = self.results.get("coverage_v19") or {}
        integrity = self.results.get("pipeline_integrity_v3221") or {}
        http = self.results.get("http") or {}
        browser = self.results.get("browser") or {}

        observed = float(coverage.get("observed_percent") or integrity.get("observed_percent") or 0)
        restricted = bool(http.get("access_restricted") or browser.get("access_restricted"))
        body_ok = bool(http.get("content_trusted_for_analysis") or browser.get("success"))
        access_state = self.results.get("target_access_v32313") or self.classify_target_access_protection_v32313()
        access_protected = bool(access_state.get("suspected"))
        domain_imp = self.results.get("domain_impersonation_v32313") or {}
        passive_identity_threat = bool(domain_imp.get("detected"))

        score = (self.results.get("scores") or {}).get("threat")
        if score is None:
            score = (self.results.get("canonical_scoring_v3222") or {}).get("threat_score")
        if score is None:
            score = ((self.results.get("defender") or {}).get("fusion") or {}).get("score")
        try:
            score = None if score is None else max(0, min(100, int(round(float(score)))))
        except Exception:
            score = None

        http_decision = str(http.get("decision") or "")
        browser_decision = str(browser.get("decision") or "")
        target_unavailable = (http_decision == "target_content_unavailable" or browser_decision == "target_content_unavailable")
        stateful = browser.get("stateful_surface") or {}
        surface_unverified = bool(body_ok and stateful.get("interaction_gate_suspected") and not stateful.get("application_surface_verified"))

        if not body_ok and passive_identity_threat:
            label = "⚠️ ŞÜPHELİ KİMLİK / ANALİZ SINIRLI"
            band = "guarded_unverified"
        elif access_protected and not body_ok:
            label = "🛡️ HEDEF ERİŞİM KORUMASI / ERİŞİM KISITI NEDENİYLE ANALİZ SINIRLI"
            band = "unverified"
        elif restricted and not body_ok:
            label = "🛡️ HEDEF ERİŞİM KORUMASI / ERİŞİM KISITI NEDENİYLE ANALİZ SINIRLI"
            band = "unverified"
        elif target_unavailable and not body_ok:
            label = "🌐 HEDEF İÇERİĞİ ALINAMADI / ANALİZ SINIRLI"
            band = "unverified"
        elif not body_ok or observed <= 0 or score is None:
            label = "❓ İÇERİK DOĞRULANAMADI / ANALİZ EKSİK"
            band = "unverified"
        elif surface_unverified and score < 25:
            label = "🧭 UYGULAMA YÜZEYİ DOĞRULANAMADI / ANALİZ KISMİ"
            band = "unverified"
        elif score >= 70:
            label = "🔴 BELİRGİN ZARARLI DAVRANIŞ BULUNDU"
            band = "danger"
        elif score >= 45:
            label = "🟠 ŞÜPHELİ / YÜKSEK RİSK"
            band = "high"
        elif score >= 25:
            label = "🟡 DİKKAT GEREKTİREN SİNYALLER"
            band = "guarded"
        else:
            label = "🟢 BELİRGİN TEHDİT KANITI YOK"
            band = "low"

        self.results["risk_level"] = label
        assessment = (self.results.setdefault("defender", {})).setdefault("assessment", {})
        if not body_ok and passive_identity_threat:
            assessment["plain_summary"] = "Hedef içeriği tam doğrulanamadı; ancak alan adı/kimlik katmanında bağımsız taklit veya typosquatting sinyali gözlendi. Erişim kısıtı bu pasif kanıtı geçersiz kılmaz."
            assessment["action"] = "Alan adını dikkatle doğrulayın; hassas bilgi girmeyin. İçerik analizi sınırlı olsa da kimlik/domain uyarısını dikkate alın."
        elif surface_unverified and score is not None and score < 25:
            assessment["plain_summary"] = "Sayfa yüklendi ancak giriş/devam/doğrulama benzeri bir etkileşim kapısı gözlenirken gerçek form veya hassas giriş yüzeyi doğrulanamadı. Bu bir sensör/uygulama-durumu boşluğudur; güvenli hükmü değildir."
            assessment["action"] = "Uygulama yüzeyi doğrulanamadığı için sonucu kısmi kabul edin. Web Defender canlı hedefte buton tıklamaz, veri girmez veya form göndermez."
        elif not body_ok and access_protected:
            assessment["plain_summary"] = "Hedef, erişim koruması, bot/WAF benzeri bir kısıt veya erişim politikası nedeniyle gerçek sayfa içeriğini analiz ortamına sunmadı. Bu durum sitenin güvenli veya zararlı olduğunu kanıtlamaz."
            assessment["action"] = "İçerik doğrulanamadığı için güvenli hükmü vermeyin. Web Defender erişilebilen URL/domain, DNS/TLS, IOC ve diğer bağımsız sinyalleri değerlendirmeye devam eder."
        self.results["ui_verdict_v32361"] = {
            "label": label,
            "band": band,
            "canonical_threat_score": score,
            "observed_percent": observed,
            "body_observed": body_ok,
            "rule": "canonical threat score -> one UI label/icon; observation failure blocks clean verdict but never suppresses independent passive threat evidence"
        }
        return self.results["ui_verdict_v32361"]

