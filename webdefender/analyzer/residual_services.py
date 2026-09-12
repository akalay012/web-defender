"""Residual analysis services.

Compatibility-era helper services used by the modular orchestrator. These
helpers do not own HTTP routing or final presentation.
"""
import requests
from ..metadata import APP_VERSION
import os, re, json, time, hashlib, math, uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

from ..database import db_connect
from ..state import LEARNING_ENGINE, THREAT_INTEL_STORE
from .url_domain import get_root_domain, get_canonical_root
from ..guards.policy import is_hard_evidence_text
from ..fusion.policy import compute_final_decision

class ResidualServicesMixin:
    def evaluate_final_decision(self):
        return self.decision_authority_v32321()

    def evaluate_hard_evidence(self, finding):
        return self._v321_is_hard_evidence(finding)

    def evaluate_temporal_history(self):
        return self.temporal_threat_memory_v3241()

    def persist_temporal_history(self):
        return self.persist_temporal_observation_v3241()

    def check_cors(self, headers):
        origin      = headers.get("Access-Control-Allow-Origin", "")
        credentials = headers.get("Access-Control-Allow-Credentials", "")
        risk = "none"
        if origin == "*":
            risk = "low"
        if origin == "*" and credentials.lower() == "true":
            risk = "high"
            self.add_finding(
                "Geniş CORS yapılandırması", "high",
                "Wildcard origin (*) ile credentials birlikte kullanılıyor.",
                "cors", f"origin={origin}; credentials={credentials}", 1.0,
            )
        self.results["cors"] = {
            "allow_origin": origin, "allow_credentials": credentials,
            "wildcard": origin == "*", "risk": risk,
        }

    def apply_local_learning(self):
        try:
            pred=LEARNING_ENGINE.predict(self.results["defender"]["feature_vector"])
            self.results["learning"].update(pred)
            self.results["learning"]["stats"] = LEARNING_ENGINE.stats()
            if pred.get("active") and pred.get("probability") is not None:
                p=float(pred["probability"])
                if p >= .90:
                    self.add_finding("Yerel öğrenme modeli: yüksek risk olasılığı", "high",
                        f"Doğrulanmış yerel örneklerden öğrenen model bu sayfayı %{p*100:.1f} zararlı/şüpheli olasılıkla sınıflandırdı.",
                        "learning", f"samples={pred.get('sample_count')}", 0.78)
                elif p >= .75:
                    self.add_finding("Yerel öğrenme modeli: şüpheli örüntü", "medium",
                        f"Yerel model %{p*100:.1f} risk olasılığı hesapladı.", "learning",
                        f"samples={pred.get('sample_count')}", 0.70)
        except Exception as exc:
            self.results["errors"].append({"module":"local_learning", "error":str(exc)})

    def check_local_threat_intel(self, url):
        """Önce Web Defender'ın kendi IOC hafızasını sorgular; ağ servisine bağımlı değildir."""
        ti=self.results['threat_intelligence']
        matches=THREAT_INTEL_STORE.lookup(url)
        ti['sources'].append({'name':'Web Defender Local IOC','status':'ok','matches':len(matches)})
        for x in matches[:30]:
            ti['matches'].append({'source':x.get('source'),'type':x.get('threat_type'),'ioc':x.get('ioc'),'malware':x.get('malware_family'),'local_cache':True})
            sev='critical' if x.get('source') in ('URLhaus','ThreatFox') else 'high'
            self.add_finding('Yerel IOC hafızası eşleşmesi',sev,
                f"Web Defender IOC veritabanında {x.get('source')} kaynaklı aktif kayıt eşleşti.",
                'malware',json.dumps({'ioc':x.get('ioc'),'ioc_type':x.get('ioc_type'),'source':x.get('source'),'threat_type':x.get('threat_type'),'malware':x.get('malware_family')},ensure_ascii=False),.985)

    def check_cisa_kev(self):
        """NVD adaylarından CISA KEV eşleşmelerini güvenli biçimde işaretler; exploit yapmaz."""
        candidates={x.get('cve') for x in self.results.get('cve_intelligence',{}).get('candidates',[]) if x.get('cve')}
        if not candidates: return
        try:
            r=requests.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',headers={'User-Agent':f'WebDefender/{APP_VERSION}'},timeout=8)
            if not r.ok: return
            for x in r.json().get('vulnerabilities',[]):
                if x.get('cveID') in candidates:
                    self.results['cve_intelligence']['kev_matches'].append({'cve':x.get('cveID'),'vendor':x.get('vendorProject'),'product':x.get('product'),'date_added':x.get('dateAdded'),'ransomware_use':x.get('knownRansomwareCampaignUse'),'status':'known_exploited_vulnerability'})
        except Exception as e:
            self.results['errors'].append({'module':'cisa_kev','error':str(e)[:220]})

    def evidence_text_v32362(self, value):
        """Render nested evidence deterministically; never leak Python/JS object repr."""
        if value is None:
            return ""
        if isinstance(value, (str, int, float, bool)):
            return str(value)
        if isinstance(value, (list, tuple, set)):
            return " • ".join(x for x in (self.evidence_text_v32362(v) for v in value) if x)
        if isinstance(value, dict):
            preferred=("evidence_id","canonical_event_id","expert_family","expert","modality",
                       "producer","source","group","family","title","description","detail",
                       "observation","reason","signal","value","target","destination","url")
            parts=[]
            for k in preferred:
                if k in value and value[k] not in (None,"",[],{}):
                    text=self.evidence_text_v32362(value[k])
                    if text:
                        parts.append(f"{k}: {text}")
            if parts:
                return " • ".join(parts)
            return " • ".join(
                f"{k}: {self.evidence_text_v32362(v)}"
                for k,v in list(value.items())[:12]
                if v not in (None,"",[],{})
            )
        return str(value)

    def run_fast_pipeline_v19(self, url):
        started=time.perf_counter(); host=(urlparse(url).hostname or "").lower(); out=[]
        def local_ioc():
            try: return THREAT_INTEL_STORE.lookup_url_domain_ip(url,host,[])
            except Exception: return []
        def graph():
            try: return THREAT_INTEL_STORE.graph_neighborhood("domain",host,30) if host else {}
            except Exception: return {}
        with ThreadPoolExecutor(max_workers=4) as ex:
            jobs={ex.submit(local_ioc):"local_ioc",ex.submit(graph):"threat_graph"}
            for f in as_completed(jobs):
                try: out.append({"name":jobs[f],"state":"observed","value":f.result()})
                except Exception as e: out.append({"name":jobs[f],"state":"error","error":str(e)[:240]})
        self.results["fast_pipeline_v19"]={"elapsed_ms":round((time.perf_counter()-started)*1000),"sensors":out}

    def should_deep_scan_v19(self):
        h=self.results.get("http",{}) or {}
        if h.get("status") in (401,403,429) or not h.get("body_analyzed"): return True
        return any(str(x.get("severity","")).lower() in ("medium","high","critical") for x in (self.results.get("findings",[]) or []))

    def build_coverage_v19(self):
        h=self.results.get("http",{}) or {}; b=self.results.get("browser",{}) or {}
        ti=self.results.get("threat_intelligence",{}) or {}; dns=self.results.get("dns",{}) or {}
        surfaces={
          "URL / DNS":"observed" if dns else "not_observed",
          "Statik içerik":"observed" if h.get("body_analyzed") else ("blocked" if h.get("status") in (401,403,429) else "not_observed"),
          "Browser davranışı":"observed" if b.get("success") else ("blocked" if b.get("blocked") else "not_observed"),
          "Runtime network":"observed" if b.get("success") else "not_observed",
          "Threat Intelligence":"observed" if ti.get("checked") else "not_observed",
          "Dosya analizi":"observed" if b.get("downloads") else "not_applicable"}
        pct=round(sum(v in ("observed","not_applicable") for v in surfaces.values())/len(surfaces)*100)
        self.results["coverage_v19"]={"quality":"Yüksek" if pct>=85 else "Orta" if pct>=60 else "Sınırlı",
          "observed_percent":pct,"surfaces":surfaces,
          "note":"Kapsam güvenlik olasılığı değildir; gerçekten gözlemlenen analiz yüzeylerini gösterir."}

    def build_identity_trust_v21(self):
        final=(self.results.get("browser",{}) or {}).get("final_url") or self.results.get("final_url") or self.results.get("analyzed_url") or ""
        host=(urlparse(final).hostname or "").lower(); root=registrable_domain_v21(host)
        ident=self.results.get("identity_semantic_v18",{}) or {}
        detected=[x for x in ident.get("detected_brands",[]) if x.get("brand")]
        official=[x for x in detected if x.get("official_domain")]
        score=0; evidence=[]
        if official:
            score+=65; evidence.append("Sayfa marka kimliği registrable domain ile eşleşiyor")
        if self.results.get("ssl_info",{}).get("valid"):
            score+=5; evidence.append("TLS hostname doğrulaması başarılı")
        self.results["identity_trust_v21"]={"host":host,"registrable_domain":root,
            "official_brand_matches":official,"score":min(score,100),
            "level":"Yüksek" if score>=70 else "Orta" if score>=40 else "Düşük",
            "evidence":evidence,"rule":"Kimlik güveni tehdit kanıtını azaltmaz veya silmez."}

    def _evidence_sensor_v26(self, finding):
        cat=str(finding.get("category","")).lower()
        title=str(finding.get("title","")).lower()
        if cat=="visual_impersonation": return "visual_similarity_v27"
        if cat in ("data_exfiltration","network_exfil"): return "network_behavior_v22"
        if cat in ("javascript","suspicious_script"): return "js_payload_v23"
        if cat in ("malware","threat_intel"): return "threat_intelligence"
        if cat in ("phishing","credential","credential_theft") and ("görsel" in title or "logo" in title): return "visual_impersonation_v24"
        if cat in ("phishing","credential","credential_theft"): return "identity_semantic_v18"
        if cat in ("domain_age","infrastructure"): return "trust_context_v21"
        if "redirect" in cat or "yönlend" in title: return "redirect_behavior"
        return "core_static"

    def _evidence_group_v26(self, sensor):
        # Sensors in the same modality are not independent votes.
        groups={
          "visual_similarity_v27":"visual_similarity",
          "network_behavior_v22":"runtime_network",
          "js_payload_v23":"script_content",
          "visual_impersonation_v24":"visual_dom",
          "identity_semantic_v18":"identity_content",
          "threat_intelligence":"external_ioc",
          "trust_context_v21":"infrastructure_context",
          "redirect_behavior":"runtime_navigation",
          "core_static":"static_content"
        }
        return groups.get(sensor,sensor)

    def apply_provenance_fusion_guard_v26(self):
        """Prevent duplicate modalities from masquerading as independent corroboration."""
        p=self.results.get("evidence_provenance_v26",{}) or {}
        groups=set(p.get("independent_groups") or [])
        fusion=(self.results.get("defender",{}) or {}).get("fusion",{}) or {}
        fusion["provenance_independent_groups"]=sorted(groups)
        fusion["provenance_independent_count"]=len(groups)
        # Never lower a hard verified IOC verdict. This guard only limits independence bonuses.
        old=int(fusion.get("independent_experts") or 0)
        fusion["independent_experts_raw"]=old
        fusion["independent_experts"]=min(old,len(groups)) if groups else 0
        self.results.setdefault("defender",{})["fusion"]=fusion

    def _hamming_hex_v27(self,a,b):
        try:
            if not a or not b or len(a)!=len(b): return None
            return sum(bin(int(x,16)^int(y,16)).count("1") for x,y in zip(a,b))
        except Exception: return None

    def calibration_metrics_v29(self, rows):
        tp=fp=tn=fn=0
        for r in rows:
            actual=bool(r.get("actual_malicious")); pred=bool(r.get("predicted_malicious"))
            if actual and pred: tp+=1
            elif not actual and pred: fp+=1
            elif not actual and not pred: tn+=1
            else: fn+=1
        precision=tp/(tp+fp) if tp+fp else 0.0
        recall=tp/(tp+fn) if tp+fn else 0.0
        f1=2*precision*recall/(precision+recall) if precision+recall else 0.0
        fpr=fp/(fp+tn) if fp+tn else 0.0
        fnr=fn/(fn+tp) if fn+tp else 0.0
        return {"total":len(rows),"tp":tp,"fp":fp,"tn":tn,"fn":fn,
                "precision":precision,"recall":recall,"f1":f1,
                "false_positive_rate":fpr,"false_negative_rate":fnr}

    def propose_calibration_v29(self, sensor_report):
        """Create shadow weights only. Production weights are not silently rewritten."""
        proposed={}
        for sensor,m in sensor_report.items():
            n=m.get("samples",0)
            if n<30: continue
            p=m.get("precision",0); r=m.get("recall",0)
            # Conservative bounded adjustment: FN matters more than FP, but neither can dominate.
            quality=.55*r+.45*p
            proposed[sensor]=round(max(.70,min(1.30,.70+.60*quality)),4)
        return proposed

    def evaluate_candidate_v29(self, baseline, candidate, min_cases=60):
        """Promotion gate: never trade recall away to gain prettier precision."""
        if baseline.get("total",0)<min_cases or candidate.get("total",0)<min_cases:
            return {"promote":False,"reason":f"En az {min_cases} doğrulanmış regresyon örneği gerekli"}
        if candidate["recall"]+1e-9 < baseline["recall"]:
            return {"promote":False,"reason":"Recall düştü; zararlı site kaçırma riski arttı"}
        if candidate["false_negative_rate"] > baseline["false_negative_rate"]+1e-9:
            return {"promote":False,"reason":"False-negative oranı arttı"}
        if candidate["f1"] < baseline["f1"]-0.01:
            return {"promote":False,"reason":"F1 anlamlı biçimde kötüleşti"}
        if candidate["false_positive_rate"] > baseline["false_positive_rate"]+0.02:
            return {"promote":False,"reason":"False-positive oranı fazla arttı"}
        improved=(candidate["recall"]>baseline["recall"] or
                  candidate["f1"]>=baseline["f1"]+.01 or
                  candidate["false_positive_rate"]<=baseline["false_positive_rate"]-.01)
        return {"promote":bool(improved),"reason":"Güvenlik metrikleri gerilemeden iyileşme var" if improved else "Anlamlı iyileşme yok"}

    def family_metrics_v30(self, rows):
        """Metrics per threat family. Clean rows participate in FPR for every declared family scope."""
        families=sorted(set(str(r.get("family") or "general").lower() for r in rows))
        out={}
        for fam in families:
            subset=[r for r in rows if str(r.get("family") or "general").lower()==fam]
            out[fam]=self.calibration_metrics_v29(subset)
        return out

    def family_thresholds_v30(self):
        # Missing malicious sites is more costly than nuisance warnings.
        return {
          "malware":{"min_recall":.995,"max_fnr":.005,"max_fpr":.08},
          "credential_theft":{"min_recall":.990,"max_fnr":.010,"max_fpr":.10},
          "phishing":{"min_recall":.985,"max_fnr":.015,"max_fpr":.12},
          "data_exfiltration":{"min_recall":.990,"max_fnr":.010,"max_fpr":.10},
          "visual_impersonation":{"min_recall":.970,"max_fnr":.030,"max_fpr":.15},
          "general":{"min_recall":.980,"max_fnr":.020,"max_fpr":.12},
        }

    def detect_concept_drift_v30(self, baseline_rows, current_rows):
        """Compare time windows. Drift is an alert/rollback signal, not permission to auto-train."""
        base=self.family_metrics_v30(baseline_rows); cur=self.family_metrics_v30(current_rows)
        events=[]
        for fam in sorted(set(base)&set(cur)):
            b,c=base[fam],cur[fam]
            recall_drop=b.get("recall",0)-c.get("recall",0)
            fpr_rise=c.get("false_positive_rate",0)-b.get("false_positive_rate",0)
            if recall_drop>=.03 or fpr_rise>=.05:
                sev="critical" if recall_drop>=.05 else "high"
                events.append({"family":fam,"severity":sev,"recall_drop":round(recall_drop,4),
                               "fpr_rise":round(fpr_rise,4),
                               "action":"rollback_candidate" if recall_drop>=.03 else "investigate"})
        return {"drift_detected":bool(events),"events":events}

    def create_model_snapshot_v30(self, weights, global_metrics, family_metrics, parent=None, status="shadow",
                                  dataset_fingerprint=None, reason=""):
        now=datetime.now(timezone.utc).isoformat()
        body={"created_at":now,"parent":parent,"status":status,"version":APP_VERSION,
              "weights":weights,"global_metrics":global_metrics,"family_metrics":family_metrics,
              "dataset_fingerprint":dataset_fingerprint,"reason":reason}
        immutable_hash=hashlib.sha256(json.dumps(body,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
        model_id="mdl_"+immutable_hash[:20]
        with db_connect(DB_PATH, timeout=12) as con:
            con.execute("""INSERT OR IGNORE INTO model_snapshots_v30
              (model_id,created_at,parent_model_id,status,version,weights,global_metrics,family_metrics,
               dataset_fingerprint,reason,immutable_hash)
              VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
              (model_id,now,parent,status,APP_VERSION,json.dumps(weights,sort_keys=True),
               json.dumps(global_metrics,sort_keys=True),json.dumps(family_metrics,sort_keys=True),
               dataset_fingerprint,reason[:1000],immutable_hash))
        return {"model_id":model_id,"immutable_hash":immutable_hash,"status":status}

    def active_model_v30(self):
        try:
            with db_connect(DB_PATH, timeout=8) as con:
                row=con.execute("""SELECT model_id,weights,global_metrics,family_metrics,immutable_hash,created_at
                                   FROM model_snapshots_v30 WHERE status='active'
                                   ORDER BY created_at DESC LIMIT 1""").fetchone()
            if row:
                return {"model_id":row[0],"weights":json.loads(row[1]),"global_metrics":json.loads(row[2]),
                        "family_metrics":json.loads(row[3]),"immutable_hash":row[4],"created_at":row[5]}
        except Exception: pass
        return None

    def promote_model_v30(self, model_id, reason):
        """Promotion is explicit/admin-gated. It never changes hard safety rules."""
        now=datetime.now(timezone.utc).isoformat()
        with db_connect(DB_PATH, timeout=12) as con:
            row=con.execute("SELECT model_id FROM model_snapshots_v30 WHERE model_id=? AND status='shadow'",(model_id,)).fetchone()
            if not row: return {"ok":False,"error":"Shadow model bulunamadı"}
            old=con.execute("SELECT model_id FROM model_snapshots_v30 WHERE status='active' ORDER BY created_at DESC LIMIT 1").fetchone()
            if old: con.execute("UPDATE model_snapshots_v30 SET status='retired' WHERE model_id=?",(old[0],))
            con.execute("UPDATE model_snapshots_v30 SET status='active',reason=? WHERE model_id=?",(reason[:1000],model_id))
        return {"ok":True,"active_model":model_id,"previous_model":old[0] if old else None,"promoted_at":now}

    def rollback_model_v30(self, reason, automatic=False):
        now=datetime.now(timezone.utc).isoformat()
        with db_connect(DB_PATH, timeout=12) as con:
            cur=con.execute("SELECT model_id,parent_model_id FROM model_snapshots_v30 WHERE status='active' ORDER BY created_at DESC LIMIT 1").fetchone()
            if not cur or not cur[1]: return {"ok":False,"error":"Rollback hedefi yok"}
            parent=con.execute("SELECT model_id FROM model_snapshots_v30 WHERE model_id=?",(cur[1],)).fetchone()
            if not parent: return {"ok":False,"error":"Parent snapshot bulunamadı"}
            con.execute("UPDATE model_snapshots_v30 SET status='rolled_back' WHERE model_id=?",(cur[0],))
            con.execute("UPDATE model_snapshots_v30 SET status='active' WHERE model_id=?",(parent[0],))
            con.execute("""INSERT INTO rollback_audit_v30(created_at,from_model,to_model,reason,automatic)
                           VALUES(?,?,?,?,?)""",(now,cur[0],parent[0],reason[:1000],1 if automatic else 0))
        return {"ok":True,"from":cur[0],"to":parent[0],"automatic":automatic}

    def build_self_evolution_guard_v30(self):
        active=self.active_model_v30()
        self.results["self_evolution_guard_v30"]={
          "active_model":active,
          "family_thresholds":self.family_thresholds_v30(),
          "mode":"shadow → verified regression → family guard → explicit promotion → monitored rollback",
          "automatic_learning_limit":"Motor yeni ağırlık önerebilir; hard safety kurallarını veya allowlist'i kendi başına değiştiremez.",
          "rollback_ready":bool(active and active.get("model_id")),
          "adversarial":self.adversarial_regression_v30()
        }

    def normalize_discovery_url_v301(self, url):
        try:
            u=self.normalize_url(str(url or "").strip())
            p=urlparse(u)
            if p.scheme not in ("http","https") or not p.hostname: return None
            return u
        except Exception: return None

    def enqueue_discovery_v301(self, url, source="manual", source_ref=None, priority=50):
        u=self.normalize_discovery_url_v301(url)
        if not u: return {"ok":False,"error":"Geçersiz URL"}
        # Reuse existing route/private-network protections before a queued URL is ever scanned.
        h=hashlib.sha256(u.encode()).hexdigest()
        item_id="dq_"+hashlib.sha256((source+"|"+u).encode()).hexdigest()[:20]
        now=datetime.now(timezone.utc).isoformat()
        try:
            with db_connect(DB_PATH, timeout=10) as con:
                con.execute("""INSERT OR IGNORE INTO discovery_queue_v301
                    (item_id,url,url_hash,source,source_ref,priority,status,discovered_at,attempts)
                    VALUES(?,?,?,?,?,?,?, ?,0)""",
                    (item_id,u,h,str(source)[:80],str(source_ref or "")[:500],
                     max(0,min(100,int(priority))),"queued",now))
            return {"ok":True,"item_id":item_id,"url_hash":h}
        except Exception as exc: return {"ok":False,"error":str(exc)[:300]}

    def verify_observation_v301(self, observation_id, label, family, verifier, source, confidence, notes=""):
        if label not in ("malicious","clean"): return {"ok":False,"error":"label malicious veya clean olmalı"}
        confidence=max(0.0,min(1.0,float(confidence)))
        if confidence<.90: return {"ok":False,"error":"Ground truth için confidence >= 0.90 gerekli"}
        with db_connect(DB_PATH, timeout=10) as con:
            obs=con.execute("SELECT observation_id FROM live_observations_v301 WHERE observation_id=?",(observation_id,)).fetchone()
            if not obs: return {"ok":False,"error":"Observation bulunamadı"}
            tid="gt_"+uuid.uuid4().hex[:20]; now=datetime.now(timezone.utc).isoformat()
            con.execute("""INSERT INTO verified_ground_truth_v301
              (truth_id,observation_id,verified_at,label,family,verifier,source,confidence,notes)
              VALUES(?,?,?,?,?,?,?,?,?)""",(tid,observation_id,now,label,str(family or "general").lower(),
              str(verifier)[:120],str(source)[:200],confidence,str(notes)[:1500]))
            con.execute("UPDATE live_observations_v301 SET ground_truth_status='verified' WHERE observation_id=?",(observation_id,))
        return {"ok":True,"truth_id":tid,"observation_id":observation_id}

    def discovery_status_v301(self):
        try:
            with db_connect(DB_PATH, timeout=8) as con:
                q=dict(con.execute("SELECT status,COUNT(*) FROM discovery_queue_v301 GROUP BY status").fetchall())
                cand=con.execute("SELECT COUNT(*) FROM live_observations_v301 WHERE ground_truth_status='candidate'").fetchone()[0]
                ver=con.execute("SELECT COUNT(*) FROM live_observations_v301 WHERE ground_truth_status='verified'").fetchone()[0]
            return {"queue":q,"candidate_observations":cand,"verified_observations":ver}
        except Exception as exc: return {"error":str(exc)[:300]}

    def persistence_status_v31(self):
        backend=db_backend_name()
        return {
          "backend":backend,
          "database_url_configured":bool(os.getenv("DATABASE_URL","").strip()),
          "durable":backend=="postgresql",
          "sqlite_path":DB_PATH if backend=="sqlite" else None,
          "migration_scope":"V31.1 routes scanner, threat intelligence, evidence, graph, learning, calibration, discovery and model state through the shared PostgreSQL adapter.",
          "durability_warning":None if backend=="postgresql" else "SQLite geliştirme fallback'ıdır; production öğrenme belleği için DATABASE_URL ile PostgreSQL kullanın."
        }

    def register_discovery_source_v31(self, name, source_type, trust_level="contextual", config=None):
        allowed={"url_feed","ioc_feed","analyst","user_submission","internal_graph"}
        if source_type not in allowed: return {"ok":False,"error":"Desteklenmeyen source_type"}
        sid="src_"+hashlib.sha256((name+"|"+source_type).encode()).hexdigest()[:18]
        now=datetime.now(timezone.utc).isoformat()
        with db_connect(DB_PATH, timeout=10) as con:
            con.execute("""INSERT INTO discovery_sources_v31(source_id,name,source_type,enabled,trust_level,config,last_sync)
              VALUES(?,?,?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET name=excluded.name,
              source_type=excluded.source_type,trust_level=excluded.trust_level,config=excluded.config""",
              (sid,str(name)[:120],source_type,1,str(trust_level)[:40],json.dumps(config or {}),None))
        return {"ok":True,"source_id":sid,"registered_at":now}

    def ingest_discovery_urls_v31(self, source_id, urls):
        """Ingest indicators only. A feed hit is not ground truth and not a malicious verdict."""
        with db_connect(DB_PATH, timeout=10) as con:
            src=con.execute("SELECT name,enabled,trust_level FROM discovery_sources_v31 WHERE source_id=?",(source_id,)).fetchone()
        if not src or not src[1]: return {"ok":False,"error":"Kaynak bulunamadı veya kapalı"}
        accepted=0; rejected=0
        for raw in list(urls or [])[:5000]:
            r=self.enqueue_discovery_v301(str(raw),source=f"v31:{source_id}",source_ref=src[0],priority=65)
            accepted += int(bool(r.get("ok"))); rejected += int(not r.get("ok"))
        with db_connect(DB_PATH, timeout=10) as con:
            con.execute("UPDATE discovery_sources_v31 SET last_sync=?,last_error=NULL WHERE source_id=?",
                        (datetime.now(timezone.utc).isoformat(),source_id))
        return {"ok":True,"accepted":accepted,"rejected":rejected,
                "policy":"Kaynak girdisi yalnızca discovery candidate üretir; ground truth üretmez."}

    def build_v31_status(self):
        self.results["v31"]={
          "persistence":self.persistence_status_v31(),
          "discovery":self.discovery_status_v301(),
          "feed_sync":self.feed_sync_status_v312(),
          "campaign_detection":{"engine":"V31.3","mode":"bounded persisted-graph clustering",
                                "shared_infrastructure_alone":"never sufficient"},
          "policy":"Discovery source / graph relation / campaign candidate / model prediction ground truth değildir.",
          "autonomy_boundary":"Kendi kendine aday keşfedebilir ve tarayabilir; doğrulanmamış sonucu training label veya allowlist yapamaz."
        }

    def feed_sync_status_v312(self):
        try:
            with db_connect(DB_PATH,timeout=8) as con:
                sources=con.execute("""SELECT s.source_id,s.name,s.source_type,s.enabled,s.trust_level,
                    s.last_sync,s.last_error,st.next_sync_at,st.consecutive_failures,st.backoff_seconds
                    FROM discovery_sources_v31 s LEFT JOIN feed_sync_state_v312 st ON st.source_id=s.source_id
                    ORDER BY s.name""").fetchall()
            return {"sources":[{"source_id":r[0],"name":r[1],"type":r[2],"enabled":bool(r[3]),
              "trust_level":r[4],"last_sync":r[5],"last_error":r[6],"next_sync_at":r[7],
              "consecutive_failures":r[8] or 0,"backoff_seconds":r[9] or 0} for r in sources]}
        except Exception as exc: return {"error":str(exc)[:300]}

    def sync_due_feeds_v312(self, limit=8):
        now=datetime.now(timezone.utc).isoformat()
        with db_connect(DB_PATH,timeout=10) as con:
            rows=con.execute("""SELECT s.source_id FROM discovery_sources_v31 s
              LEFT JOIN feed_sync_state_v312 st ON st.source_id=s.source_id
              WHERE s.enabled=1 AND s.source_type IN ('url_feed','ioc_feed')
                AND (st.next_sync_at IS NULL OR st.next_sync_at<=?)
              ORDER BY COALESCE(st.next_sync_at,'') ASC LIMIT ?""",(now,max(1,min(32,int(limit))))).fetchall()
        return [self.sync_discovery_source_v312(r[0]) for r in rows]

    def _campaign_relation_group_v313(self, relation):
        r=str(relation or "").lower()
        if "resolve" in r or "ip" in r: return "infrastructure"
        if "redirect" in r or "navigat" in r: return "redirect"
        if "runtime" in r or "connect" in r or "write" in r: return "runtime_network"
        if "download" in r or "hash" in r or "classif" in r: return "payload"
        if "brand" in r or "visual" in r: return "identity_visual"
        return "graph_context"

    def _campaign_edges_v313(self, seed_type, seed_value, limit=250):
        """Read already-observed graph relations only. This detector does not probe hosts."""
        edges=[]
        try:
            raw=THREAT_INTEL_STORE.graph_neighborhood(seed_type,seed_value,limit=max(20,min(500,int(limit)))) or []
        except Exception:
            raw=[]
        if isinstance(raw,dict):
            raw=raw.get("edges") or []
        for e in raw:
            if not isinstance(e,dict): continue
            ft=str(e.get("from_type") or e.get("src_type") or seed_type)
            fv=str(e.get("from_value") or e.get("src_value") or seed_value)
            tt=str(e.get("to_type") or e.get("dst_type") or "")
            tv=str(e.get("to_value") or e.get("dst_value") or "")
            rel=str(e.get("relation") or "related")
            try: conf=float(e.get("confidence") or 0)
            except Exception: conf=0
            if conf>1: conf/=100.0
            conf=max(0.0,min(1.0,conf))
            if tt and tv:
                edges.append({"from_type":ft,"from_value":fv,"to_type":tt,"to_value":tv,
                              "relation":rel,"confidence":conf,
                              "group":self._campaign_relation_group_v313(rel),
                              "source":str(e.get("source") or "threat_graph")})
        return edges

    def campaign_status_v313(self, limit=50):
        with db_connect(DB_PATH,timeout=10) as con:
            rows=con.execute("""SELECT campaign_id,updated_at,status,confidence,threat_families,node_count,
              edge_count,independent_signal_groups,summary FROM threat_campaigns_v313
              ORDER BY confidence DESC,updated_at DESC LIMIT ?""",(max(1,min(200,int(limit))),)).fetchall()
        return {"campaigns":[{"campaign_id":r[0],"updated_at":r[1],"status":r[2],"confidence":r[3],
          "threat_families":json.loads(r[4] or "[]"),"nodes":r[5],"edges":r[6],
          "independent_groups":r[7],"summary":r[8]} for r in rows]}

    def auto_campaign_from_observation_v313(self, observation_id):
        with db_connect(DB_PATH,timeout=8) as con:
            row=con.execute("SELECT registrable_domain,predicted_score FROM live_observations_v301 WHERE observation_id=?",
                            (observation_id,)).fetchone()
        if not row or not row[0]: return {"ok":False,"error":"Seed observation/domain yok"}
        # Avoid cluster churn for low-signal observations.
        if float(row[1] or 0)<30: return {"ok":True,"campaign":None,"reason":"Düşük sinyal; cluster tetiklenmedi."}
        return self.detect_campaign_v313("domain",row[0])

    def _v321_text(self,obj):
        try: return json.dumps(obj,ensure_ascii=False,default=str).lower()
        except Exception: return str(obj).lower()

    def _v321_is_hard_evidence(self, finding):
        """Compatibility delegate to canonical guard policy."""
        text=self._v322_blob(finding) if hasattr(self,"_v322_blob") else str(finding).lower()
        return is_hard_evidence_text(text)

    def claimed_brand_mismatch(self):
        """Strong page identity plus a recorded brand/domain mismatch."""
        ident=self.results.get("identity_semantic_v18") or {}
        mismatches=list(ident.get("brand_mismatches") or [])
        if not mismatches:
            for row in ident.get("detected_brands") or []:
                if not isinstance(row,dict): continue
                brand=str(row.get("brand") or row.get("name") or "").strip().lower()
                if brand and bool(row.get("mismatch") or row.get("domain_mismatch") or row.get("official_domain") is False):
                    mismatches.append({"brand":brand})
        if not mismatches: return False
        browser=self.results.get("browser") or {}; sem=self.results.get("static_semantic_v3232") or {}; ids=sem.get("identity_surfaces") or {}
        strong=self._v322_blob({"title":browser.get("title") or sem.get("title"),"h1":browser.get("h1") or " ".join(map(str,(sem.get("headings") or [])[:3])),"og_title":browser.get("og_title") or ids.get("og_title"),"app_name":ids.get("app_name"),"header_text":ids.get("header_text"),"logo_text":ids.get("logo_text")}).lower()
        return any(str(m.get("brand") or "").strip().lower() in strong for m in mismatches if isinstance(m,dict) and str(m.get("brand") or "").strip())

    def _v3222_is_claimed_brand(self):
        return self.claimed_brand_mismatch()

    def _v3224_explicit_causal_sink(self, finding):
        text=self._v322_blob(finding)
        generic=("storage/cookie + network + obfuscation" in text or
                 "input events + network + obfuscation" in text or
                 "token/cookie veri sızdırma korelasyonu" in text or
                 "girdi yakalama ve aktarım korelasyonu" in text)
        sink_terms=("cross-origin","cross origin","external destination","harici hedef",
                    "form action","sendbeacon","websocket","xhr post","fetch post",
                    "post destination","exfil destination","destination_host","sink_host")
        return bool(any(x in text for x in sink_terms) and not generic)

    def _v3224_verified_brand_sensitive_chain(self, finding):
        text=self._v322_blob(finding)
        if not ("marka taklidi" in text or "brand" in text or "domain uyuşmaz" in text):
            return True
        if not self._v3222_is_claimed_brand():
            return False
        return any(x in text for x in ("password","parola","otp","cvv","cvc","card","kart",
                                       "iban","login","giriş","credential","kimlik bilg"))

    def _v322_blob(self,obj):
        try: return json.dumps(obj,ensure_ascii=False,default=str).lower()
        except Exception: return str(obj).lower()

    def _v322_sensitive_external_causal_chain(self):
        """Require a sensitive source AND a distinct external sink for credential-exfil claims."""
        blob=self._v322_blob({
            "browser":self.results.get("browser") or {},
            "forms":self.results.get("forms") or {},
            "network":self.results.get("network_behavior_v22") or {},
            "behavior":self.results.get("behavioral_fusion_v17") or {}
        })
        sensitive=any(x in blob for x in (
            '"type":"password"','"type": "password"',"password","passwd","otp",
            "verification code","cvv","cvc","card number","iban","pin input"))
        external=any(x in blob for x in (
            "cross-origin","cross_origin","cross-site","cross_site",
            "external_sink","external sink","foreign form action","third-party submit"))
        write=any(x in blob for x in ("post","sendbeacon","fetch","xmlhttprequest","form_action","form action"))
        return bool(sensitive and external and write)

    def _v323_add(self,title,severity,description,category,evidence,confidence,expert):
        self.add_finding(title,severity,description,category,evidence,confidence)
        f=self.results["findings"][-1]
        f["source_expert"]=expert
        f["producer"]="independent_phishing_v323"
        f["feed_independent"]=True
        return f

    def canonical_fusion_floor_v3235(self):
        """Prevent corroborated bridge evidence from collapsing in a stale score path."""
        bridge=self.results.get("fusion_brain_v3235") or {}
        if not bridge.get("promoted"): return {"applied":False,"reason":"no_corroborated_bridge"}
        floor=int(bridge.get("score") or 0)
        if floor<45: return {"applied":False,"reason":"below_bridge_floor"}
        cats=self.results.get("canonical_category_scores_v3222") or {}
        target="credential" if "credential_theft" in (bridge.get("expert_groups") or []) else "phishing"
        old=int(cats.get(target,0) or 0)
        cats[target]=max(old,floor)
        self.results["canonical_category_scores_v3222"]=cats
        for key in ("category_scores","threat_categories"):
            obj=self.results.get(key)
            if isinstance(obj,dict): obj[target]=max(int(obj.get(target,0) or 0),floor)
        out={"applied":True,"category":target,"old":old,"floor":floor,"new":max(old,floor)}
        self.results["canonical_fusion_floor_v3235"]=out
        return out

    def serialize_evidence_for_ui_v3235(self):
        """Normalize nested diagnostic evidence for the UI."""
        def clean(v,depth=0):
            if depth>4: return str(v)[:1000]
            if isinstance(v,dict): return {str(k):clean(val,depth+1) for k,val in list(v.items())[:60]}
            if isinstance(v,list): return [clean(x,depth+1) for x in v[:60]]
            if isinstance(v,(str,int,float,bool)) or v is None: return v
            return str(v)
        bridge=self.results.get("fusion_brain_v3235")
        if isinstance(bridge,dict): bridge["evidence"]=clean(bridge.get("evidence") or [])
        for f in self.results.get("findings") or []:
            if isinstance(f.get("metadata"),dict): f["metadata"]=clean(f["metadata"])
        return {"ok":True}

    def publish_dual_intelligence_v32320(self):
        """Expose Web Defender engine and external intelligence as separate channels."""
        enabled=bool(self.results.get("_feed_off_v3231"))
        feed_findings=[]
        for f in self.results.get("findings") or []:
            if f.get("external_intelligence_v32320"):
                feed_findings.append({k:f.get(k) for k in ("title","severity","description","category","evidence","confidence","external_intelligence_source_v32320")})
        ti=self.results.get("threat_intelligence") or {}
        matches=ti.get("matches") or []
        sources=[]
        for x in matches:
            src=str(x.get("source") or "")
            if src and src not in sources: sources.append(src)
        engine_score=(self.results.get("scores") or {}).get("threat")
        if engine_score is None: engine_score=(self.results.get("canonical_scoring_v3222") or {}).get("threat_score")
        ext_score=0
        for f in feed_findings:
            sev=str(f.get("severity") or "").lower()
            ext_score=max(ext_score,{"critical":100,"high":75,"medium":45,"low":20}.get(sev,0))
        if matches: ext_score=max(ext_score,100 if any(str(x.get("source") or "").lower() in ("openphish","phishtank","urlhaus","threatfox") for x in matches) else 70)
        self.results["decision_channels_v32320"]={
            "mode":"FEED_OFF_TEST" if enabled else "COMBINED_PRODUCTION",
            "web_defender_engine":{"score":engine_score,"decision_authority":True if enabled else True,
                "feed_independent_in_test":enabled,"label":"Web Defender Motoru"},
            "external_intelligence":{"score":ext_score,"match":bool(feed_findings or matches),
                "sources":sources,"findings":feed_findings[:20],"decision_authority":False if enabled else True,
                "label":"Harici İstihbarat"},
            "invariant":"Feed OFF: external intelligence may be displayed but can never alter engine score, category score, fusion or final verdict."
        }
        return self.results["decision_channels_v32320"]

    def _v3241_surface_snapshot(self):
        b=self.results.get("browser") or {}; st=self.results.get("static_source_intelligence_v32317") or {}
        state=b.get("stateful_surface") or {}; snaps=state.get("snapshots") or []
        title=str((snaps[-1].get("title") if snaps else "") or (self.results.get("http") or {}).get("title") or "")[:300]
        html=str(b.get("html") or "")
        if not html:
            h=self.results.get("http") or {}; html=str(h.get("html") or h.get("content") or h.get("body") or "")
        low=(title+" "+str((snaps[-1].get("text_sample") if snaps else "") or "")).lower()
        credential=bool(st.get("credential_source") or any((x.get("inputs") or 0)>0 and x.get("auth_intent") for x in snaps if isinstance(x,dict)))
        maintenance=bool(re.search(r"maintenance|under construction|temporarily unavailable|parked domain|bakım|yapım aşamasında",low,re.I))
        challenge=bool((self.results.get("target_access_v32313") or {}).get("restricted") or (self.results.get("http") or {}).get("status_code") in (401,403,429))
        surface="credential" if credential else ("maintenance" if maintenance else ("challenge" if challenge else ("ordinary" if html or snaps else "unobserved")))
        return {"title":title,"dom_sha256":hashlib.sha256(html.encode("utf-8","ignore")).hexdigest() if html else "","surface_class":surface,"credential_surface":credential}

    def analyze_temporal_history(self):
        rep=self.temporal_threat_memory_v3241(); self.results["temporal_history"]=rep; return rep

    def persist_temporal_observation(self):
        rep=self.persist_temporal_observation_v3241(); self.results["temporal_persist"]=rep; return rep

    def zero_day_status_v32(self, limit=50):
        with db_connect(DB_PATH,timeout=10) as con:
            rows=con.execute("""SELECT observation_id,created_at,registrable_domain,score,confidence,verdict,
              independent_groups,behavior_families,known_ioc FROM zero_day_observations_v32
              ORDER BY score DESC,created_at DESC LIMIT ?""",(max(1,min(200,int(limit))),)).fetchall()
        return {"observations":[{"observation_id":r[0],"created_at":r[1],"domain":r[2],"score":r[3],
          "confidence":r[4],"verdict":r[5],"independent_groups":r[6],
          "families":json.loads(r[7] or "[]"),"known_ioc":bool(r[8])} for r in rows]}

    @staticmethod
    def _leet_skeleton_v32313(value):
        """Conservative hostname skeleton for brand-typo comparison only."""
        trans = str.maketrans({"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t"})
        return re.sub(r"[^a-z0-9]", "", str(value or "").lower()).translate(trans)

