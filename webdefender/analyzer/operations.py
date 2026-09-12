import signal
import tempfile
import subprocess
import sys
"""Discovery, learning, campaign and calibration mixin.

These subsystems evolve observations and regression knowledge. They do not own
the final verdict and must never promote the engine's own prediction to ground truth.
"""
from ..state import DB_PATH
from ..analyzer.url_domain import registrable_domain_v21
import requests
from ..metadata import APP_VERSION
import csv
import os, re, json, time, hashlib, math, uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

from ..database import db_connect
from ..state import LEARNING_ENGINE, THREAT_INTEL_STORE
from .url_domain import get_root_domain, get_canonical_root

class OperationalLearningMixin:
    def update_threat_graph_v25(self):
        final=(self.results.get("browser",{}) or {}).get("final_url") or self.results.get("final_url") or ""
        root=registrable_domain_v21(urlparse(final).hostname or "")
        if final and root: THREAT_INTEL_STORE.upsert_relation("url",final,"domain",root,"belongs_to","scan",.95)
        for ip in ((self.results.get("dns",{}) or {}).get("addresses") or [])[:12]:
            if root: THREAT_INTEL_STORE.upsert_relation("domain",root,"ip",ip,"resolves_to","dns",.8)
        for e in (self.results.get("network_behavior_v22",{}) or {}).get("events",[])[:150]:
            rr=e.get("root")
            if root and rr and rr!=root:
                THREAT_INTEL_STORE.upsert_relation("domain",root,"domain",rr,
                    "runtime_write_to" if e.get("has_body") else "runtime_connects_to","browser",.9 if e.get("has_body") else .65,{"kind":e.get("kind"),"url":e.get("url")})
        for dl in ((self.results.get("browser",{}) or {}).get("downloads") or [])[:30]:
            sh=str(dl.get("sha256") or "").lower()
            if root and re.fullmatch(r"[0-9a-f]{64}",sh):
                THREAT_INTEL_STORE.upsert_relation("domain",root,"sha256",sh,"downloaded_hash","browser",.98,{"filename":dl.get("suggested_filename"),"size":dl.get("size")})
                for hit in THREAT_INTEL_STORE.lookup_hash(sh)[:20]:
                    fam=hit.get("malware_family")
                    if fam: THREAT_INTEL_STORE.upsert_relation("sha256",sh,"malware_family",fam,"classified_as",hit.get("source") or "intel",.98)
        self.results["threat_graph_v25"]={"root":root,"neighborhood":THREAT_INTEL_STORE.graph_neighborhood("domain",root,80) if root else {}}

    def build_active_learning_v26(self):
        """Read learned sensor reliability. It is advisory until enough verified feedback exists."""
        rows=[]
        try:
            with db_connect(DB_PATH, timeout=8) as con:
                rows=con.execute("SELECT sensor,tp,fp,tn,fn,weight,updated_at FROM sensor_learning").fetchall()
        except Exception: pass
        sensors={}
        for sensor,tp,fp,tn,fn,w,updated in rows:
            n=tp+fp+tn+fn
            precision=tp/(tp+fp) if tp+fp else None
            recall=tp/(tp+fn) if tp+fn else None
            sensors[sensor]={"samples":n,"tp":tp,"fp":fp,"tn":tn,"fn":fn,"weight":w,
                             "precision":precision,"recall":recall,"updated_at":updated,
                             "active_for_scoring":n>=30}
        self.results["active_learning_v26"]={
          "sensors":sensors,
          "policy":"Öğrenilmiş ağırlıklar 30 doğrulanmış örnekten önce tehdit skoruna uygulanmaz.",
          "feedback_labels":["malicious","clean","false_positive","false_negative"]
        }

    def _layout_fingerprint_v27(self):
        b=self.results.get("browser",{}) or {}; sem=b.get("semantic_dom") or {}
        forms=b.get("forms") or []; inputs=sem.get("inputs") or []
        features={
          "headings":min(len(sem.get("headings") or []),20),
          "buttons":min(len(sem.get("buttons") or []),30),
          "inputs":min(len(inputs),40),
          "passwords":sum(1 for i in inputs if str(i.get("type","")).lower()=="password"),
          "forms":min(len(forms),20),
          "iframes":min(len(b.get("frames") or []),20),
          "has_otp":int(any(f.get("has_otp") for f in forms)),
          "has_card":int(any(f.get("has_card") for f in forms)),
          "has_password_form":int(any(f.get("has_password") for f in forms)),
        }
        # Bucket counts to make the fingerprint robust to small UI changes.
        bucket={k:(min(5,int(v)//2) if k in ("headings","buttons","inputs","forms","iframes") else int(v))
                for k,v in features.items()}
        raw=json.dumps(bucket,sort_keys=True,separators=(",",":"))
        return {"features":features,"bucket":bucket,"hash":hashlib.sha256(raw.encode()).hexdigest()[:24]}

    def run_visual_similarity_v27(self):
        """Compare against locally verified official-site baselines. Similarity is evidence, never a verdict alone."""
        b=self.results.get("browser",{}) or {}; final=b.get("final_url") or self.results.get("final_url") or ""
        root=registrable_domain_v21(urlparse(final).hostname or "")
        ident=self.results.get("identity_semantic_v18",{}) or {}
        brands=[x.get("brand") for x in ident.get("detected_brands",[]) if x.get("brand")]
        layout=self._layout_fingerprint_v27()
        dhash=b.get("screenshot_dhash")
        comparisons=[]
        try:
            with db_connect(DB_PATH, timeout=8) as con:
                for brand in brands[:8]:
                    rows=con.execute("""SELECT domain,layout_fingerprint,screenshot_dhash,dom_tokens,verified_at,source
                                      FROM visual_baselines WHERE brand=? LIMIT 30""",(brand,)).fetchall()
                    for domain,lf,ph,tokens,verified_at,source in rows:
                        # Layout exact bucket match is useful but deliberately capped.
                        layout_sim=1.0 if lf==layout["hash"] else 0.0
                        dist=self._hamming_hex_v27(dhash,ph)
                        visual_sim=(1.0-dist/(len(dhash)*4)) if dist is not None else None
                        token_set=set(re.findall(r"[a-z0-9]{3,}",str((b.get("semantic_dom") or {}).get("visible_text","")).lower())[:400])
                        base_set=set(json.loads(tokens or "[]"))
                        dom_sim=(len(token_set & base_set)/max(1,len(token_set | base_set))) if token_set and base_set else 0.0
                        parts=[x for x in (visual_sim,dom_sim,layout_sim) if x is not None]
                        score=round(100*(.55*(visual_sim or 0)+.30*dom_sim+.15*layout_sim),1) if parts else 0
                        comparisons.append({"brand":brand,"baseline_domain":domain,"score":score,
                            "screenshot_similarity":round(100*visual_sim,1) if visual_sim is not None else None,
                            "dom_similarity":round(100*dom_sim,1),"layout_similarity":round(100*layout_sim,1),
                            "verified_at":verified_at,"source":source})
        except Exception as exc:
            self.results["visual_similarity_v27"]={"observed":False,"error":str(exc)[:300]}; return
        comparisons.sort(key=lambda x:x["score"],reverse=True)
        best=comparisons[0] if comparisons else None
        mismatch=bool(best and registrable_domain_v21(best["baseline_domain"])!=root)
        if best and best["score"]>=82 and mismatch:
            self.add_finding("Doğrulanmış marka arayüzüne yüksek görsel benzerlik","high",
                f"Sayfa, doğrulanmış {best['brand']} baseline'ına %{best['score']} benziyor fakat registrable domain farklı.",
                "visual_impersonation",json.dumps(best,ensure_ascii=False),.92)
        self.results["visual_similarity_v27"]={"observed":True,"layout":layout,"screenshot_dhash":dhash,
            "comparisons":comparisons[:12],"best":best,"domain_mismatch":mismatch,
            "policy":"Görsel benzerlik tek başına phishing hükmü değildir; baseline yalnızca doğrulanmış resmi domain taramalarından oluşturulur."}

    def sensor_error_report_v29(self, rows):
        sensors={}
        for r in rows:
            actual=bool(r.get("actual_malicious"))
            fired=set(r.get("sensors_fired") or [])
            all_sensors=set(r.get("all_sensors") or fired)
            for sensor in all_sensors:
                x=sensors.setdefault(sensor,{"tp":0,"fp":0,"tn":0,"fn":0})
                pred=sensor in fired
                if actual and pred:x["tp"]+=1
                elif not actual and pred:x["fp"]+=1
                elif not actual and not pred:x["tn"]+=1
                else:x["fn"]+=1
        for sensor,x in sensors.items():
            x["precision"]=x["tp"]/(x["tp"]+x["fp"]) if x["tp"]+x["fp"] else 0
            x["recall"]=x["tp"]/(x["tp"]+x["fn"]) if x["tp"]+x["fn"] else 0
            x["samples"]=sum(x[k] for k in ("tp","fp","tn","fn"))
        return sensors

    def build_calibration_snapshot_v29(self):
        """Expose current learning health without letting learning override hard safety rules."""
        rows=[]
        try:
            with db_connect(DB_PATH, timeout=8) as con:
                rows=con.execute("""SELECT sensor,tp,fp,tn,fn,weight,updated_at
                                    FROM sensor_learning ORDER BY sensor""").fetchall()
        except Exception: pass
        report={}
        for sensor,tp,fp,tn,fn,w,updated in rows:
            n=tp+fp+tn+fn
            report[sensor]={"samples":n,"tp":tp,"fp":fp,"tn":tn,"fn":fn,"weight":w,
                "precision":tp/(tp+fp) if tp+fp else None,
                "recall":tp/(tp+fn) if tp+fn else None,
                "eligible_for_shadow_calibration":n>=30,"updated_at":updated}
        self.results["calibration_v29"]={
          "sensor_health":report,
          "learning_mode":"shadow_then_promote",
          "promotion_guard":"Recall/FNR gerileyen aday model otomatik terfi edemez.",
          "hard_safety_override":"IOC/malware/exfiltration gibi kritik kanıtlar öğrenilmiş ağırlıklarla bastırılamaz."
        }

    def evaluate_family_guard_v30(self, baseline_rows, candidate_rows, min_family_cases=20):
        base=self.family_metrics_v30(baseline_rows); cand=self.family_metrics_v30(candidate_rows)
        thresholds=self.family_thresholds_v30(); failures=[]; report={}
        for fam in sorted(set(base)|set(cand)):
            b=base.get(fam,{}); c=cand.get(fam,{})
            t=thresholds.get(fam,thresholds["general"])
            malicious_cases=c.get("tp",0)+c.get("fn",0)
            total=c.get("total",0)
            reasons=[]
            if total<min_family_cases:
                reasons.append(f"yetersiz örnek ({total}<{min_family_cases})")
            if malicious_cases and c.get("recall",0)<t["min_recall"]:
                reasons.append(f"recall {c.get('recall',0):.4f} < {t['min_recall']:.4f}")
            if malicious_cases and c.get("false_negative_rate",0)>t["max_fnr"]:
                reasons.append(f"FNR {c.get('false_negative_rate',0):.4f} > {t['max_fnr']:.4f}")
            if c.get("false_positive_rate",0)>t["max_fpr"]:
                reasons.append(f"FPR {c.get('false_positive_rate',0):.4f} > {t['max_fpr']:.4f}")
            if b and c and malicious_cases and c.get("recall",0)+1e-9<b.get("recall",0):
                reasons.append("baseline'a göre recall geriledi")
            report[fam]={"baseline":b,"candidate":c,"thresholds":t,"pass":not reasons,"reasons":reasons}
            if reasons: failures.append({"family":fam,"reasons":reasons})
        return {"pass":not failures,"families":report,"failures":failures}

    def adversarial_regression_v30(self):
        """Safe synthetic invariants: evasion transformations, no live malicious execution."""
        cases=[
          {"name":"mixed_case_brand","input":"FaCeBoOk LOGIN","expect":"brand survives case mutation"},
          {"name":"unicode_spacing","input":"p a s s w o r d","expect":"obfuscation must not imply safe"},
          {"name":"redirect_encoding","input":"%252F%252Fcollector.example","expect":"multi-decode inspected"},
          {"name":"official_plus_hard_ioc","input":"official-domain + critical SHA256 IOC","expect":"hard threat wins trust"},
          {"name":"new_clean_domain","input":"2-day domain + benign content","expect":"age alone not malicious"},
          {"name":"duplicate_sensor","input":"same event HTTP+browser+fusion","expect":"one independent evidence group"},
        ]
        # These are guard assertions against architecture regressions, not claims of full adversarial coverage.
        checks={
          "trust_never_suppresses_hard_threat": "Trust/itibar/domain yaşı/Tranco/TLS güçlü tehdit kanıtını bastıramaz." in
              str((self.results.get("safety_gate_v21") or {}).get("invariant","")),
          "provenance_present": "evidence_provenance_v26" in self.results,
          "visual_not_standalone": "Görsel benzerlik tek başına phishing hükmü değildir" in
              str((self.results.get("visual_similarity_v27") or {}).get("policy","")),
        }
        return {"cases":cases,"architecture_checks":checks,"all_architecture_checks":all(checks.values())}

    def record_live_observation_v301(self, item_id=None):
        url=self.results.get("final_url") or self.results.get("analyzed_url") or ""
        uh=hashlib.sha256(str(url).encode()).hexdigest()
        domain=registrable_domain_v21(urlparse(str(url)).hostname or "")
        fusion=((self.results.get("defender") or {}).get("fusion") or {})
        score=float(self.results.get("risk_score") or fusion.get("score") or 0)
        verdict=str(self.results.get("risk_level") or "")
        predicted=1 if ("TEHLİKELİ" in verdict or score>=45) else 0
        findings=self.results.get("findings") or []
        sensors=sorted(set(str(f.get("sensor")) for f in findings if f.get("sensor")))
        evidence=sorted(set(str(f.get("evidence_id")) for f in findings if f.get("evidence_id")))
        families=sorted(set(str(f.get("category")) for f in findings if f.get("category")))
        quality=str((self.results.get("coverage_v19") or {}).get("quality") or "unknown")
        oid="obs_"+uuid.uuid4().hex[:20]; now=datetime.now(timezone.utc).isoformat()
        with db_connect(DB_PATH, timeout=10) as con:
            con.execute("""INSERT INTO live_observations_v301
              (observation_id,item_id,created_at,url_hash,registrable_domain,predicted_malicious,predicted_score,
               verdict,threat_families,sensors_fired,evidence_ids,observation_quality,scan_version,ground_truth_status)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (oid,item_id,now,uh,domain,predicted,score,verdict,json.dumps(families),
               json.dumps(sensors),json.dumps(evidence),quality,APP_VERSION,"candidate"))
        self.results["live_discovery_v301"]={"observation_id":oid,"ground_truth_status":"candidate",
          "rule":"Motor tahmini ground truth değildir; doğrulanana kadar yalnızca candidate olarak kalır."}
        return oid

    def continuous_regression_v301(self, limit=2000, window_name="verified-live"):
        rows=[]
        with db_connect(DB_PATH, timeout=12) as con:
            data=con.execute("""SELECT o.predicted_malicious,o.sensors_fired,g.label,g.family
                FROM verified_ground_truth_v301 g
                JOIN live_observations_v301 o ON o.observation_id=g.observation_id
                ORDER BY g.verified_at DESC LIMIT ?""",(max(1,min(10000,int(limit))),)).fetchall()
        all_sensors=set()
        parsed=[]
        for pred,sensors,label,family in data:
            ss=set(json.loads(sensors or "[]")); all_sensors|=ss
            parsed.append({"actual_malicious":label=="malicious","predicted_malicious":bool(pred),
                           "family":family or "general","sensors_fired":list(ss)})
        for r in parsed: r["all_sensors"]=sorted(all_sensors)
        metrics=self.calibration_metrics_v29(parsed)
        fam=self.family_metrics_v30(parsed)
        sr=self.sensor_error_report_v29(parsed)
        fp=hashlib.sha256(json.dumps(parsed,sort_keys=True).encode()).hexdigest()
        now=datetime.now(timezone.utc).isoformat()
        with db_connect(DB_PATH, timeout=10) as con:
            con.execute("""INSERT INTO continuous_regression_v301
              (created_at,window_name,total,metrics,family_metrics,sensor_report,dataset_fingerprint)
              VALUES(?,?,?,?,?,?,?)""",(now,str(window_name)[:100],len(parsed),json.dumps(metrics),
                json.dumps(fam),json.dumps(sr),fp))
        return {"metrics":metrics,"family_metrics":fam,"sensor_report":sr,"dataset_fingerprint":fp,
                "shadow_weight_proposal":self.propose_calibration_v29(sr),
                "training_policy":"Doğrulanmış ground truth kullanılır; candidate tahminler öğrenme etiketi değildir."}

    def expand_threat_hunt_v31(self, observation_id, max_depth=1):
        """Bounded graph expansion from already observed evidence. No internet-wide crawling or exploitation."""
        max_depth=max(1,min(2,int(max_depth)))
        with db_connect(DB_PATH, timeout=10) as con:
            obs=con.execute("""SELECT registrable_domain,evidence_ids,threat_families,predicted_score
                               FROM live_observations_v301 WHERE observation_id=?""",(observation_id,)).fetchone()
        if not obs: return {"ok":False,"error":"Observation bulunamadı"}
        domain,eids,families,score=obs
        candidates=[]
        # Reuse persisted graph neighborhood produced by prior scanners, not arbitrary network probing.
        try:
            neigh=THREAT_INTEL_STORE.graph_neighborhood("domain",domain,limit=80) if domain else []
        except Exception:
            neigh=[]
        for edge in neigh or []:
            if not isinstance(edge,dict): continue
            to_type=str(edge.get("to_type") or edge.get("dst_type") or "")
            to_value=str(edge.get("to_value") or edge.get("dst_value") or "")
            relation=str(edge.get("relation") or "related")
            conf=float(edge.get("confidence") or 0)/100.0 if float(edge.get("confidence") or 0)>1 else float(edge.get("confidence") or 0)
            if to_type not in ("domain","url","ip","sha256") or not to_value: continue
            # Only URL/domain candidates become active scan candidates; IP/hash stay correlation context.
            candidates.append({"type":to_type,"value":to_value,"relation":relation,
                               "confidence":max(0,min(1,conf)),"depth":1})
        now=datetime.now(timezone.utc).isoformat(); stored=0; queued=0
        with db_connect(DB_PATH, timeout=12) as con:
            for c in candidates[:100]:
                cid="hunt_"+hashlib.sha256((observation_id+"|"+c["type"]+"|"+c["value"]).encode()).hexdigest()[:20]
                con.execute("""INSERT OR IGNORE INTO hunt_candidates_v31
                  (candidate_id,created_at,seed_observation_id,indicator_type,indicator_value,relation,confidence,depth,status,reason)
                  VALUES(?,?,?,?,?,?,?,?,?,?)""",(cid,now,observation_id,c["type"],c["value"],c["relation"],
                    c["confidence"],c["depth"],"candidate","bounded persisted-graph expansion"))
                stored+=1
                if c["confidence"]>=.70 and c["type"] in ("url","domain"):
                    u=c["value"] if c["type"]=="url" else "https://"+c["value"]+"/"
                    q=self.enqueue_discovery_v301(u,source="v31:threat_graph",source_ref=observation_id,priority=70)
                    queued+=int(bool(q.get("ok")))
        return {"ok":True,"seed":observation_id,"stored_candidates":stored,"queued_for_scan":queued,
                "max_depth":max_depth,
                "safety":"Expansion yalnızca mevcut graph ilişkilerinden gelir; exploit, port taraması veya sınırsız crawling yapmaz."}

    def sync_discovery_source_v312(self, source_id):
        """Fetch a configured URL feed with bounded parsing, provenance, conditional GET and backoff."""
        from datetime import timedelta
        with db_connect(DB_PATH,timeout=10) as con:
            row=con.execute("""SELECT name,source_type,enabled,trust_level,config
                               FROM discovery_sources_v31 WHERE source_id=?""",(source_id,)).fetchone()
            st=con.execute("""SELECT etag,last_modified,next_sync_at,consecutive_failures
                              FROM feed_sync_state_v312 WHERE source_id=?""",(source_id,)).fetchone()
        if not row or not row[2]: return {"ok":False,"error":"Kaynak bulunamadı veya kapalı"}
        name,stype,enabled,trust,config_raw=row
        if stype not in ("url_feed","ioc_feed"): return {"ok":False,"error":"Bu kaynak otomatik feed değildir"}
        try: cfg=json.loads(config_raw or "{}") if isinstance(config_raw,str) else (config_raw or {})
        except Exception: cfg={}
        feed_url=str(cfg.get("url") or "").strip()
        if not feed_url.startswith("https://"): return {"ok":False,"error":"Feed URL HTTPS olmalı"}
        max_bytes=max(1024,min(8*1024*1024,int(cfg.get("max_bytes") or 2*1024*1024)))
        max_items=max(1,min(5000,int(cfg.get("max_items") or 2000)))
        timeout=max(3,min(30,int(cfg.get("timeout") or 12)))
        now=datetime.now(timezone.utc); run_id="fs_"+uuid.uuid4().hex[:20]
        with db_connect(DB_PATH,timeout=10) as con:
            con.execute("""INSERT INTO feed_sync_runs_v312(run_id,source_id,started_at,status)
                           VALUES(?,?,?,?)""",(run_id,source_id,now.isoformat(),"running"))
        headers={"User-Agent":"WebDefender-FeedSync/31.2","Accept":"text/plain,application/json,text/csv,*/*;q=0.2"}
        if st and st[0]: headers["If-None-Match"]=st[0]
        if st and st[1]: headers["If-Modified-Since"]=st[1]
        try:
            # Feed retrieval is data ingestion only; feed content is never executed.
            resp=requests.get(feed_url,headers=headers,timeout=timeout,stream=True,allow_redirects=False)
            if resp.status_code==304:
                with db_connect(DB_PATH,timeout=10) as con:
                    con.execute("""UPDATE feed_sync_runs_v312 SET finished_at=?,status='not_modified',http_status=304
                                   WHERE run_id=?""",(datetime.now(timezone.utc).isoformat(),run_id))
                    con.execute("""INSERT INTO feed_sync_state_v312(source_id,etag,last_modified,next_sync_at,
                      consecutive_failures,backoff_seconds,last_success_at,last_error)
                      VALUES(?,?,?,?,0,0,?,NULL)
                      ON CONFLICT(source_id) DO UPDATE SET next_sync_at=excluded.next_sync_at,
                      consecutive_failures=0,backoff_seconds=0,last_success_at=excluded.last_success_at,last_error=NULL""",
                      (source_id,st[0] if st else None,st[1] if st else None,(now+timedelta(minutes=30)).isoformat(),now.isoformat()))
                return {"ok":True,"status":"not_modified","run_id":run_id}
            if resp.status_code!=200:
                _loc=str(resp.headers.get("Location") or "")
                if 300 <= resp.status_code < 400 and _loc:
                    try:
                        _lp=urlparse(urljoin(feed_url,_loc))
                        _safe_loc=f"{_lp.scheme}://{_lp.netloc}{_lp.path}"[:240]
                    except Exception:
                        _safe_loc="[unparseable]"
                    raise RuntimeError("HTTP "+str(resp.status_code)+" redirect="+_safe_loc)
                raise RuntimeError("HTTP "+str(resp.status_code))
            chunks=[]; total=0
            for chunk in resp.iter_content(65536):
                if not chunk: continue
                total+=len(chunk)
                if total>max_bytes: raise RuntimeError("Feed boyut limiti aşıldı")
                chunks.append(chunk)
            raw=b"".join(chunks).decode("utf-8","replace")
            fmt=str(cfg.get("format") or "lines").lower()
            urls=[]
            if fmt=="json":
                obj=json.loads(raw)
                path=str(cfg.get("items_key") or "urls")
                items=obj.get(path,[]) if isinstance(obj,dict) else obj
                if isinstance(items,list):
                    for x in items[:max_items]:
                        if isinstance(x,str): urls.append(x)
                        elif isinstance(x,dict):
                            v=x.get(str(cfg.get("url_key") or "url"))
                            if v: urls.append(str(v))
            else:
                for line in raw.splitlines():
                    line=line.strip()
                    if not line or line.startswith("#"): continue
                    if fmt=="csv":
                        try: line=next(csv.reader([line]))[int(cfg.get("url_column") or 0)].strip()
                        except Exception: continue
                    urls.append(line)
                    if len(urls)>=max_items: break
            # Normalize + dedupe before queue insertion.
            seen=set(); normalized=[]; rejected=0
            for u in urls:
                nu=self.normalize_discovery_url_v301(u)
                if not nu: rejected+=1; continue
                h=hashlib.sha256(nu.encode()).hexdigest()
                if h in seen: continue
                seen.add(h); normalized.append(nu)
            accepted=0; dup=0
            queue_target=max(1,min(100,int(cfg.get("queue_target") or max_items)))
            for u in normalized:
                if accepted>=queue_target: break
                r=self.enqueue_discovery_v301(u,source=f"v31:{source_id}",source_ref=name,priority=int(cfg.get("priority") or 65))
                if r.get("ok"): accepted+=1
                else: rejected+=1
            print(f"[DISCOVERY] Source sync | source={name} | fetched={len(urls)} | normalized={len(normalized)} | queued={accepted} | rejected={rejected} | target={queue_target}", flush=True)
            etag=resp.headers.get("ETag"); lm=resp.headers.get("Last-Modified")
            done=datetime.now(timezone.utc)
            interval=max(15,min(1440,int(cfg.get("interval_minutes") or 30)))
            with db_connect(DB_PATH,timeout=10) as con:
                con.execute("""UPDATE feed_sync_runs_v312 SET finished_at=?,status='success',fetched=?,accepted=?,
                    rejected=?,duplicates=?,http_status=?,etag=?,last_modified=? WHERE run_id=?""",
                    (done.isoformat(),len(urls),accepted,rejected,dup,resp.status_code,etag,lm,run_id))
                con.execute("""INSERT INTO feed_sync_state_v312(source_id,etag,last_modified,next_sync_at,
                    consecutive_failures,backoff_seconds,last_success_at,last_error)
                    VALUES(?,?,?,?,0,0,?,NULL)
                    ON CONFLICT(source_id) DO UPDATE SET etag=excluded.etag,last_modified=excluded.last_modified,
                    next_sync_at=excluded.next_sync_at,consecutive_failures=0,backoff_seconds=0,
                    last_success_at=excluded.last_success_at,last_error=NULL""",
                    (source_id,etag,lm,(done+timedelta(minutes=interval)).isoformat(),done.isoformat()))
                con.execute("UPDATE discovery_sources_v31 SET last_sync=?,last_error=NULL WHERE source_id=?",(done.isoformat(),source_id))
            return {"ok":True,"run_id":run_id,"fetched":len(urls),"accepted":accepted,"rejected":rejected,
                    "policy":"Feed hit yalnızca discovery candidate üretir."}
        except Exception as exc:
            failures=(int(st[3]) if st and st[3] is not None else 0)+1
            backoff=min(6*3600,60*(2**min(failures,6)))
            done=datetime.now(timezone.utc)
            with db_connect(DB_PATH,timeout=10) as con:
                con.execute("""UPDATE feed_sync_runs_v312 SET finished_at=?,status='failed',error=? WHERE run_id=?""",
                            (done.isoformat(),str(exc)[:500],run_id))
                con.execute("""INSERT INTO feed_sync_state_v312(source_id,next_sync_at,consecutive_failures,backoff_seconds,last_error)
                  VALUES(?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET next_sync_at=excluded.next_sync_at,
                  consecutive_failures=excluded.consecutive_failures,backoff_seconds=excluded.backoff_seconds,last_error=excluded.last_error""",
                  (source_id,(done+timedelta(seconds=backoff)).isoformat(),failures,backoff,str(exc)[:500]))
                con.execute("UPDATE discovery_sources_v31 SET last_error=? WHERE source_id=?",(str(exc)[:500],source_id))
            print(f"[DISCOVERY][ERROR] Source sync failed | source={name} | error={str(exc)[:240]} | backoff={backoff}s", flush=True)
            return {"ok":False,"run_id":run_id,"error":str(exc)[:500],"backoff_seconds":backoff}

    def discovery_runtime_status_v346(self):
        """Operational view of the autonomous discovery loop without changing decisions."""
        now=datetime.now(timezone.utc).isoformat()
        with db_connect(DB_PATH,timeout=8) as con:
            queue=dict(con.execute("SELECT status,COUNT(*) FROM discovery_queue_v301 GROUP BY status").fetchall())
            due_sources=con.execute("""SELECT COUNT(*) FROM discovery_sources_v31 s
              LEFT JOIN feed_sync_state_v312 f ON f.source_id=s.source_id
              WHERE s.enabled=1 AND s.source_type IN ('url_feed','ioc_feed')
                AND (f.next_sync_at IS NULL OR f.next_sync_at<=?)""",(now,)).fetchone()[0]
            last=con.execute("""SELECT run_id,created_at,finished_at,claimed,scanned,failed,observations,campaigns,status
              FROM discovery_scan_runs_v344 ORDER BY created_at DESC LIMIT 1""").fetchone()
        return {"queue":queue,"due_sources":int(due_sources or 0),
                "last_scan_run":dict(zip(("run_id","created_at","finished_at","claimed","scanned","failed",
                    "observations","campaigns","status"),last)) if last else None,
                "autonomous_enabled":os.getenv("WEB_DEFENDER_DISCOVERY_WORKER","0").lower() in ("1","true","yes","on"),
                "policy":"Autonomous loop only processes bounded candidates. It cannot verify ground truth or promote model weights."}

    def recover_stale_discovery_leases_v346(self, stale_minutes=20):
        """Return abandoned scanning leases to retry after worker restarts."""
        stale_minutes=max(5,min(180,int(stale_minutes)))
        cutoff=(datetime.now(timezone.utc)-timedelta(minutes=stale_minutes)).isoformat()
        # discovered_at is the durable timestamp available in the legacy queue schema.
        # Only old 'scanning' rows are recovered; normal queued/observed rows are untouched.
        with db_connect(DB_PATH,timeout=8) as con:
            rows=con.execute("""SELECT item_id,attempts FROM discovery_queue_v301
                WHERE status='scanning' AND discovered_at<?""",(cutoff,)).fetchall()
            recovered=0
            for item_id,attempts in rows:
                status="failed" if int(attempts or 0)>=5 else "retry"
                con.execute("""UPDATE discovery_queue_v301 SET status=?,next_attempt_at=?,
                    last_error=? WHERE item_id=? AND status='scanning'""",
                    (status,datetime.now(timezone.utc).isoformat(),
                     "Recovered stale discovery lease after worker restart",item_id))
                recovered+=1
        return {"ok":True,"recovered":recovered,"stale_minutes":stale_minutes}

    def run_autonomous_discovery_ingestion_v347(self, feed_limit=4):
        """Bounded feed ingestion only; never scans and never writes ground truth."""
        from ..intelligence.sync import _trust_db_init
        _trust_db_init()
        builtins=self.ensure_builtin_phishing_sources_v347()
        print(f"[DISCOVERY] Built-in phishing sources ready | sources={len(builtins.get('sources') or [])} | target_per_source=20", flush=True)
        self.recover_stale_discovery_leases_v346()
        feed_limit=max(1,min(8,int(feed_limit)))
        # Reuse the existing source synchronizer without entering queue processing.
        sources=self.list_discovery_sources_v301(enabled_only=True)[:feed_limit]
        synced=[]
        for source in sources:
            try:
                synced.append(self.sync_discovery_source_v301(source.get("source_id")))
            except Exception as exc:
                synced.append({"source_id":source.get("source_id"),"error":str(exc)[:300]})
        return {"sources":synced,"builtin_phishing_sources":builtins,
                "ground_truth_write":False,"production_weight_write":False}

    def run_autonomous_discovery_iteration_v346(self, feed_limit=4, scan_limit=2):
        """One conservative autonomous iteration.

        This is intentionally small for Render-class instances: ingestion is bounded,
        scanning is Feed OFF, and learning remains shadow-only.
        """
        from ..intelligence.sync import _trust_db_init
        _trust_db_init()
        builtins=self.ensure_builtin_phishing_sources_v347()
        print(f"[DISCOVERY] Built-in phishing sources ready | sources={len(builtins.get('sources') or [])} | target_per_source=20", flush=True)
        self.recover_stale_discovery_leases_v346()
        feed_limit=max(1,min(8,int(feed_limit)))
        scan_limit=max(1,min(4,int(scan_limit)))
        result=self.run_production_discovery_pipeline_v344(feed_limit,scan_limit)
        result["builtin_phishing_sources"]=builtins
        result["autonomous_iteration"]=True
        result["feed_limit"]=feed_limit
        result["scan_limit"]=scan_limit
        result["ground_truth_write"]=False
        result["production_weight_write"]=False
        return result

    def process_discovery_queue_v344(self, limit=4):
        """Analyze a bounded batch of already-ingested candidates.

        Candidates are claimed transactionally, scanned with Feed OFF as the engine KPI,
        persisted as candidate observations, and correlated to campaigns as context only.
        No candidate/prediction/campaign result becomes verified ground truth.
        """
        limit=max(1,min(12,int(limit)))
        now=datetime.now(timezone.utc).isoformat()
        run_id="scan_"+uuid.uuid4().hex[:20]
        claimed=[]
        with db_connect(DB_PATH,timeout=12) as con:
            rows=con.execute("""SELECT item_id,url,attempts FROM discovery_queue_v301
              WHERE status IN ('queued','retry')
                AND (next_attempt_at IS NULL OR next_attempt_at<=?)
              ORDER BY priority DESC,discovered_at ASC LIMIT ?""",(now,limit)).fetchall()
            for item_id,url,attempts in rows:
                cur=con.execute("""UPDATE discovery_queue_v301 SET status='scanning',attempts=attempts+1,
                    last_error=NULL WHERE item_id=? AND status IN ('queued','retry')""",(item_id,))
                if getattr(cur,"rowcount",1)!=0:
                    claimed.append((item_id,url,int(attempts or 0)+1))
            con.execute("""INSERT INTO discovery_scan_runs_v344
              (run_id,created_at,claimed,status,details) VALUES(?,?,?,?,?)""",
              (run_id,now,len(claimed),"running",json.dumps({"limit":limit})))

        scanned=failed=observations=campaigns=0; reports=[]
        print(f"[DISCOVERY] Queue batch | run={run_id} | claimed={len(claimed)} | feed_off=true", flush=True)
        # Local import avoids an engine/operations circular import at module import time.
        from ..engine import WebDefenderAnalyzer
        for item_id,url,attempt_no in claimed:
            try:
                try:
                    _lp=urlparse(url)
                    log_url=urlunparse((_lp.scheme,_lp.netloc,_lp.path,"","[redacted]" if _lp.query else "",""))
                except Exception:
                    log_url=str(url).split("?",1)[0]
                print(f"[DISCOVERY] Scan started | url={log_url} | attempt={attempt_no} | feed_off=true", flush=True)
                # Feed OFF is intentional: external intelligence may remain visible, but
                # cannot carry the engine verdict for autonomous discovery evaluation.
                # Autonomous candidates are scanned in a separate process so a hostile,
                # broken or indefinitely-stalling target can never freeze the queue.
                _scan_timeout=max(30,min(85,int(os.getenv("WEB_DEFENDER_DISCOVERY_SCAN_TIMEOUT_SECONDS","75") or 75)))
                _tmp=tempfile.NamedTemporaryFile(prefix="wd-discovery-",suffix=".json",delete=False)
                _tmp_path=_tmp.name; _tmp.close()
                try:
                    # Do not use subprocess.run(..., stderr=PIPE) here. Browser descendants
                    # can inherit the pipe and keep communicate() blocked even after the direct
                    # child is killed. A new POSIX process group lets us terminate the complete
                    # scan tree at the deadline.
                    _proc=subprocess.Popen(
                        [sys.executable,"-m","webdefender.discovery_scan_runner",url,_tmp_path],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                        text=True,start_new_session=True
                    )
                    try:
                        _rc=_proc.wait(timeout=_scan_timeout)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(_proc.pid, signal.SIGKILL)
                        except (ProcessLookupError, PermissionError, OSError):
                            try: _proc.kill()
                            except Exception: pass
                        try: _proc.wait(timeout=5)
                        except Exception: pass
                        raise RuntimeError(f"isolated scan hard timeout after {_scan_timeout}s")
                    if _rc!=0:
                        raise RuntimeError("isolated scan exited "+str(_rc))
                    with open(_tmp_path,"r",encoding="utf-8") as _fh:
                        result=json.load(_fh)
                finally:
                    try: os.unlink(_tmp_path)
                    except OSError: pass
                if not isinstance(result,dict) or result.get("error"):
                    raise RuntimeError(str((result or {}).get("error") or "scan failed"))
                # Persist the isolated result through the existing candidate-observation path.
                child=WebDefenderAnalyzer()
                child.results=result
                oid=child.record_live_observation_v301(item_id)
                observations+=1; scanned+=1
                corr=child.correlate_observation_campaign_v343(oid)
                if (corr or {}).get("campaign"): campaigns+=1
                with db_connect(DB_PATH,timeout=10) as con:
                    con.execute("""UPDATE discovery_queue_v301 SET status='observed',
                      next_attempt_at=NULL,last_error=NULL WHERE item_id=?""",(item_id,))
                score=float(result.get("risk_score") or 0)
                verdict=((result.get("defender") or {}).get("assessment") or {}).get("verdict") or result.get("risk_level") or "unknown"
                reports.append({"item_id":item_id,"observation_id":oid,
                    "engine_score":score,
                    "ground_truth_status":"candidate",
                    "campaign_id":((corr or {}).get("campaign") or {}).get("campaign_id")})
                print(f"[DISCOVERY] Scan finished | url={log_url} | threat={score:g} | verdict={verdict} | observation={oid}", flush=True)
            except Exception as exc:
                failed+=1
                # Bounded exponential retry, then terminal failure. Never infinite-spin.
                delay=min(86400,300*(2**min(attempt_no,8)))
                next_at=(datetime.now(timezone.utc)+timedelta(seconds=delay)).isoformat()
                status="failed" if attempt_no>=5 else "retry"
                with db_connect(DB_PATH,timeout=10) as con:
                    con.execute("""UPDATE discovery_queue_v301 SET status=?,next_attempt_at=?,
                      last_error=? WHERE item_id=?""",(status,next_at,str(exc)[:500],item_id))
                reports.append({"item_id":item_id,"error":str(exc)[:240],"status":status})
                print(f"[DISCOVERY][ERROR] Scan failed | url={log_url} | status={status} | error={str(exc)[:240]}", flush=True)

        finished=datetime.now(timezone.utc).isoformat()
        with db_connect(DB_PATH,timeout=10) as con:
            con.execute("""UPDATE discovery_scan_runs_v344 SET finished_at=?,scanned=?,failed=?,
              observations=?,campaigns=?,status=?,details=? WHERE run_id=?""",
              (finished,scanned,failed,observations,campaigns,
               "success" if failed==0 else ("partial" if scanned else "failed"),
               json.dumps({"reports":reports[:12]},ensure_ascii=False,default=str),run_id))
        print(f"[DISCOVERY] Cycle finished | run={run_id} | scanned={scanned} | failed={failed} | observations={observations} | campaigns={campaigns}", flush=True)
        return {"ok":failed==0,"run_id":run_id,"claimed":len(claimed),"scanned":scanned,
                "failed":failed,"observations":observations,"campaigns":campaigns,
                "feed_off":True,"ground_truth_effect":False,"reports":reports,
                "policy":"Candidate → Feed OFF scan → candidate observation → context-only campaign. Verified ground truth yalnızca ayrı doğrulama hattından gelir."}

    def run_production_discovery_pipeline_v344(self, feed_limit=8, scan_limit=4):
        """One bounded production iteration: ingest due sources, then scan queued candidates."""
        ingestion=self.run_discovery_cycle_v343(feed_limit)
        scanning=self.process_discovery_queue_v344(scan_limit)
        learning=self.build_verified_learning_proposal_v343(limit=5000,min_cases=60)
        return {"ok":bool(ingestion.get("ok")) and bool(scanning.get("ok")),
                "ingestion":ingestion,"scanning":scanning,"learning_shadow":learning,
                "automatic_weight_promotion":False,
                "internet_wide_crawling":False,
                "policy":"Observe → Learn → Evolve; öğrenme yalnızca verified ground truth ile, production ağırlıklarına otomatik terfi yok."}

    def ensure_builtin_phishing_sources_v347(self):
        """Register current phishing discovery sensors.

        Feed entries are candidates only. They never become engine verdicts or training
        ground truth merely because a provider listed them.
        """
        sources=[
            ("OpenPhish Community","url_feed","verified_external",{
                "url":"https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
                "format":"lines","max_items":80,"queue_target":20,"interval_minutes":720,
                "priority":72,"timeout":15,"max_bytes":2097152,"category":"phishing"
            }),
            ("PhishTank Online Valid","url_feed","verified_external",{
                "url":"https://data.phishtank.com/data/online-valid.csv",
                "format":"csv","url_column":1,"max_items":80,"queue_target":20,"interval_minutes":360,
                "priority":72,"timeout":20,"max_bytes":8388608,"category":"phishing",
                "items_key":"urls","url_key":"url","top_level_list":True
            }),
        ]
        out=[]
        for name,stype,trust,cfg in sources:
            r=self.register_discovery_source_v31(name,stype,trust,cfg)
            out.append({"name":name,**r})
        return {"ok":all(x.get("ok") for x in out),"sources":out,
                "target_per_source":20,
                "policy":"Provider listing = discovery candidate only; Feed OFF engine scan remains authoritative for Web Defender prediction."}

    def run_discovery_cycle_v343(self, limit=8):
        """Synchronize due discovery sources as candidate ingestion only.

        This scheduler does not scan arbitrary internet ranges and never turns a feed hit
        into a verdict or training label.
        """
        limit=max(1,min(32,int(limit)))
        now=datetime.now(timezone.utc).isoformat()
        run_id="ds_"+uuid.uuid4().hex[:20]
        with db_connect(DB_PATH,timeout=10) as con:
            due=con.execute("""SELECT COUNT(*) FROM discovery_sources_v31 s
              LEFT JOIN feed_sync_state_v312 st ON st.source_id=s.source_id
              WHERE s.enabled=1 AND s.source_type IN ('url_feed','ioc_feed')
                AND (st.next_sync_at IS NULL OR st.next_sync_at<=?)""",(now,)).fetchone()[0]
            con.execute("""INSERT INTO discovery_scheduler_runs_v343
              (run_id,created_at,due_sources,status,details) VALUES(?,?,?,?,?)""",
              (run_id,now,int(due or 0),"running",json.dumps({"limit":limit})))
        results=self.sync_due_feeds_v312(limit)
        ok=sum(1 for r in results if isinstance(r,dict) and r.get("ok"))
        failed=len(results)-ok
        accepted=sum(int((r or {}).get("accepted") or 0) for r in results if isinstance(r,dict))
        finished=datetime.now(timezone.utc).isoformat()
        with db_connect(DB_PATH,timeout=10) as con:
            con.execute("""UPDATE discovery_scheduler_runs_v343 SET finished_at=?,successful_sources=?,
              failed_sources=?,accepted_candidates=?,status=?,details=? WHERE run_id=?""",
              (finished,ok,failed,accepted,"success" if failed==0 else "partial",
               json.dumps({"results":results[:16]},ensure_ascii=False,default=str),run_id))
        return {"ok":failed==0,"run_id":run_id,"due_sources":int(due or 0),
                "synced_sources":len(results),"successful_sources":ok,"failed_sources":failed,
                "accepted_candidates":accepted,
                "authority":"candidate_ingestion_only",
                "policy":"Feed/discovery sonucu yalnızca adaydır; motor kararı veya verified ground truth değildir."}

    def build_verified_learning_proposal_v343(self, limit=5000, min_cases=60):
        """Create a shadow calibration proposal exclusively from verified ground truth."""
        limit=max(1,min(10000,int(limit))); min_cases=max(60,min(5000,int(min_cases)))
        with db_connect(DB_PATH,timeout=15) as con:
            rows=con.execute("""SELECT o.predicted_malicious,o.sensors_fired,g.label,g.family,g.confidence,
              g.truth_id,g.source FROM verified_ground_truth_v301 g
              JOIN live_observations_v301 o ON o.observation_id=g.observation_id
              WHERE g.confidence>=0.90 ORDER BY g.verified_at DESC LIMIT ?""",(limit,)).fetchall()
        parsed=[]; all_sensors=set()
        for pred,sensors,label,family,confidence,truth_id,source in rows:
            ss=set(json.loads(sensors or "[]")); all_sensors|=ss
            parsed.append({"actual_malicious":str(label)=="malicious",
                "predicted_malicious":bool(pred),"family":str(family or "general").lower(),
                "sensors_fired":sorted(ss),"truth_id":truth_id,"confidence":float(confidence or 0),
                "ground_truth_source":str(source or "")})
        for row in parsed: row["all_sensors"]=sorted(all_sensors)
        metrics=self.calibration_metrics_v29(parsed)
        families=self.family_metrics_v30(parsed)
        sensor_report=self.sensor_error_report_v29(parsed)
        proposal=self.propose_calibration_v29(sensor_report)
        fingerprint=hashlib.sha256(json.dumps(
            [{"truth_id":r["truth_id"],"actual":r["actual_malicious"],"family":r["family"]} for r in parsed],
            sort_keys=True).encode()).hexdigest()
        malicious=sum(1 for r in parsed if r["actual_malicious"]); clean=len(parsed)-malicious
        # A proposal is shadow-only. Eligibility merely means it may be reviewed/evaluated;
        # it does not modify production weights.
        enough=len(parsed)>=min_cases and malicious>0 and clean>0
        reason=("verified dataset is eligible for shadow evaluation" if enough else
                f"verified dataset insufficient/balanced cases required ({len(parsed)}/{min_cases})")
        pid="lp_"+fingerprint[:20]
        with db_connect(DB_PATH,timeout=12) as con:
            con.execute("""INSERT INTO learning_proposals_v343
              (proposal_id,created_at,dataset_fingerprint,verified_cases,malicious_cases,clean_cases,
               metrics,family_metrics,sensor_report,proposed_weights,status,promotion_allowed,
               promotion_reason,source_policy)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
              ON CONFLICT(proposal_id) DO UPDATE SET created_at=excluded.created_at,
               verified_cases=excluded.verified_cases,malicious_cases=excluded.malicious_cases,
               clean_cases=excluded.clean_cases,metrics=excluded.metrics,family_metrics=excluded.family_metrics,
               sensor_report=excluded.sensor_report,proposed_weights=excluded.proposed_weights,
               status=excluded.status,promotion_allowed=excluded.promotion_allowed,
               promotion_reason=excluded.promotion_reason""",
              (pid,datetime.now(timezone.utc).isoformat(),fingerprint,len(parsed),malicious,clean,
               json.dumps(metrics),json.dumps(families),json.dumps(sensor_report),json.dumps(proposal),
               "shadow_candidate" if enough else "insufficient_data",0,reason,
               "verified_ground_truth_only; no prediction/feed/campaign labels"))
        return {"ok":True,"proposal_id":pid,"verified_cases":len(parsed),"malicious_cases":malicious,
                "clean_cases":clean,"metrics":metrics,"family_metrics":families,
                "shadow_weight_proposal":proposal,"eligible_for_evaluation":enough,
                "promotion_allowed":False,
                "policy":"Yalnızca verified ground truth kullanılır. Candidate/prediction/feed/campaign sonucu eğitim etiketi değildir; üretim ağırlıkları otomatik değişmez."}

    def correlate_observation_campaign_v343(self, observation_id):
        """Attach an observation to an explainable campaign candidate without changing its verdict."""
        with db_connect(DB_PATH,timeout=10) as con:
            row=con.execute("""SELECT registrable_domain,predicted_score,ground_truth_status
              FROM live_observations_v301 WHERE observation_id=?""",(observation_id,)).fetchone()
        if not row or not row[0]:
            return {"ok":False,"error":"Observation/domain bulunamadı"}
        detected=self.detect_campaign_v313("domain",row[0])
        campaign=(detected or {}).get("campaign")
        if not campaign:
            return {"ok":True,"campaign":None,"verdict_effect":0,
                    "ground_truth_effect":False,"reason":(detected or {}).get("reason")}
        now=datetime.now(timezone.utc).isoformat()
        conf=float(campaign.get("confidence") or 0)
        with db_connect(DB_PATH,timeout=10) as con:
            con.execute("""INSERT INTO campaign_observation_links_v343
              (observation_id,campaign_id,created_at,relation,confidence,authority)
              VALUES(?,?,?,?,?,?) ON CONFLICT(observation_id,campaign_id) DO UPDATE SET
              confidence=excluded.confidence,created_at=excluded.created_at""",
              (observation_id,campaign["campaign_id"],now,"bounded_graph_correlation",conf,
               "context_only"))
        return {"ok":True,"campaign":campaign,"verdict_effect":0,"ground_truth_effect":False,
                "authority":"context_only",
                "policy":"Campaign korelasyonu bağlamdır; tek başına scan verdict, score veya ground truth değiştirmez."}

    def detect_campaign_v313(self, seed_type, seed_value, max_nodes=180):
        """Bounded, explainable campaign clustering over persisted observations."""
        seed_type=str(seed_type or "").lower(); seed_value=str(seed_value or "").strip()
        if seed_type not in ("url","domain","ip","sha256") or not seed_value:
            return {"ok":False,"error":"Geçersiz seed"}
        max_nodes=max(20,min(300,int(max_nodes)))
        queue=[(seed_type,seed_value,0)]
        visited=set(); all_edges=[]; groups=set(); provenance=set()
        # Depth 2 prevents a single shared CDN/IP from exploding into an internet-scale cluster.
        while queue and len(visited)<max_nodes:
            typ,val,depth=queue.pop(0)
            key=(typ,val)
            if key in visited: continue
            visited.add(key)
            if depth>=2: continue
            for e in self._campaign_edges_v313(typ,val,120):
                # Weak graph context does not propagate a campaign.
                if e["confidence"]<0.55: continue
                all_edges.append(e); groups.add(e["group"]); provenance.add(e["source"])
                nk=(e["to_type"],e["to_value"])
                if nk not in visited and e["confidence"]>=0.70:
                    queue.append((nk[0],nk[1],depth+1))
        nodes=set([(seed_type,seed_value)])
        for e in all_edges:
            nodes.add((e["from_type"],e["from_value"])); nodes.add((e["to_type"],e["to_value"]))
        # Shared infrastructure alone is deliberately insufficient.
        strong=[e for e in all_edges if e["confidence"]>=0.75]
        external_sources={"urlhaus","threatfox","openphish","phishtank"}
        engine_strong=[e for e in strong if str(e.get("source") or "").strip().lower() not in external_sources]
        independent={e["group"] for e in strong}
        engine_independent={e["group"] for e in engine_strong}
        meaningful=engine_independent-{"graph_context","infrastructure"}
        if len(nodes)<3 or not strong or not engine_strong or (len(engine_independent)<2 and not meaningful):
            return {"ok":True,"campaign":None,"nodes":len(nodes),"edges":len(all_edges),
                    "reason":"Bağımsız ilişki kanıtı kampanya oluşturmak için yetersiz."}
        # Score independent modalities, graph density and strong-edge ratio. No trust subtraction.
        density=min(1.0,len(all_edges)/max(1,len(nodes)*1.5))
        strong_ratio=len(strong)/max(1,len(all_edges))
        conf=min(.99,.35 + .12*min(4,len(independent)) + .18*density + .16*strong_ratio)
        # Infrastructure-only clusters are capped as contextual.
        if independent.issubset({"infrastructure","graph_context"}): conf=min(conf,.49)
        member_tokens=sorted(f"{t}:{v}" for t,v in nodes)
        fp=hashlib.sha256("|".join(member_tokens).encode()).hexdigest()
        cid="camp_"+fp[:20]; now=datetime.now(timezone.utc).isoformat()
        families=set()
        # Correlate verified observations only for family labels.
        domains=[v for t,v in nodes if t=="domain"][:100]
        if domains:
            with db_connect(DB_PATH,timeout=12) as con:
                for d in domains:
                    rows=con.execute("""SELECT g.family FROM verified_ground_truth_v301 g
                      JOIN live_observations_v301 o ON o.observation_id=g.observation_id
                      WHERE o.registrable_domain=? AND g.label='malicious'""",(d,)).fetchall()
                    families.update(str(r[0]) for r in rows if r and r[0])
        status="high_confidence_candidate" if conf>=.80 and len(engine_independent)>=2 else "candidate"
        summary=f"{len(nodes)} node, {len(all_edges)} relation, {len(independent)} independent relation groups"
        with db_connect(DB_PATH,timeout=15) as con:
            con.execute("""INSERT INTO threat_campaigns_v313
              (campaign_id,created_at,updated_at,status,confidence,threat_families,seed_count,node_count,
               edge_count,independent_signal_groups,first_seen,last_seen,summary,fingerprint)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
              ON CONFLICT(campaign_id) DO UPDATE SET updated_at=excluded.updated_at,status=excluded.status,
              confidence=excluded.confidence,threat_families=excluded.threat_families,node_count=excluded.node_count,
              edge_count=excluded.edge_count,independent_signal_groups=excluded.independent_signal_groups,
              last_seen=excluded.last_seen,summary=excluded.summary""",
              (cid,now,now,status,conf,json.dumps(sorted(families)),1,len(nodes),len(all_edges),
               len(independent),now,now,summary,fp))
            for typ,val in list(nodes)[:max_nodes]:
                role="seed" if (typ,val)==(seed_type,seed_value) else "related"
                con.execute("""INSERT INTO threat_campaign_members_v313
                  (campaign_id,node_type,node_value,role,confidence,first_seen,last_seen,provenance)
                  VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(campaign_id,node_type,node_value) DO UPDATE SET
                  last_seen=excluded.last_seen,confidence=excluded.confidence""",
                  (cid,typ,val,role,conf,now,now,json.dumps(sorted(provenance))))
            for e in all_edges[:500]:
                con.execute("""INSERT INTO threat_campaign_links_v313
                  (campaign_id,from_type,from_value,to_type,to_value,relation,confidence,provenance)
                  VALUES(?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING""",
                  (cid,e["from_type"],e["from_value"],e["to_type"],e["to_value"],e["relation"],
                   e["confidence"],json.dumps({"source":e["source"],"group":e["group"]})))
        return {"ok":True,"campaign":{"campaign_id":cid,"status":status,"confidence":round(conf,3),
          "nodes":len(nodes),"edges":len(all_edges),"independent_groups":sorted(independent),
          "engine_independent_groups":sorted(engine_independent),
          "verified_threat_families":sorted(families),"summary":summary},
          "policy":"Campaign candidate ground truth değildir; shared hosting/IP tek başına malicious hüküm üretmez."}

