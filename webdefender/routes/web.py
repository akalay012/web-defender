"""Web/API routes.

def analyze_url(url, feed_off=True):
    from ..engine import WebDefenderAnalyzer
    return WebDefenderAnalyzer(url, feed_off=feed_off).analyze_url()

This module owns HTTP presentation and administrative endpoints. It delegates
analysis to the engine and never recalculates threat scores.
"""
import hashlib, re
import uuid
import os, json
from flask import request, jsonify, render_template_string

from ..state import LEARNING_ENGINE, THREAT_INTEL_STORE
from ..intelligence.sync import sync_all_threat_intel
from ..application import app, APP_VERSION
from .template import HTML_TEMPLATE
from ..routes.policy import decision_payload

# Canonical route dependencies. No compatibility-core aliases.
def _analyzer():
    from ..engine import SecurityAnalyzer
    return SecurityAnalyzer()

def _admin_ok_v30():
    expected=(os.getenv("WEB_DEFENDER_ADMIN_TOKEN") or "").strip()
    supplied=(request.headers.get("X-Web-Defender-Admin") or request.args.get("admin_token") or "").strip()
    return bool(expected) and supplied == expected

def _admin_error_v30():
    if not (os.getenv("WEB_DEFENDER_ADMIN_TOKEN") or "").strip():
        return jsonify({"error":"WEB_DEFENDER_ADMIN_TOKEN yapılandırılmamış."}),503
    return jsonify({"error":"Yetkisiz."}),401

@app.post("/api/v31/source/register")
def v31_source_register():
    if not _admin_ok_v30(): return _admin_error_v30()
    d=request.get_json(silent=True) or {}; a=_analyzer()
    return jsonify(a.register_discovery_source_v31(str(d.get("name") or ""),str(d.get("source_type") or ""),
        str(d.get("trust_level") or "contextual"),d.get("config") or {}))

@app.post("/api/v31/feed/sync")
def v312_feed_sync():
    if not _admin_ok_v30(): return _admin_error_v30()
    d=request.get_json(silent=True) or {}; a=_analyzer()
    sid=str(d.get("source_id") or "")
    if sid: return jsonify(a.sync_discovery_source_v312(sid))
    return jsonify({"ok":True,"results":a.sync_due_feeds_v312(int(d.get("limit") or 8))})

@app.get("/api/v31/feed/status")
def v312_feed_status():
    if not _admin_ok_v30(): return _admin_error_v30()
    return jsonify({"ok":True,**_analyzer().feed_sync_status_v312()})

@app.post("/api/v31/source/ingest")
def v31_source_ingest():
    if not _admin_ok_v30(): return _admin_error_v30()
    d=request.get_json(silent=True) or {}; a=_analyzer()
    return jsonify(a.ingest_discovery_urls_v31(str(d.get("source_id") or ""),d.get("urls") or []))

@app.get("/api/v32/zero-day/status")
def v32_zero_day_status():
    if not _admin_ok_v30(): return _admin_error_v30()
    return jsonify({"ok":True,**_analyzer().zero_day_status_v32(int(request.args.get("limit","50")))})

@app.post("/api/v31/campaign/detect")
def v313_campaign_detect():
    if not _admin_ok_v30(): return _admin_error_v30()
    d=request.get_json(silent=True) or {}; a=_analyzer()
    return jsonify(a.detect_campaign_v313(str(d.get("seed_type") or "domain"),
        str(d.get("seed_value") or ""),int(d.get("max_nodes") or 180)))

@app.post("/api/v31/campaign/from-observation")
def v313_campaign_observation():
    if not _admin_ok_v30(): return _admin_error_v30()
    d=request.get_json(silent=True) or {}
    return jsonify(_analyzer().auto_campaign_from_observation_v313(str(d.get("observation_id") or "")))

@app.get("/api/v31/campaign/status")
def v313_campaign_status():
    if not _admin_ok_v30(): return _admin_error_v30()
    return jsonify({"ok":True,**_analyzer().campaign_status_v313(int(request.args.get("limit","50")))})

@app.post("/api/v31/hunt/expand")
def v31_hunt_expand():
    if not _admin_ok_v30(): return _admin_error_v30()
    d=request.get_json(silent=True) or {}; a=_analyzer()
    return jsonify(a.expand_threat_hunt_v31(str(d.get("observation_id") or ""),int(d.get("max_depth") or 1)))

@app.get("/api/v31/status")
def v31_status():
    if not _admin_ok_v30(): return _admin_error_v30()
    a=_analyzer()
    return jsonify({"ok":True,"persistence":a.persistence_status_v31(),"discovery":a.discovery_status_v301()})

@app.post("/api/discovery/enqueue")
def discovery_enqueue_v301():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}; a=_analyzer()
    return jsonify(a.enqueue_discovery_v301(data.get("url"),str(data.get("source") or "manual"),
        data.get("source_ref"),int(data.get("priority") or 50)))

@app.get("/api/discovery/status")
def discovery_status_api_v301():
    if not _admin_ok_v30(): return _admin_error_v30()
    return jsonify({"ok":True,**_analyzer().discovery_status_v301()})

@app.post("/api/discovery/verify")
def discovery_verify_v301():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}; a=_analyzer()
    return jsonify(a.verify_observation_v301(str(data.get("observation_id") or ""),
        str(data.get("label") or ""),str(data.get("family") or "general"),
        str(data.get("verifier") or "analyst"),str(data.get("source") or "analyst"),
        float(data.get("confidence") or 0),str(data.get("notes") or "")))

@app.post("/api/discovery/regression")
def discovery_regression_v301():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}; a=_analyzer()
    return jsonify({"ok":True,**a.continuous_regression_v301(int(data.get("limit") or 2000),
        str(data.get("window_name") or "verified-live"))})

@app.post("/api/evolution/snapshot")
def evolution_snapshot_v30():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}
    a=_analyzer()
    snap=a.create_model_snapshot_v30(data.get("weights") or {},data.get("global_metrics") or {},
        data.get("family_metrics") or {},data.get("parent_model_id"),"shadow",
        str(data.get("dataset_fingerprint") or "")[:128],str(data.get("reason") or "candidate"))
    return jsonify({"ok":True,**snap})

@app.post("/api/evolution/family-guard")
def evolution_family_guard_v30():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}; a=_analyzer()
    return jsonify({"ok":True,"guard":a.evaluate_family_guard_v30(
        data.get("baseline_rows") or [],data.get("candidate_rows") or [],int(data.get("min_family_cases") or 20))})

@app.post("/api/evolution/drift")
def evolution_drift_v30():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}; a=_analyzer()
    result=a.detect_concept_drift_v30(data.get("baseline_rows") or [],data.get("current_rows") or [])
    now=datetime.now(timezone.utc).isoformat()
    with db_connect(DB_PATH, timeout=12) as con:
        for e in result.get("events",[]):
            con.execute("""INSERT INTO drift_events_v30(created_at,window_name,family,baseline_recall,current_recall,
              baseline_fpr,current_fpr,severity,action,details) VALUES(?,?,?,?,?,?,?,?,?,?)""",
              (now,str(data.get("window_name") or "current")[:100],e["family"],None,None,None,None,
               e["severity"],e["action"],json.dumps(e)))
    return jsonify({"ok":True,**result})

@app.post("/api/evolution/promote")
def evolution_promote_v30():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}
    # Promotion requires caller to include a passed family guard generated from verified regression.
    guard=data.get("family_guard") or {}
    if not guard.get("pass"):
        return jsonify({"ok":False,"error":"Family guard geçmeden promotion yapılamaz"}),409
    a=_analyzer()
    return jsonify(a.promote_model_v30(str(data.get("model_id") or ""),str(data.get("reason") or "verified promotion")))

@app.post("/api/evolution/rollback")
def evolution_rollback_v30():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}; a=_analyzer()
    return jsonify(a.rollback_model_v30(str(data.get("reason") or "manual rollback"),False))

@app.post("/api/calibration/evaluate")
def calibration_evaluate_v29():
    token=os.getenv("THREAT_INTEL_ADMIN_TOKEN","").strip()
    if not token or request.headers.get("X-Web-Defender-Token","") != token:
        return jsonify({"ok":False,"error":"Yetkisiz"}),401
    data=request.get_json(silent=True) or {}
    rows=data.get("rows") or []
    if not isinstance(rows,list) or not rows:
        return jsonify({"ok":False,"error":"rows gerekli"}),400
    a=_analyzer()
    metrics=a.calibration_metrics_v29(rows)
    sensors=a.sensor_error_report_v29(rows)
    proposal=a.propose_calibration_v29(sensors)
    run_id="cal_"+uuid.uuid4().hex[:16]; now=datetime.now(timezone.utc).isoformat()
    with db_connect(DB_PATH, timeout=12) as con:
        con.execute("""INSERT INTO calibration_runs(run_id,created_at,version,dataset_name,total,tp,fp,tn,fn,
          precision,recall,f1,false_positive_rate,false_negative_rate,sensor_report,notes)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (run_id,now,APP_VERSION,str(data.get("dataset_name") or "verified-regression")[:120],
           metrics["total"],metrics["tp"],metrics["fp"],metrics["tn"],metrics["fn"],metrics["precision"],
           metrics["recall"],metrics["f1"],metrics["false_positive_rate"],metrics["false_negative_rate"],
           json.dumps(sensors,ensure_ascii=False),str(data.get("notes") or "")[:1000]))
    return jsonify({"ok":True,"run_id":run_id,"metrics":metrics,"sensor_report":sensors,
                    "shadow_weight_proposal":proposal,
                    "note":"Bu endpoint üretim ağırlıklarını değiştirmez; yalnızca aday üretir."})

@app.post("/api/calibration/compare")
def calibration_compare_v29():
    token=os.getenv("THREAT_INTEL_ADMIN_TOKEN","").strip()
    if not token or request.headers.get("X-Web-Defender-Token","") != token:
        return jsonify({"ok":False,"error":"Yetkisiz"}),401
    data=request.get_json(silent=True) or {}
    a=_analyzer()
    base=a.calibration_metrics_v29(data.get("baseline_rows") or [])
    cand=a.calibration_metrics_v29(data.get("candidate_rows") or [])
    gate=a.evaluate_candidate_v29(base,cand,int(data.get("min_cases") or 60))
    return jsonify({"ok":True,"baseline":base,"candidate":cand,"promotion_gate":gate,
                    "rule":"Recall/FNR gerilerse aday model terfi etmez."})

@app.post("/api/visual-baseline/enroll")
def visual_baseline_enroll_v27():
    token=os.getenv("THREAT_INTEL_ADMIN_TOKEN","").strip()
    if not token or request.headers.get("X-Web-Defender-Token","") != token:
        return jsonify({"ok":False,"error":"Yetkisiz veya admin token ayarlanmamış"}),401
    data=request.get_json(silent=True) or {}
    brand=str(data.get("brand") or "").strip().lower()
    domain=registrable_domain_v21(str(data.get("domain") or "").strip().lower())
    layout=str(data.get("layout_fingerprint") or "").strip()
    dhash=str(data.get("screenshot_dhash") or "").strip().lower() or None
    tokens=[str(x).lower()[:80] for x in (data.get("dom_tokens") or [])[:400] if str(x).strip()]
    if not brand or not domain or not layout:
        return jsonify({"ok":False,"error":"brand, domain ve layout_fingerprint gerekli"}),400
    # Enrollment is deliberately admin-verified; scans cannot self-promote to trusted baseline.
    now=datetime.now(timezone.utc).isoformat()
    with db_connect(DB_PATH, timeout=10) as con:
        con.execute("""INSERT INTO visual_baselines(brand,domain,layout_fingerprint,screenshot_dhash,dom_tokens,verified_at,source)
          VALUES(?,?,?,?,?,?,?)
          ON CONFLICT(brand,domain,layout_fingerprint) DO UPDATE SET screenshot_dhash=excluded.screenshot_dhash,
          dom_tokens=excluded.dom_tokens,verified_at=excluded.verified_at,source=excluded.source""",
          (brand,domain,layout,dhash,json.dumps(tokens,ensure_ascii=False),now,"admin_verified"))
    return jsonify({"ok":True,"brand":brand,"domain":domain,"verified_at":now})

@app.post("/api/feedback")
def feedback_v26():
    """Single feedback endpoint for scan labels and verified evidence labels."""
    data=request.get_json(silent=True) or {}
    if data.get("scan_id") and data.get("verdict") and not data.get("url"):
        try:
            LEARNING_ENGINE.label_scan(str(data.get("scan_id") or "").strip(),str(data.get("verdict") or "").strip().lower())
            return jsonify({"ok":True,"stats":LEARNING_ENGINE.stats(),"mode":"scan_feedback"})
        except ValueError as exc: return jsonify({"error":str(exc)}),400
        except Exception as exc: return jsonify({"error":f"Geri bildirim kaydedilemedi: {exc}"}),500
    label=str(data.get("label") or "").strip().lower()
    if label not in {"malicious","clean","false_positive","false_negative"}:
        return jsonify({"ok":False,"error":"Geçerli label: malicious, clean, false_positive, false_negative"}),400
    url=str(data.get("url") or "").strip()
    if not url:
        return jsonify({"ok":False,"error":"url gerekli"}),400
    try:
        host=(urlparse(normalize_url(url)).hostname or "").lower()
        root=registrable_domain_v21(host)
    except Exception:
        return jsonify({"ok":False,"error":"Geçersiz URL"}),400
    evidence=data.get("evidence") or []
    ids=[]; sensors=set()
    for e in evidence[:100]:
        if not isinstance(e,dict): continue
        if e.get("evidence_id"): ids.append(str(e["evidence_id"]))
        if e.get("sensor"): sensors.add(str(e["sensor"]))
    now=datetime.now(timezone.utc).isoformat()
    url_hash=hashlib.sha256(normalize_url(url).encode()).hexdigest()
    with db_connect(DB_PATH, timeout=12) as con:
        con.execute("""INSERT INTO scan_feedback(created_at,url_hash,registrable_domain,label,reason,scan_version,evidence_ids,feature_snapshot)
          VALUES(?,?,?,?,?,?,?,?)""",(now,url_hash,root,label,str(data.get("reason") or "")[:1000],APP_VERSION,
          json.dumps(ids),json.dumps(data.get("features") or {},ensure_ascii=False)[:12000]))
        # Conservative online reliability update. A sensor only becomes active after 30 samples.
        for sensor in sensors:
            row=con.execute("SELECT tp,fp,tn,fn FROM sensor_learning WHERE sensor=?",(sensor,)).fetchone() or (0,0,0,0)
            tp,fp,tn,fn=row
            predicted_malicious=True  # submitted evidence means this sensor fired
            actual_malicious=label in ("malicious","false_negative")
            if predicted_malicious and actual_malicious: tp+=1
            elif predicted_malicious and not actual_malicious: fp+=1
            precision=(tp+1)/(tp+fp+2)  # Laplace-smoothed
            weight=max(.65,min(1.35,.65+.70*precision))
            con.execute("""INSERT INTO sensor_learning(sensor,tp,fp,tn,fn,weight,updated_at) VALUES(?,?,?,?,?,?,?)
              ON CONFLICT(sensor) DO UPDATE SET tp=excluded.tp,fp=excluded.fp,tn=excluded.tn,fn=excluded.fn,
              weight=excluded.weight,updated_at=excluded.updated_at""",(sensor,tp,fp,tn,fn,weight,now))
    return jsonify({"ok":True,"label":label,"domain":root,"evidence_count":len(ids),
                    "note":"Ağırlıklar 30 doğrulanmış örnekten önce skorlamaya açılmaz."})

@app.get("/api/trust-context/status")
def trust_context_status_v21():
    try:
        with db_connect(DB_PATH, timeout=8) as con:
            row=con.execute("SELECT COUNT(*),MAX(updated_at) FROM tranco_ranks").fetchone()
        return jsonify({"ok":True,"tranco_records":row[0],"tranco_updated_at":row[1],"version":APP_VERSION})
    except Exception as exc:
        return jsonify({"ok":False,"error":str(exc)}),500

@app.post("/api/trust-context/sync")
def trust_context_sync_v21():
    token=os.getenv("THREAT_INTEL_ADMIN_TOKEN","").strip()
    if not token:
        return jsonify({"ok":False,"error":"THREAT_INTEL_ADMIN_TOKEN ayarlanmadan sync endpoint etkin değildir."}),503
    if request.headers.get("X-Web-Defender-Token","") != token:
        return jsonify({"ok":False,"error":"Yetkisiz"}),401
    try:
        return jsonify(sync_tranco_v21())
    except Exception as exc:
        return jsonify({"ok":False,"error":str(exc)}),500

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE, app_version=APP_VERSION)

@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type application/json olmali."}), 415
        data = request.get_json(silent=True) or {}
        url  = (data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "URL gerekli."}), 400

        analyzer = _analyzer()
        # V32.3.1.1: feed_off may arrive in JSON (UI/API) or query/form values.
        feed_raw = data.get("feed_off", request.values.get("feed_off", "0"))
        analyzer.feed_off_v3231 = str(feed_raw).lower() in ("1", "true", "yes", "on")
        result = analyzer.analyze_url(url)

        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": f"Sunucu hatası: {exc}"}), 500

@app.route("/health")
@app.route("/healthz")
def health():
    # Liveness endpoint: analyzer, Chromium, DB, DNS veya threat-feed çağırmaz.
    return jsonify({
        "status": "ok",
        "service": f"Web Defender {APP_VERSION}",
        "time": datetime.now(timezone.utc).isoformat(),
    }), 200

@app.post("/api/threat-intel/sync")
def threat_intel_sync():
    token=os.getenv("THREAT_INTEL_ADMIN_TOKEN","").strip()
    if token and request.headers.get("X-Web-Defender-Token","")!=token:
        return jsonify({"ok":False,"error":"unauthorized"}),403
    return jsonify(sync_all_threat_intel())

@app.post("/api/threat-intel/hash")
def threat_intel_hash_lookup():
    data=request.get_json(silent=True) or {}; sh=str(data.get("sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}",sh): return jsonify({"ok":False,"error":"Geçerli SHA-256 gerekli."}),400
    out={"ok":True,"sha256":sh,"local_matches":THREAT_INTEL_STORE.lookup_hash(sh),"threatfox":None}
    key=os.getenv("ABUSECH_AUTH_KEY","").strip()
    if key:
        try:
            rr=requests.post("https://threatfox-api.abuse.ch/api/v1/",json={"query":"search_hash","hash":sh},
                headers={"Auth-Key":key,"User-Agent":f"WebDefender/{APP_VERSION}"},timeout=10)
            jj=rr.json() if rr.ok else {}
            out["threatfox"]={"status":rr.status_code,"query_status":jj.get("query_status"),"data":jj.get("data") if jj.get("query_status")=="ok" else []}
        except Exception as e: out["threatfox"]={"error":str(e)[:250]}
    return jsonify(out)

@app.get("/api/threat-intel/graph")
def threat_intel_graph():
    typ=request.args.get("type","domain").strip(); value=request.args.get("value","").strip()
    if not value: return jsonify({"ok":False,"error":"value gerekli"}),400
    return jsonify({"ok":True,**THREAT_INTEL_STORE.graph_neighborhood(typ,value)})

@app.get("/api/threat-intel/graph/stats")
def threat_intel_graph_stats():
    return jsonify({"ok":True,**THREAT_INTEL_STORE.graph_stats()})

@app.get("/api/threat-intel/status")
def threat_intel_status():
    st=THREAT_INTEL_STORE.status()
    st['active_ioc_count']=THREAT_INTEL_STORE.active_count()
    st['graph']=THREAT_INTEL_STORE.graph_stats()
    st['urlhaus_configured']=bool(os.getenv('ABUSECH_AUTH_KEY','').strip())
    st['threatfox_configured']=bool(os.getenv('ABUSECH_AUTH_KEY','').strip())
    st['note']='IOC kaynakları bağımsız sensörlerdir; eşleşmeler Fusion Engine tarafından diğer davranış kanıtlarıyla birlikte değerlendirilir.'
    return jsonify(st)

