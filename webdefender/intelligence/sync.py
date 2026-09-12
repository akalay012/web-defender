"""Threat intelligence and trust-context synchronization.

External feeds are sensors only. This module ingests and caches observations;
it does not own Web Defender's final verdict.
"""
from ..metadata import APP_VERSION
import tempfile
import os, re, json, time, hashlib, threading, csv, io
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

from ..state import THREAT_INTEL_STORE, _TI_SYNC_LOCK
from ..database import db_connect
from ..analyzer.url_domain import get_root_domain, get_canonical_root

def _expiry(value,days):
    try:
        d=datetime.fromisoformat(str(value or "").replace("Z","+00:00"))
        if d.tzinfo is None: d=d.replace(tzinfo=timezone.utc)
    except Exception: d=datetime.now(timezone.utc)
    return datetime.fromtimestamp(d.timestamp()+days*86400,timezone.utc).isoformat()

def sync_urlhaus_recent():
    key=os.getenv("ABUSECH_AUTH_KEY","").strip(); count=0
    if not key:
        THREAT_INTEL_STORE.sync_state("URLhaus",False,0,"ABUSECH_AUTH_KEY gerekli")
        return {"source":"URLhaus","ok":False,"records":0,"error":"not_configured"}
    try:
        r=requests.get(f"https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
                       headers={"User-Agent":f"WebDefender/{APP_VERSION}"},timeout=30)
        r.raise_for_status()
        lines=[x for x in r.text.splitlines() if x and not x.startswith("#")]
        rows=list(csv.reader(lines))
        if not rows: raise RuntimeError("empty_feed")
        hdr=[x.strip().lower().replace(" ","_") for x in rows[0]]
        has="url" in hdr; idx={x:i for i,x in enumerate(hdr)} if has else {}
        for row in (rows[1:] if has else rows):
            try:
                u=row[idx["url"]].strip() if has else row[2].strip()
                if not u.startswith(("http://","https://")): continue
                first=(row[idx["dateadded"]].strip() if has and "dateadded" in idx else (row[1].strip() if len(row)>1 else None))
                threat=(row[idx["threat"]].strip() if has and "threat" in idx else (row[5].strip() if len(row)>5 else "malware_download"))
                THREAT_INTEL_STORE.upsert("url",u,"URLhaus",threat_type=threat or "malware_download",
                    confidence=98,first_seen=first,expires_at=_expiry(first,90),raw={"bulk":True})
                host=(urlparse(u).hostname or "").lower()
                if host:
                    THREAT_INTEL_STORE.upsert("domain",host,"URLhaus",threat_type="malware_host_observed",
                        confidence=78,first_seen=first,expires_at=_expiry(first,30),raw={"derived_from_url":True})
                    THREAT_INTEL_STORE.graph_edge("url",u,"has-host","domain",host,"URLhaus",90,first_seen=first,evidence={"feed":"recent.csv"})
                count+=1
            except Exception: continue
        THREAT_INTEL_STORE.sync_state("URLhaus",True,count,"")
        return {"source":"URLhaus","ok":True,"records":count}
    except Exception as e:
        THREAT_INTEL_STORE.sync_state("URLhaus",False,count,str(e))
        return {"source":"URLhaus","ok":False,"records":count,"error":str(e)[:250]}

def sync_threatfox_recent(days=3):
    key=os.getenv("ABUSECH_AUTH_KEY","").strip(); count=0; days=max(1,min(int(days),7))
    if not key:
        THREAT_INTEL_STORE.sync_state("ThreatFox",False,0,"ABUSECH_AUTH_KEY gerekli")
        return {"source":"ThreatFox","ok":False,"records":0,"error":"not_configured"}
    try:
        r=requests.post("https://threatfox-api.abuse.ch/api/v1/",json={"query":"get_iocs","days":days},
            headers={"Auth-Key":key,"User-Agent":f"WebDefender/{APP_VERSION}"},timeout=30)
        r.raise_for_status(); j=r.json(); data=j.get("data") if j.get("query_status")=="ok" else []
        for x in data if isinstance(data,list) else []:
            ioc=str(x.get("ioc") or "").strip(); typ=str(x.get("ioc_type") or "").lower()
            if typ=="url": it="url"
            elif "domain" in typ: it="domain"
            elif "ip" in typ: it="ip"
            elif "sha256" in typ: it="sha256"
            else: continue
            if it=="ip" and ioc.count(":")==1: ioc=ioc.split(":",1)[0]
            last=x.get("last_seen") or x.get("first_seen")
            fam=x.get("malware_printable") or x.get("malware"); conf=x.get("confidence_level") or 0
            THREAT_INTEL_STORE.upsert(it,ioc,"ThreatFox",threat_type=x.get("threat_type"),
                malware_family=fam,confidence=conf,first_seen=x.get("first_seen"),last_seen=last,expires_at=_expiry(last,180),raw=x)
            if fam:
                THREAT_INTEL_STORE.graph_edge(it,ioc,"indicates","malware_family",fam,"ThreatFox",conf,
                    x.get("first_seen"),last,{"threat_type":x.get("threat_type")})
            count+=1
        THREAT_INTEL_STORE.sync_state("ThreatFox",True,count,"")
        return {"source":"ThreatFox","ok":True,"records":count}
    except Exception as e:
        THREAT_INTEL_STORE.sync_state("ThreatFox",False,count,str(e))
        return {"source":"ThreatFox","ok":False,"records":count,"error":str(e)[:250]}

def sync_all_threat_intel():
    if not _TI_SYNC_LOCK.acquire(False): return {"ok":False,"error":"sync_already_running"}
    try:
        expired=THREAT_INTEL_STORE.expire_old()
        a=sync_urlhaus_recent(); b=sync_threatfox_recent(os.getenv("THREATFOX_SYNC_DAYS","3"))
        return {"ok":a.get("ok") or b.get("ok"),"expired_now":expired,"active_iocs":THREAT_INTEL_STORE.active_count(),"results":[a,b]}
    finally: _TI_SYNC_LOCK.release()

def _ti_loop():
    interval=max(300,int(os.getenv("THREAT_INTEL_SYNC_SECONDS","1800")))
    time.sleep(max(2,min(30,int(os.getenv("THREAT_INTEL_INITIAL_DELAY","8")))))
    while True:
        try: sync_all_threat_intel()
        except Exception: pass
        time.sleep(interval)

def _trust_db_init():
    with db_connect(DB_PATH, timeout=15) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS tranco_ranks(
            domain TEXT PRIMARY KEY, rank INTEGER NOT NULL, updated_at TEXT NOT NULL)""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_tranco_rank ON tranco_ranks(rank)")
        con.execute("""CREATE TABLE IF NOT EXISTS trust_cache(
            cache_key TEXT PRIMARY KEY, payload TEXT NOT NULL, expires_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS evidence_registry(
            evidence_id TEXT PRIMARY KEY,
            fingerprint TEXT UNIQUE NOT NULL,
            sensor TEXT NOT NULL,
            source TEXT NOT NULL,
            category TEXT,
            title TEXT,
            confidence REAL DEFAULT 0.5,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            seen_count INTEGER DEFAULT 1,
            independent_group TEXT,
            payload TEXT)""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_evidence_sensor ON evidence_registry(sensor,category)")
        con.execute("""CREATE TABLE IF NOT EXISTS scan_feedback(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            url_hash TEXT NOT NULL,
            registrable_domain TEXT,
            label TEXT NOT NULL,
            reason TEXT,
            scan_version TEXT,
            evidence_ids TEXT,
            feature_snapshot TEXT)""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_feedback_domain ON scan_feedback(registrable_domain,label)")
        con.execute("""CREATE TABLE IF NOT EXISTS sensor_learning(
            sensor TEXT PRIMARY KEY,
            tp INTEGER DEFAULT 0, fp INTEGER DEFAULT 0,
            tn INTEGER DEFAULT 0, fn INTEGER DEFAULT 0,
            weight REAL DEFAULT 1.0,
            updated_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS visual_baselines(
            brand TEXT NOT NULL,
            domain TEXT NOT NULL,
            layout_fingerprint TEXT NOT NULL,
            screenshot_dhash TEXT,
            dom_tokens TEXT,
            verified_at TEXT NOT NULL,
            source TEXT NOT NULL,
            PRIMARY KEY(brand,domain,layout_fingerprint))""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_visual_brand ON visual_baselines(brand)")
        con.execute("""CREATE TABLE IF NOT EXISTS calibration_runs(
            run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, version TEXT NOT NULL,
            dataset_name TEXT NOT NULL, total INTEGER NOT NULL,
            tp INTEGER, fp INTEGER, tn INTEGER, fn INTEGER,
            precision REAL, recall REAL, f1 REAL, false_positive_rate REAL, false_negative_rate REAL,
            sensor_report TEXT, notes TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS calibration_models(
            model_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, status TEXT NOT NULL,
            parent_model_id TEXT, weights TEXT NOT NULL, metrics TEXT NOT NULL,
            promotion_reason TEXT, rollback_reason TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS regression_cases(
            case_id TEXT PRIMARY KEY, label TEXT NOT NULL, scenario TEXT NOT NULL,
            expected_min_threat INTEGER, expected_max_threat INTEGER,
            expected_verdict TEXT, fixture TEXT NOT NULL, verified INTEGER DEFAULT 0,
            updated_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS model_snapshots_v30(
            model_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            parent_model_id TEXT,
            status TEXT NOT NULL,
            version TEXT NOT NULL,
            weights TEXT NOT NULL,
            global_metrics TEXT NOT NULL,
            family_metrics TEXT NOT NULL,
            dataset_fingerprint TEXT,
            reason TEXT,
            immutable_hash TEXT NOT NULL)""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_model_status_v30 ON model_snapshots_v30(status,created_at)")
        con.execute("""CREATE TABLE IF NOT EXISTS drift_events_v30(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            window_name TEXT NOT NULL,
            family TEXT NOT NULL,
            baseline_recall REAL,
            current_recall REAL,
            baseline_fpr REAL,
            current_fpr REAL,
            severity TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS rollback_audit_v30(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            from_model TEXT,
            to_model TEXT,
            reason TEXT NOT NULL,
            automatic INTEGER DEFAULT 0)""")
        con.execute("""CREATE TABLE IF NOT EXISTS discovery_queue_v301(
            item_id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            url_hash TEXT NOT NULL,
            source TEXT NOT NULL,
            source_ref TEXT,
            priority INTEGER DEFAULT 50,
            status TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            next_attempt_at TEXT,
            attempts INTEGER DEFAULT 0,
            last_error TEXT,
            UNIQUE(url_hash,source))""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_discovery_status_v301 ON discovery_queue_v301(status,priority,discovered_at)")
        con.execute("""CREATE TABLE IF NOT EXISTS live_observations_v301(
            observation_id TEXT PRIMARY KEY,
            item_id TEXT,
            created_at TEXT NOT NULL,
            url_hash TEXT NOT NULL,
            registrable_domain TEXT,
            predicted_malicious INTEGER NOT NULL,
            predicted_score REAL,
            verdict TEXT,
            threat_families TEXT,
            sensors_fired TEXT,
            evidence_ids TEXT,
            observation_quality TEXT,
            scan_version TEXT NOT NULL,
            ground_truth_status TEXT NOT NULL DEFAULT 'candidate',
            FOREIGN KEY(item_id) REFERENCES discovery_queue_v301(item_id))""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_live_gt_v301 ON live_observations_v301(ground_truth_status,created_at)")
        con.execute("""CREATE TABLE IF NOT EXISTS verified_ground_truth_v301(
            truth_id TEXT PRIMARY KEY,
            observation_id TEXT NOT NULL,
            verified_at TEXT NOT NULL,
            label TEXT NOT NULL,
            family TEXT NOT NULL,
            verifier TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL,
            notes TEXT,
            FOREIGN KEY(observation_id) REFERENCES live_observations_v301(observation_id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS continuous_regression_v301(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            window_name TEXT NOT NULL,
            total INTEGER NOT NULL,
            metrics TEXT NOT NULL,
            family_metrics TEXT NOT NULL,
            sensor_report TEXT NOT NULL,
            dataset_fingerprint TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS discovery_sources_v31(
            source_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            trust_level TEXT NOT NULL,
            config TEXT NOT NULL,
            last_sync TEXT,
            last_error TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS feed_sync_runs_v312(
            run_id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            fetched INTEGER DEFAULT 0,
            accepted INTEGER DEFAULT 0,
            rejected INTEGER DEFAULT 0,
            duplicates INTEGER DEFAULT 0,
            http_status INTEGER,
            etag TEXT,
            last_modified TEXT,
            error TEXT)""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_feed_runs_v312 ON feed_sync_runs_v312(source_id,started_at)")
        con.execute("""CREATE TABLE IF NOT EXISTS feed_sync_state_v312(
            source_id TEXT PRIMARY KEY,
            etag TEXT,
            last_modified TEXT,
            next_sync_at TEXT,
            consecutive_failures INTEGER DEFAULT 0,
            backoff_seconds INTEGER DEFAULT 0,
            last_success_at TEXT,
            last_error TEXT)""")

        con.execute("""CREATE TABLE IF NOT EXISTS hunt_candidates_v31(
            candidate_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            seed_observation_id TEXT,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            relation TEXT NOT NULL,
            confidence REAL NOT NULL,
            depth INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'candidate',
            reason TEXT,
            UNIQUE(indicator_type,indicator_value,seed_observation_id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS threat_campaigns_v313(
            campaign_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            status TEXT NOT NULL,
            confidence REAL NOT NULL,
            threat_families TEXT NOT NULL,
            seed_count INTEGER DEFAULT 0,
            node_count INTEGER DEFAULT 0,
            edge_count INTEGER DEFAULT 0,
            independent_signal_groups INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            summary TEXT,
            fingerprint TEXT UNIQUE)""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_campaign_conf_v313 ON threat_campaigns_v313(status,confidence,updated_at)")
        con.execute("""CREATE TABLE IF NOT EXISTS threat_campaign_members_v313(
            campaign_id TEXT NOT NULL,
            node_type TEXT NOT NULL,
            node_value TEXT NOT NULL,
            role TEXT NOT NULL,
            confidence REAL NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            provenance TEXT,
            PRIMARY KEY(campaign_id,node_type,node_value))""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_campaign_member_v313 ON threat_campaign_members_v313(node_type,node_value)")
        con.execute("""CREATE TABLE IF NOT EXISTS threat_campaign_links_v313(
            campaign_id TEXT NOT NULL,
            from_type TEXT NOT NULL,
            from_value TEXT NOT NULL,
            to_type TEXT NOT NULL,
            to_value TEXT NOT NULL,
            relation TEXT NOT NULL,
            confidence REAL NOT NULL,
            provenance TEXT,
            PRIMARY KEY(campaign_id,from_type,from_value,to_type,to_value,relation))""")
        con.execute("""CREATE TABLE IF NOT EXISTS campaign_detection_runs_v313(
            run_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            seed_type TEXT NOT NULL,
            seed_value TEXT NOT NULL,
            candidates INTEGER DEFAULT 0,
            campaigns INTEGER DEFAULT 0,
            details TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS zero_day_observations_v32(
            observation_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            url_hash TEXT NOT NULL,
            registrable_domain TEXT,
            score REAL NOT NULL,
            confidence REAL NOT NULL,
            verdict TEXT NOT NULL,
            independent_groups INTEGER NOT NULL,
            behavior_families TEXT NOT NULL,
            evidence TEXT NOT NULL,
            known_ioc INTEGER DEFAULT 0,
            scan_version TEXT NOT NULL)""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_zeroday_v32 ON zero_day_observations_v32(verdict,score,created_at)")
        con.execute("""CREATE TABLE IF NOT EXISTS temporal_observations_v3241(
            observation_id TEXT PRIMARY KEY,
            observed_at TEXT NOT NULL,
            url_hash TEXT NOT NULL,
            normalized_url TEXT NOT NULL,
            registrable_domain TEXT,
            final_url TEXT,
            http_status INTEGER,
            title TEXT,
            dom_sha256 TEXT,
            surface_class TEXT NOT NULL,
            credential_surface INTEGER DEFAULT 0,
            proven_sensitive_crossroot INTEGER DEFAULT 0,
            known_ioc INTEGER DEFAULT 0,
            engine_score REAL DEFAULT 0,
            authority TEXT NOT NULL DEFAULT 'observation',
            provenance TEXT,
            scan_version TEXT NOT NULL)""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_temporal_url_v3241 ON temporal_observations_v3241(url_hash,observed_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_temporal_domain_v3241 ON temporal_observations_v3241(registrable_domain,observed_at)")


        con.execute("CREATE INDEX IF NOT EXISTS idx_hunt_status_v31 ON hunt_candidates_v31(status,confidence,created_at)")
        con.execute("""CREATE TABLE IF NOT EXISTS persistence_migrations_v31(
            migration_id TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL,
            backend TEXT NOT NULL,
            details TEXT)""")

def _cache_get(key):
    try:
        _ensure_trust_db()
        with db_connect(DB_PATH, timeout=10) as con:
            row=con.execute("SELECT payload,expires_at FROM trust_cache WHERE cache_key=?",(key,)).fetchone()
        if not row: return None
        if datetime.fromisoformat(row[1]) <= datetime.now(timezone.utc): return None
        return json.loads(row[0])
    except Exception: return None

def _cache_put(key,payload,ttl_hours):
    try:
        _ensure_trust_db()
        key=str(key or '')[:512]  # prevent unbounded cache key length
        exp=(datetime.now(timezone.utc)+timedelta(hours=ttl_hours)).isoformat()
        with db_connect(DB_PATH, timeout=10) as con:
            con.execute("""INSERT INTO trust_cache(cache_key,payload,expires_at) VALUES(?,?,?)
                           ON CONFLICT(cache_key) DO UPDATE SET payload=excluded.payload,expires_at=excluded.expires_at""",
                        (key,json.dumps(payload,ensure_ascii=False),exp))
    except Exception: pass

def tranco_rank_v21(domain):
    try:
        with db_connect(DB_PATH, timeout=8) as con:
            row=con.execute("SELECT rank,updated_at FROM tranco_ranks WHERE domain=?",(registrable_domain_v21(domain),)).fetchone()
        return {"rank":row[0],"updated_at":row[1]} if row else {"rank":None,"updated_at":None}
    except Exception as exc:
        return {"rank":None,"updated_at":None,"error":str(exc)}

def sync_tranco_v21():
    """Manual/local cache refresh. It is intentionally not on the scan critical path."""
    _trust_db_init()
    url=os.getenv("TRANCO_LIST_URL","https://tranco-list.eu/top-1m.csv.zip")
    tmp=tempfile.NamedTemporaryFile(delete=False,suffix=".zip")
    tmp.close(); count=0
    try:
        with requests.get(url,stream=True,timeout=(5,60),headers={"User-Agent":USER_AGENT}) as r:
            r.raise_for_status()
            _tranco_max=200*1024*1024  # 200 MB hard cap
            _tranco_written=0
            with open(tmp.name,"wb") as f:
                for chunk in r.iter_content(1024*1024):
                    if chunk:
                        _tranco_written+=len(chunk)
                        if _tranco_written>_tranco_max:
                            raise ValueError(f"Tranco ZIP download exceeded limit")
                        f.write(chunk)
        now=datetime.now(timezone.utc).isoformat()
        rows=[]
        with zipfile.ZipFile(tmp.name) as z:
            name=next((n for n in z.namelist() if n.lower().endswith(".csv")),None)
            if not name: raise ValueError("Tranco ZIP içinde CSV bulunamadı")
            with z.open(name) as fh:
                for raw in fh:
                    try:
                        rank_s,domain=raw.decode("utf-8","replace").strip().split(",",1)
                        rows.append((registrable_domain_v21(domain),int(rank_s),now))
                    except Exception: continue
                    if len(rows)>=10000:
                        with db_connect(DB_PATH, timeout=30) as con:
                            con.executemany("""INSERT INTO tranco_ranks(domain,rank,updated_at) VALUES(?,?,?)
                              ON CONFLICT(domain) DO UPDATE SET rank=excluded.rank,updated_at=excluded.updated_at""",rows)
                        count+=len(rows); rows=[]
                if rows:
                    with db_connect(DB_PATH, timeout=30) as con:
                        con.executemany("""INSERT INTO tranco_ranks(domain,rank,updated_at) VALUES(?,?,?)
                          ON CONFLICT(domain) DO UPDATE SET rank=excluded.rank,updated_at=excluded.updated_at""",rows)
                    count+=len(rows)
        return {"ok":True,"records":count,"updated_at":now}
    finally:
        try: os.unlink(tmp.name)
        except Exception: pass

def _ensure_trust_db():
    global _TRUST_DB_INITIALIZED
    if _TRUST_DB_INITIALIZED:
        return
    with _TRUST_DB_INIT_LOCK:
        if _TRUST_DB_INITIALIZED:
            return
        try:
            _trust_db_init()
        except Exception:
            pass
        _TRUST_DB_INITIALIZED = True

