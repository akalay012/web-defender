"""Persistent learning and local threat-intelligence stores.

Verified labels and locally persisted IOC observations live here. External feeds
remain sensors and do not become ground truth by being stored.
"""
import json, hashlib, math, threading, sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse
from .database import DATABASE_URL, db_connect
from .analyzer.url_domain import get_root_domain

DB_PATH = __import__("os").getenv(
    "WEB_DEFENDER_DB",
    "/var/data/web_defender.db" if __import__("os").path.isdir("/var/data") else "web_defender.db",
)

class LocalLearningEngine:
    """Harici davranış analizi API'si kullanmayan, yalnızca doğrulanmış yerel etiketlerden öğrenen motor."""
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        return db_connect(self.db_path, timeout=5)

    def _init_db(self):
        with self._connect() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, url_hash TEXT NOT NULL,
                host TEXT, risk_score INTEGER, risk_level TEXT, features_json TEXT NOT NULL,
                verdict TEXT, verified INTEGER NOT NULL DEFAULT 0
            )""")
            con.execute("CREATE INDEX IF NOT EXISTS idx_scans_verified ON scans(verified, verdict)")

    def save_scan(self, scan_id, url, host, risk_score, risk_level, features):
        url_hash = hashlib.sha256(url.encode('utf-8', errors='ignore')).hexdigest()
        with self._connect() as con:
            con.execute("""INSERT INTO scans
                (scan_id, created_at, url_hash, host, risk_score, risk_level, features_json, verdict, verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0)
                ON CONFLICT(scan_id) DO UPDATE SET
                  created_at=excluded.created_at, url_hash=excluded.url_hash, host=excluded.host,
                  risk_score=excluded.risk_score, risk_level=excluded.risk_level,
                  features_json=excluded.features_json""",
                (scan_id, datetime.now(timezone.utc).isoformat(), url_hash, host, int(risk_score),
                 risk_level, json.dumps(features, ensure_ascii=False)))

    def label_scan(self, scan_id, verdict):
        allowed = {"safe", "phishing", "malware", "suspicious"}
        if verdict not in allowed:
            raise ValueError("Geçersiz etiket.")
        with self._connect() as con:
            cur = con.execute("UPDATE scans SET verdict=?, verified=1 WHERE scan_id=?", (verdict, scan_id))
            if cur.rowcount != 1:
                raise ValueError("Scan ID bulunamadı.")

    def stats(self):
        with self._connect() as con:
            total = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            verified = con.execute("SELECT COUNT(*) FROM scans WHERE verified=1").fetchone()[0]
            rows = con.execute("SELECT verdict, COUNT(*) FROM scans WHERE verified=1 GROUP BY verdict").fetchall()
        return {"total_scans": total, "verified_samples": verified, "labels": dict(rows)}

    def predict(self, features):
        """Bernoulli Naive Bayes. Az veri varsa karar üretmez; yanlış güveni önler."""
        with self._connect() as con:
            rows = con.execute("SELECT features_json, verdict FROM scans WHERE verified=1").fetchall()
        samples=[]
        for raw, verdict in rows:
            try: samples.append((json.loads(raw), 0 if verdict == "safe" else 1))
            except Exception: pass
        pos=sum(y for _,y in samples); neg=len(samples)-pos
        if len(samples) < 10 or pos < 3 or neg < 3:
            return {"active": False, "probability": None, "sample_count": len(samples),
                    "reason": "Öğrenme için en az 10 doğrulanmış örnek ve iki sınıfta en az 3 örnek gerekli."}
        keys=sorted(features)
        lp=math.log((pos+1)/(len(samples)+2)); ln=math.log((neg+1)/(len(samples)+2))
        for k in keys:
            x=1 if features.get(k) else 0
            pc=(sum(1 for f,y in samples if y==1 and bool(f.get(k)))+1)/(pos+2)
            nc=(sum(1 for f,y in samples if y==0 and bool(f.get(k)))+1)/(neg+2)
            lp += math.log(pc if x else 1-pc)
            ln += math.log(nc if x else 1-nc)
        m=max(lp,ln); ep=math.exp(lp-m); en=math.exp(ln-m)
        prob=ep/(ep+en)
        return {"active": True, "probability": round(prob,4), "sample_count": len(samples),
                "model": "local_bernoulli_naive_bayes_v1"}

class _LazyLocalLearningEngine:
    """DB bağlantısını Gunicorn import/health aşamasından çıkarır."""
    def __init__(self):
        self._instance = None
        self._lock = threading.Lock()
    def _get(self):
        if self._instance is None:
            with self._lock:
                if self._instance is None:
                    self._instance = LocalLearningEngine()
        return self._instance
    def __getattr__(self, name):
        return getattr(self._get(), name)

LEARNING_ENGINE = _LazyLocalLearningEngine()

class ThreatIntelStore:
    """Web Defender yerel IOC hafızası. Harici feedler sensördür; nihai karar Fusion Engine'indir."""
    def __init__(self, db_path=DB_PATH):
        self.db_path=db_path
        self._init_db()
    def _connect(self):
        con=db_connect(self.db_path, timeout=8)
        # sqlite3.Row is SQLite-only; PGConnection uses HybridRow -- skip for PostgreSQL
        if not DATABASE_URL and hasattr(con,'row_factory'):
            con.row_factory=sqlite3.Row
        return con
    def _init_db(self):
        with self._connect() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS threat_iocs (
                ioc_type TEXT NOT NULL, ioc TEXT NOT NULL, source TEXT NOT NULL,
                threat_type TEXT, malware_family TEXT, confidence INTEGER,
                first_seen TEXT, last_seen TEXT, expires_at TEXT,
                raw_json TEXT, updated_at TEXT NOT NULL,
                PRIMARY KEY(ioc_type,ioc,source)
            )""")
            con.execute("CREATE INDEX IF NOT EXISTS idx_ti_ioc ON threat_iocs(ioc_type,ioc)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_ti_updated ON threat_iocs(updated_at)")
            con.execute("""CREATE TABLE IF NOT EXISTS threat_relations(
                from_type TEXT NOT NULL, from_value TEXT NOT NULL, to_type TEXT NOT NULL, to_value TEXT NOT NULL,
                relation TEXT NOT NULL, source TEXT NOT NULL, confidence REAL DEFAULT 0.5,
                first_seen TEXT, last_seen TEXT, metadata TEXT,
                PRIMARY KEY(from_type,from_value,to_type,to_value,relation,source))""")
            con.execute("CREATE INDEX IF NOT EXISTS idx_rel_from ON threat_relations(from_type,from_value)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_rel_to ON threat_relations(to_type,to_value)")
            con.execute("""CREATE TABLE IF NOT EXISTS threat_intel_sync (
                source TEXT PRIMARY KEY, last_success TEXT, last_attempt TEXT,
                records INTEGER DEFAULT 0, error TEXT
            )""")
            con.execute("""CREATE TABLE IF NOT EXISTS threat_graph_nodes (
                node_type TEXT NOT NULL,value TEXT NOT NULL,label TEXT,confidence INTEGER DEFAULT 0,
                first_seen TEXT,last_seen TEXT,expires_at TEXT,metadata_json TEXT,
                PRIMARY KEY(node_type,value))""")
            con.execute("""CREATE TABLE IF NOT EXISTS threat_graph_edges (
                src_type TEXT NOT NULL,src_value TEXT NOT NULL,relation TEXT NOT NULL,
                dst_type TEXT NOT NULL,dst_value TEXT NOT NULL,source TEXT NOT NULL,
                confidence INTEGER DEFAULT 0,first_seen TEXT,last_seen TEXT,evidence_json TEXT,
                PRIMARY KEY(src_type,src_value,relation,dst_type,dst_value,source))""")
            con.execute("CREATE INDEX IF NOT EXISTS idx_tg_src ON threat_graph_edges(src_type,src_value)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_tg_dst ON threat_graph_edges(dst_type,dst_value)")
    def upsert(self, ioc_type, ioc, source, **kw):
        if not ioc: return
        now=datetime.now(timezone.utc).isoformat()
        raw=kw.get('raw')
        with self._connect() as con:
            con.execute("""INSERT INTO threat_iocs
            (ioc_type,ioc,source,threat_type,malware_family,confidence,first_seen,last_seen,expires_at,raw_json,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ioc_type,ioc,source) DO UPDATE SET
              threat_type=excluded.threat_type, malware_family=excluded.malware_family,
              confidence=excluded.confidence, first_seen=COALESCE(excluded.first_seen,threat_iocs.first_seen),
              last_seen=excluded.last_seen, expires_at=excluded.expires_at,
              raw_json=excluded.raw_json, updated_at=excluded.updated_at""",
            (ioc_type, str(ioc).strip().lower(), source, kw.get('threat_type'), kw.get('malware_family'),
             kw.get('confidence'), kw.get('first_seen'), kw.get('last_seen'), kw.get('expires_at'),
             json.dumps(raw,ensure_ascii=False)[:5000] if raw is not None else None, now))
    def lookup(self, url):
        p=urlparse(url); host=(p.hostname or '').lower(); root=get_root_domain(host) if host else ''
        terms=[('url',url.lower()),('domain',host),('domain',root)]
        ips=[]
        try:
            ips=[str(x) for x in socket.getaddrinfo(host,None) if x and x[4] and x[4][0]]
        except Exception: pass
        terms += [('ip',x) for x in sorted(set(ips))]
        out=[]
        now=datetime.now(timezone.utc).isoformat()
        with self._connect() as con:
            for typ,val in terms:
                if not val: continue
                rows=con.execute("""SELECT * FROM threat_iocs WHERE ioc_type=? AND ioc=?
                    AND (expires_at IS NULL OR expires_at='' OR expires_at>?)""",(typ,val,now)).fetchall()
                out.extend(dict(r) for r in rows)
        # same record may match host/root
        uniq={ (x['ioc_type'],x['ioc'],x['source']):x for x in out }
        return list(uniq.values())
    def lookup_url_domain_ip(self, url, host=None, ips=None):
        """Fast-pipeline compatibility lookup using the canonical local IOC store."""
        try: return self.lookup(url)
        except Exception: return []

    def sync_state(self, source, ok, records=0, error=''):
        now=datetime.now(timezone.utc).isoformat()
        with self._connect() as con:
            con.execute("""INSERT INTO threat_intel_sync(source,last_success,last_attempt,records,error)
            VALUES(?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET
            last_success=CASE WHEN excluded.error='' THEN excluded.last_success ELSE threat_intel_sync.last_success END,
            last_attempt=excluded.last_attempt, records=excluded.records, error=excluded.error""",
            (source,now if ok else None,now,int(records),str(error)[:500]))
    def graph_edge(self,st,sv,rel,dt,dv,source,confidence=0,first_seen=None,last_seen=None,evidence=None):
        sv=str(sv or "").strip().lower(); dv=str(dv or "").strip().lower()
        if not sv or not dv: return
        now=datetime.now(timezone.utc).isoformat()
        with self._connect() as con:
            for typ,val in ((st,sv),(dt,dv)):
                con.execute("""INSERT INTO threat_graph_nodes(node_type,value,confidence,first_seen,last_seen)
                    VALUES(?,?,?,?,?) ON CONFLICT(node_type,value) DO UPDATE SET
                    confidence=MAX(threat_graph_nodes.confidence,excluded.confidence),last_seen=excluded.last_seen""",
                    (typ,val,int(confidence or 0),first_seen or now,last_seen or now))
            con.execute("""INSERT INTO threat_graph_edges(src_type,src_value,relation,dst_type,dst_value,source,confidence,first_seen,last_seen,evidence_json)
                VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(src_type,src_value,relation,dst_type,dst_value,source) DO UPDATE SET
                confidence=MAX(threat_graph_edges.confidence,excluded.confidence),last_seen=excluded.last_seen,evidence_json=excluded.evidence_json""",
                (st,sv,rel,dt,dv,source,int(confidence or 0),first_seen or now,last_seen or now,
                 json.dumps(evidence,ensure_ascii=False)[:5000] if evidence else None))

    def upsert_relation(self,from_type,from_value,to_type,to_value,relation,source="WebDefender",confidence=.6,metadata=None):
        if not all((from_type,from_value,to_type,to_value,relation)): return
        now=datetime.now(timezone.utc).isoformat()
        try:
            with self._connect() as con:
                con.execute("""INSERT INTO threat_relations
                (from_type,from_value,to_type,to_value,relation,source,confidence,first_seen,last_seen,metadata)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(from_type,from_value,to_type,to_value,relation,source) DO UPDATE SET
                confidence=MAX(confidence,excluded.confidence),last_seen=excluded.last_seen,metadata=excluded.metadata""",
                (from_type,str(from_value)[:1000],to_type,str(to_value)[:1000],relation,source,float(confidence),
                 now,now,json.dumps(metadata or {},ensure_ascii=False)[:6000]))
        except Exception: pass

    def graph_neighborhood(self,typ,value,limit=100):
        value=str(value or "").strip().lower()
        with self._connect() as con:
            node=con.execute("SELECT * FROM threat_graph_nodes WHERE node_type=? AND value=?",(typ,value)).fetchone()
            edges=con.execute("""SELECT * FROM threat_graph_edges WHERE (src_type=? AND src_value=?) OR
                (dst_type=? AND dst_value=?) ORDER BY confidence DESC,last_seen DESC LIMIT ?""",
                (typ,value,typ,value,int(limit))).fetchall()
        return {"node":dict(node) if node else None,"edges":[dict(x) for x in edges]}

    def graph_stats(self):
        with self._connect() as con:
            return {"nodes":con.execute("SELECT COUNT(*) FROM threat_graph_nodes").fetchone()[0],
                    "edges":con.execute("SELECT COUNT(*) FROM threat_graph_edges").fetchone()[0],
                    "node_types":[dict(x) for x in con.execute("SELECT node_type,COUNT(*) count FROM threat_graph_nodes GROUP BY node_type ORDER BY count DESC").fetchall()]}

    def lookup_hash(self, sha256):
        h=(sha256 or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}",h): return []
        now=datetime.now(timezone.utc).isoformat()
        with self._connect() as con:
            rows=con.execute("""SELECT * FROM threat_iocs WHERE ioc_type='sha256' AND ioc=? AND (expires_at IS NULL OR expires_at='' OR expires_at>?)""",(h,now)).fetchall()
        return [dict(r) for r in rows]

    def active_count(self):
        now=datetime.now(timezone.utc).isoformat()
        with self._connect() as con:
            return con.execute("SELECT COUNT(*) FROM threat_iocs WHERE expires_at IS NULL OR expires_at='' OR expires_at>?",(now,)).fetchone()[0]

    def expire_old(self):
        now=datetime.now(timezone.utc); changed=0
        limits={"ThreatFox":180,"URLhaus":90}
        with self._connect() as con:
            rows=con.execute("SELECT * FROM threat_iocs WHERE expires_at IS NULL OR expires_at=''").fetchall()
            for r in rows:
                if r["source"] not in limits: continue
                stamp=r["last_seen"] or r["first_seen"] or r["updated_at"]
                try:
                    dt=datetime.fromisoformat(str(stamp).replace("Z","+00:00"))
                    if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
                except Exception: continue
                if (now-dt).total_seconds() > limits[r["source"]]*86400:
                    con.execute("UPDATE threat_iocs SET expires_at=? WHERE ioc_type=? AND ioc=? AND source=?",
                                (now.isoformat(),r["ioc_type"],r["ioc"],r["source"]))
                    changed+=1
        return changed

    def status(self):
        with self._connect() as con:
            count=con.execute('SELECT COUNT(*) FROM threat_iocs').fetchone()[0]
            src=con.execute('SELECT source,COUNT(*) n FROM threat_iocs GROUP BY source').fetchall()
            sync=con.execute('SELECT * FROM threat_intel_sync').fetchall()
        return {'ioc_count':count,'sources':{r['source']:r['n'] for r in src},'sync':[dict(r) for r in sync]}

class _LazyThreatIntelStore:
    """IOC deposunu yalnızca gerçekten gerektiğinde açar; /healthz DB'ye dokunmaz."""
    def __init__(self):
        self._instance = None
        self._lock = threading.Lock()
    def _get(self):
        if self._instance is None:
            with self._lock:
                if self._instance is None:
                    self._instance = ThreatIntelStore()
        return self._instance
    def __getattr__(self, name):
        return getattr(self._get(), name)

THREAT_INTEL_STORE = _LazyThreatIntelStore()
_TI_SYNC_LOCK=threading.Lock()
