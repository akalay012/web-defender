from flask import Flask, request, jsonify, render_template_string
import requests, re, ssl, socket, ipaddress, time, os, json, sqlite3, hashlib, math, uuid, subprocess, sys, tempfile, shutil, difflib, csv, threading, zipfile, io, base64
from bs4 import BeautifulSoup

# Embedded DB compatibility layer: Render-safe single-file boot.
DATABASE_URL=os.getenv("DATABASE_URL","").strip()

def db_backend_name():
    return "postgresql" if DATABASE_URL else "sqlite"

def _pg_sql(sql):
    q=str(sql)
    q=re.sub(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b","BIGSERIAL PRIMARY KEY",q,flags=re.I)
    q=re.sub(r"\bBEGIN\s+IMMEDIATE\b","BEGIN",q,flags=re.I)
    q=q.replace("?", "%s")
    # Generic SQLite INSERT OR IGNORE -> PostgreSQL ON CONFLICT DO NOTHING.
    if re.search(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\b",q,re.I):
        q=re.sub(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\b","INSERT INTO",q,flags=re.I)
        q=q.rstrip().rstrip(";")
        if not re.search(r"\bON\s+CONFLICT\b",q,re.I):
            q += " ON CONFLICT DO NOTHING"
    return q

class HybridRow:
    __slots__=("values","columns","mapping")
    def __init__(self, values, columns):
        self.values=tuple(values); self.columns=tuple(columns)
        self.mapping=dict(zip(self.columns,self.values))
    def __getitem__(self,key):
        return self.mapping[key] if isinstance(key,str) else self.values[key]
    def __iter__(self): return iter(self.values)
    def __len__(self): return len(self.values)
    def keys(self): return self.mapping.keys()

class PGCursor:
    def __init__(self, cur):
        self._cur=cur
    @property
    def rowcount(self): return self._cur.rowcount
    def _cols(self):
        return [d.name if hasattr(d,"name") else d[0] for d in (self._cur.description or [])]
    def fetchone(self):
        r=self._cur.fetchone()
        return None if r is None else HybridRow(r,self._cols())
    def fetchall(self):
        cols=self._cols()
        return [HybridRow(r,cols) for r in self._cur.fetchall()]
    def __iter__(self):
        cols=self._cols()
        for r in self._cur: yield HybridRow(r,cols)

class PGConnection:
    def __init__(self, con):
        self._con=con
        self.row_factory=None  # sqlite compatibility; HybridRow is always dual-access.
    def execute(self, sql, params=()):
        cur=self._con.cursor()
        cur.execute(_pg_sql(sql), tuple(params or ()))
        return PGCursor(cur)
    def executemany(self, sql, seq):
        cur=self._con.cursor()
        cur.executemany(_pg_sql(sql), seq)
        return PGCursor(cur)
    def commit(self): return self._con.commit()
    def rollback(self): return self._con.rollback()
    def close(self): return self._con.close()
    def __enter__(self): return self
    def __exit__(self, typ, val, tb):
        if typ is None: self._con.commit()
        else: self._con.rollback()
        self._con.close()
        return False

def db_connect(sqlite_path=None, timeout=8):
    if not DATABASE_URL:
        return sqlite3.connect(sqlite_path or "web_defender.db", timeout=timeout)
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("DATABASE_URL ayarlı ancak psycopg kurulu değil") from exc
    con=psycopg.connect(DATABASE_URL, connect_timeout=max(1,int(timeout)))
    return PGConnection(con)


try:
    import tldextract
    _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except Exception:
    _TLD_EXTRACT = None
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, urljoin, parse_qsl, unquote_plus, unquote, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

app = Flask(__name__)

APP_NAME = "Web Defender"
APP_VERSION = "V32.5.0"
# V32.4.2 Architecture: Sensors → Raw Observations → Guards → Canonical Evidence Bus
#   → Family Experts → ONE Fusion → ONE Decision Authority → UI
# Changes vs V32.4.1:
#   - calculate_scores no longer independently derives threat score (defers to canonical authority)
#   - run_behavioral_fusion_v17 is diagnostic-only (observation producer, never score producer)
#   - temporal_threat_memory repositioned to post-guard (reads settled findings only)
#   - temporal "internally_observed_hard" requires causal_graph.concrete_exfil, not just path count
#   - get_canonical_root() introduced as single PSL resolver (eliminates get_root_domain/registrable_domain_v21 divergence)
#   - _trust_db_init() is now lazy (no longer blocks startup/healthz on slow PG connections)
#   - SSRF safe_get: added post-connect re-validation (TOCTOU best-effort mitigation)

# Deployment profile:
# This build is intended for PythonAnywhere. Set WEB_DEFENDER_PYTHONANYWHERE=0
# only when deliberately running this same file somewhere else.
RUNNING_ON_PYTHONANYWHERE = os.environ.get("WEB_DEFENDER_PYTHONANYWHERE", "0").strip().lower() not in ("0", "false", "no", "off")


REQUEST_TIMEOUT = 15
MAX_CONTENT_SIZE = 5 * 1024 * 1024
MAX_REDIRECTS = 8
DB_PATH = os.getenv("WEB_DEFENDER_DB", "/var/data/web_defender.db" if os.path.isdir("/var/data") else "web_defender.db")
COMMON_MULTI_SUFFIXES = {"com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp"}
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"
)

# ── Marka listesi ──────────────────────────────────────────────────────────
BRAND_KEYWORDS = [
    "google", "gmail", "youtube", "microsoft", "outlook", "office", "live",
    "apple", "icloud", "facebook", "instagram", "whatsapp", "meta",
    "paypal", "amazon", "aws", "netflix", "twitter", "linkedin",
    "dropbox", "github", "adobe", "steam", "ebay", "bankofamerica",
    "wellsfargo", "chase", "citibank", "garanti", "akbank", "isbank",
    "ziraatbank", "vakifbank", "halkbank", "yapikredi", "dhl",
    "fedex", "ups", "shopee", "trendyol", "hepsiburada", "aliexpress", "temu", "binance", "coinbase", "discord", "telegram", "turkiye", "saglik", "edevlet", "turknet",
    "turkcell", "vodafone", "turktelekom", "btk", "ing",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".online",
    ".site", ".store", ".info", ".biz", ".link", ".click", ".work",
    ".loan", ".win", ".racing", ".download", ".stream", ".gdn", ".icu",
}

LEGITIMATE_BRAND_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "googleapis.com",
    "microsoft.com", "outlook.com", "office.com", "live.com", "bing.com",
    "apple.com", "icloud.com", "facebook.com", "instagram.com",
    "whatsapp.com", "meta.com", "paypal.com", "amazon.com", "amazon.com.tr", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.co.jp", "amazon.ca", "amazon.com.au", "amazon.in", "amazon.com.br", "amazon.com.mx", "amazonaws.com",
    "netflix.com", "twitter.com", "x.com", "linkedin.com", "dropbox.com",
    "github.com", "adobe.com", "steampowered.com", "ebay.com", "shopee.com", "shopee.co.id", "shopee.com.my", "shopee.sg", "shopee.ph", "shopee.co.th", "shopee.vn", "trendyol.com", "hepsiburada.com", "aliexpress.com", "temu.com", "binance.com", "coinbase.com", "discord.com", "telegram.org",
    "garanti.com.tr", "garantibbva.com.tr", "akbank.com", "isbank.com.tr",
    "ziraatbank.com.tr", "vakifbank.com.tr", "halkbank.com.tr",
    "yapikredi.com.tr", "turkcell.com.tr", "vodafone.com.tr",
    "turktelekom.com.tr", "turkiye.gov.tr",
    "ing.com", "ing.com.tr", "ing.de", "ing.nl", "ing.be", "ing.pl", "ing.es",
}


def brand_present(brand, text):
    """Kısa marka adlarında substring false-positive üretmeden marka görünürlüğünü kontrol eder."""
    b=(brand or "").lower().strip(); t=(text or "").lower()
    if not b: return False
    if len(b) <= 3:
        return bool(re.search(r"(?<![a-z0-9])" + re.escape(b) + r"(?![a-z0-9])", t, re.I))
    return b in t

def legitimate_brand_root(brand, root):
    b=(brand or "").lower(); r=(root or "").lower()
    if b == "ing":
        return r in {"ing.com","ing.com.tr","ing.de","ing.nl","ing.be","ing.pl","ing.es"}
    return any(r == d or r.endswith("."+d) for d in LEGITIMATE_BRAND_DOMAINS if b in d)

DANGEROUS_EXTENSIONS = {
    ".exe", ".msi", ".msp", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".apk", ".dll",
    ".iso", ".img", ".lnk", ".reg", ".chm", ".xll", ".appinstaller", ".msix"
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy"
}

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



# ── Yardımcı fonksiyonlar ─────────────────────────────────────────────────

def normalize_url(url):
    url = (url or "").strip()
    if not url:
        raise ValueError("URL boş.")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Geçersiz HTTP/HTTPS URL.")
    if len(url) > 4096:
        raise ValueError("URL çok uzun.")
    return url

def host_is_private(host):
    if not host:
        return True
    h = host.lower().rstrip(".")
    if h in {"localhost", "localhost.localdomain", "metadata",
             "metadata.google.internal", "169.254.169.254"}:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False

def host_is_raw_ip(host):
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def _legacy_root_domain_fallback(hostname):
    """Fallback parser used only when PSL extraction is unavailable."""
    if not hostname:
        return ""
    host = hostname.lower().rstrip(".")
    if host_is_raw_ip(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    suffix2 = ".".join(parts[-2:])
    if suffix2 in COMMON_MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def resolve_public_ips(host):
    """Hostun yalnızca public IP'lere çözümlendiğini doğrular."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    ips = list(dict.fromkeys(i[4][0] for i in infos))
    if not ips:
        raise ValueError("DNS çözümlemesi IP döndürmedi.")
    for raw in ips:
        ip = ipaddress.ip_address(raw)
        if (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise ValueError(f"Private/özel IP hedefi engellendi: {raw}")
    return ips

def read_limited_response(response, limit=MAX_CONTENT_SIZE):
    """Response gövdesini belleğe sınırsız almadan limitli okur."""
    chunks, total = [], 0
    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue
        remaining = limit - total
        if remaining <= 0:
            break
        chunks.append(chunk[:remaining])
        total += min(len(chunk), remaining)
        if total >= limit:
            break
    return b"".join(chunks)

def same_origin(a, b):
    pa, pb = urlparse(a), urlparse(b)
    pa_port = pa.port or (443 if pa.scheme == "https" else 80)
    pb_port = pb.port or (443 if pb.scheme == "https" else 80)
    return pa.scheme == pb.scheme and pa.hostname == pb.hostname and pa_port == pb_port

def severity_weight(sev):
    return {"critical": 40, "high": 25, "medium": 12, "low": 4, "info": 0}.get(sev, 0)

def full_decode(s):
    """Çok katmanlı URL encoding'i tamamen çöz."""
    seen = set()
    while s not in seen:
        seen.add(s)
        decoded = unquote_plus(s)
        if decoded == s:
            break
        s = decoded
    return s


# ═══════════════════════════════════════════════════════════════════════════
# V21 — Trust Context caches. Trust is context, never a safety override.
# ═══════════════════════════════════════════════════════════════════════════
_TRUST_CACHE_LOCK = threading.Lock()
_RDAP_BOOTSTRAP = {"loaded_at": 0.0, "services": []}

# V32.4.2: Canonical single PSL resolver. Always use this for cross-root comparisons.
# get_root_domain() (manual suffix list) and registrable_domain_v21() (tldextract when
# available) could diverge. get_canonical_root() is the single source of truth.
def get_canonical_root(host):
    """Single authoritative registrable-domain resolver.
    Uses tldextract when available; falls back to manual suffix list.
    Always use this for identity, cross-root exfil and destination ownership checks.
    """
    host = (host or "").strip(".").lower()
    if not host or host_is_raw_ip(host): return host
    if _TLD_EXTRACT:
        try:
            x = _TLD_EXTRACT(host)
            result = ".".join(p for p in (x.domain, x.suffix) if p)
            if result: return result
        except Exception:
            pass
    return _legacy_root_domain_fallback(host)

def get_root_domain(host):
    """Compatibility wrapper: all legacy callers use the canonical PSL authority."""
    return get_canonical_root(host)

def registrable_domain_v21(host):
    """Compatibility wrapper for V21 callers; never a second parser."""
    return get_canonical_root(host)

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

# V32.4.2: _trust_db_init() is now lazy. It is called on first use (tranco_rank_v21,
# _cache_get, _cache_put) rather than at import time. This prevents slow PostgreSQL
# connections from blocking the /healthz liveness endpoint during startup.
_TRUST_DB_INITIALIZED = False
_TRUST_DB_INIT_LOCK = threading.Lock()

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

# ═══════════════════════════════════════════════════════════════════════════
class SecurityAnalyzer:
# ═══════════════════════════════════════════════════════════════════════════

    def __init__(self):
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

    # ── Yardımcılar ───────────────────────────────────────────────────────

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

    # ── Güvenli HTTP / redirect takibi ───────────────────────────────────

    def probe_network(self, host):
        """TCP seviyesinde 80/443 portlarını HTTP'den bağımsız test eder.
        Bu sonuç bir tehdit hükmü değildir; yalnızca erişilebilirlik teşhisidir.
        """
        result = {"host": host, "ports": {}, "summary": "completed"}
        for port in (80, 443):
            started = time.perf_counter()
            item = {"port": port, "open": False, "latency_ms": None, "status": "unknown", "error": ""}
            try:
                # Önce DNS/IP güvenlik doğrulaması. Private/special hedeflere probe yapılmaz.
                resolve_public_ips(host)
                with socket.create_connection((host, port), timeout=3):
                    item["open"] = True
                    item["status"] = "open"
            except socket.timeout as exc:
                item["status"] = "timeout"
                item["error"] = str(exc) or "timeout"
            except ConnectionRefusedError as exc:
                item["status"] = "refused"
                item["error"] = str(exc)
            except OSError as exc:
                item["status"] = "network_error"
                item["error"] = str(exc)
            item["latency_ms"] = round((time.perf_counter()-started)*1000, 2)
            if RUNNING_ON_PYTHONANYWHERE:
                item["authoritative"] = False
                item["display_status"] = "hosting_unverified"
                item["note"] = "PythonAnywhere raw TCP sonucu hedef sunucunun gerçek port durumu olarak yorumlanmaz."
            else:
                item["authoritative"] = True
                item["display_status"] = item["status"]
            result["ports"][str(port)] = item
        result["authoritative"] = not RUNNING_ON_PYTHONANYWHERE
        self.results["network_probe"] = result

    def safe_get(self, session, url, timeout=REQUEST_TIMEOUT, max_redirects=MAX_REDIRECTS):
        current = url
        history = []
        for _ in range(max_redirects + 1):
            p = urlparse(current)
            if p.scheme not in ("http", "https") or not p.hostname:
                raise ValueError("Redirect geçersiz bir hedefe gidiyor.")
            # V32.4.2: Two-stage SSRF guard (TOCTOU mitigation).
            # Stage 1: Validate that all resolved IPs are public before connecting.
            # Stage 2: Re-validate after the connection attempt if the response
            # triggers a redirect to a new host (handled by next loop iteration).
            # Note: requests internally re-resolves the hostname; a fast-flipping
            # DNS entry could theoretically bypass stage 1. Full mitigation requires
            # binding to the pre-resolved IP, which is left for a network-layer
            # control (e.g. an egress firewall / allow-list) in production.
            resolve_public_ips(p.hostname)
            # Additional guard: reject if hostname resolves to a private range
            # at connection time by checking again post-resolve (best-effort).
            try:
                _post_ips = socket.getaddrinfo(p.hostname, None, type=socket.SOCK_STREAM)
                for _ai in _post_ips:
                    _ip_str = _ai[4][0]
                    _ip_obj = ipaddress.ip_address(_ip_str)
                    if (_ip_obj.is_private or _ip_obj.is_loopback or
                            _ip_obj.is_link_local or _ip_obj.is_reserved):
                        raise ValueError(f"SSRF: hostname re-resolved to private IP {_ip_str}")
            except ValueError:
                raise
            except Exception:
                pass  # DNS failure here is handled by the subsequent request
            r = session.get(current, timeout=timeout, allow_redirects=False,
                            verify=True, stream=True)
            if r.status_code not in (301, 302, 303, 307, 308):
                return r, history, current
            location = r.headers.get("Location")
            if not location:
                return r, history, current
            target = urljoin(current, location)
            tp = urlparse(target)
            if tp.scheme not in ("http", "https") or not tp.hostname:
                r.close()
                raise ValueError("Redirect HTTP/HTTPS dışı veya geçersiz hedefe gidiyor.")
            resolve_public_ips(tp.hostname)
            history.append({
                "status": r.status_code, "from": current,
                "location": location, "target": target,
                "external": not same_origin(current, target),
            })
            r.close()
            current = target
        raise requests.TooManyRedirects(f"{max_redirects} redirect sınırı aşıldı.")

    def fetch_with_scheme_fallback(self, session, url):
        """Try requested URL first. If HTTPS transport itself cannot be established,
        optionally probe the same host/path over HTTP. The fallback is explicit in
        results and never treated as equivalent HTTPS security.
        """
        attempts = []
        candidates = [url]
        p = urlparse(url)
        if p.scheme == "https":
            http_url = p._replace(scheme="http", netloc=(p.hostname or "") + ((":" + str(p.port)) if p.port and p.port not in (443, 80) else "")).geturl()
            candidates.append(http_url)

        last_exc = None
        for idx, candidate in enumerate(candidates):
            try:
                r, history, final = self.safe_get(session, candidate)
                attempts.append({"url": candidate, "ok": True, "status": r.status_code})
                return r, history, final, attempts, (idx > 0)
            except (requests.ConnectionError, requests.Timeout, ssl.SSLError, OSError) as exc:
                last_exc = exc
                attempts.append({"url": candidate, "ok": False, "error": str(exc)[:300]})
        if last_exc:
            raise last_exc
        raise requests.ConnectionError("HTTP/HTTPS bağlantısı kurulamadı.")

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

    # ── İzole Browser Worker ───────────────────────────────────────────────

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

    def run_browser_worker(self, url, timeout=42):
        """Chromium/Playwright'i ayrı bir Python prosesinde çalıştırır.
        Ana Flask prosesi şüpheli sayfanın JavaScript'ini çalıştırmaz.
        Worker ephemeral context kullanır, indirmeleri reddeder ve private/special
        hedeflere giden istekleri route seviyesinde engeller.
        """
        defender = self.results.setdefault("defender", {})
        b = self.results.setdefault("browser", {
            "attempted": False, "available": None, "success": False,
            "status_code": None, "final_url": "", "title": "",
            "dom_length": 0, "requests": [], "blocked_requests": [],
            "console_errors": [], "error": "", "duration_ms": None
        })
        defender["browser"] = b
        b["attempted"] = True
        started = time.perf_counter()
        try:
            python_bin = self.resolve_worker_python()
            b["python_interpreter"] = python_bin or ""
            if not python_bin:
                b["available"] = False
                b["decision"] = "python_interpreter_unavailable"
                b["error"] = "Browser Worker için gerçek Python interpreter bulunamadı."
                return

            import tempfile
            checkpoint_path = os.path.join(tempfile.gettempdir(), f"wd-browser-{os.getpid()}-{threading.get_ident()}-{int(time.time()*1000)}.json")
            try:
                proc = subprocess.run(
                    [python_bin, os.path.abspath(__file__), "--browser-worker", url, checkpoint_path],
                    capture_output=True, text=True, timeout=timeout,
                    env={**os.environ, "WEB_DEFENDER_WORKER": "1", "WEB_DEFENDER_PYTHONANYWHERE": "1" if RUNNING_ON_PYTHONANYWHERE else "0"}
                )
                raw = (proc.stdout or "").strip()
            except subprocess.TimeoutExpired as exc:
                payload = {}
                try:
                    if os.path.isfile(checkpoint_path):
                        with open(checkpoint_path, "r", encoding="utf-8") as fh:
                            payload = json.load(fh)
                except Exception:
                    payload = {}
                payload.update({"success": False, "decision": "browser_timeout", "failure_kind": "parent_worker_deadline",
                                "error": f"Browser worker {timeout}s ana proses zaman sınırına ulaştı; son checkpoint korundu.",
                                "partial_observation": bool(payload)})
                b.update(payload)
                b["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
                self.results["errors"].append({"module":"browser_worker","error":payload["error"]})
                return None
            finally:
                try:
                    if os.path.isfile(checkpoint_path): os.unlink(checkpoint_path)
                except Exception:
                    pass
            if not raw:
                raise RuntimeError((proc.stderr or "Browser worker çıktı üretmedi.")[-800:])
            payload = json.loads(raw.splitlines()[-1])
            b.update(payload)
            b["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
            if not payload.get("success"):
                self.results["errors"].append({
                    "module": "browser_worker",
                    "error": payload.get("error") or "Browser analizi başarısız."
                })
                return None

            html = payload.get("html", "")
            final_url = payload.get("final_url") or url
            if html:
                # Render edilmiş DOM'u mevcut motorlara besle.
                self.results["final_url"] = final_url
                self.results["http"]["body_analyzed"] = True
                self.results["http"]["content_trusted_for_analysis"] = True
                self.results["http"]["access_restricted"] = False
                self.results["http"]["decision"] = "content_analyzable_via_browser"
                self.results["http"]["reachable"] = True
                self.results["http"]["status_code"] = payload.get("status_code")
                self.results["http"]["reason"] = "BROWSER"
                self.results["http"]["content_length"] = len(html.encode("utf-8", errors="ignore"))
                self.results["http"]["network_mode"] = (
                    "pythonanywhere-browser-worker" if RUNNING_ON_PYTHONANYWHERE
                    else "isolated-browser-worker"
                )
                self.results["defender"]["content_status"] = "browser_analyzed"
                self.results["defender"]["passive_only"] = False

                # Browser sonunda login/auth/verify/payment yüzeyine geçiş ayrıca gözlemlenir.
                initial_path=(urlparse(url).path or "/").lower()
                final_path=(urlparse(final_url).path or "/").lower()
                auth_words=("login","signin","sign-in","auth","verify","verification","account","wallet","payment","checkout","otp")
                if final_url != url and any(w in final_path for w in auth_words) and not any(w in initial_path for w in auth_words):
                    self.add_finding(
                        "Tarayıcı giriş/doğrulama sayfasına yönlendirildi", "medium",
                        "Başlangıç adresi tarayıcı çalıştıktan sonra giriş, doğrulama veya ödeme bağlamlı bir yola geçti. Bu tek başına saldırı kanıtı değildir; diğer kimlik bilgisi ve marka sinyalleriyle birlikte değerlendirilir.",
                        "redirect", f"Başlangıç: {url}\nFinal: {final_url}", 0.86)

                self.run_check("browser_html", self.check_html, html, final_url)
                self.run_check("browser_patterns", self.check_suspicious_patterns, html)
                self.run_check("browser_mixed", self.check_mixed_content, html, final_url)
                self.run_check("browser_phishing", self.check_page_phishing_signals, html, final_url)
                self.run_check("browser_defender", self.check_advanced_defender, html, final_url)

                reqs = payload.get("requests") or []
                external = []
                base_root = get_root_domain(urlparse(final_url).hostname or "")
                for q in reqs:
                    try:
                        qh = urlparse(q.get("url","")).hostname or ""
                        if qh and get_root_domain(qh) != base_root:
                            external.append(q)
                    except Exception:
                        pass
                if external:
                    self.add_finding(
                        "Browser: harici ağ istekleri gözlendi", "low",
                        f"Render sırasında {len(external)} farklı-origin ağ isteği gözlendi.",
                        "behavior",
                        "\n".join(x.get("url","")[:220] for x in external[:12]),
                        0.65
                    )

                # V13.7 Runtime korelasyon: form hedefi, gerçek POST trafiği, iframe, DOM ve JS gizleme.
                forms = payload.get("forms") or []
                runtime_writes = [q for q in reqs if str(q.get("method","")).upper() in ("POST","PUT","PATCH")]
                cred_forms = [f for f in forms if f.get("has_password") or f.get("has_otp") or f.get("has_card")]
                cross_forms=[]
                for f in cred_forms:
                    try:
                        ar=get_root_domain(urlparse(str(f.get("action", ""))).hostname or "")
                        if ar and ar != base_root: cross_forms.append(f)
                    except Exception: pass
                if cross_forms:
                    self.add_finding("Runtime credential formu harici domaine gidiyor", "critical",
                        "Render edilmiş DOM'daki parola/OTP/kart formunun action hedefi farklı kök domainde.",
                        "credential_theft", "\n".join(str(x.get("action",""))[:300] for x in cross_forms[:8]), .99)

                matches=[]
                for f in cross_forms:
                    try:
                        fa=urlparse(str(f.get("action",""))); fh=(fa.hostname or "").lower(); fp=(fa.path or "/").rstrip("/")
                    except Exception: continue
                    for q in runtime_writes:
                        try:
                            qu=urlparse(str(q.get("url",""))); qh=(qu.hostname or "").lower(); qp=(qu.path or "/").rstrip("/")
                        except Exception: continue
                        if fh and fh==qh and (not fp or qp==fp or qp.startswith(fp)):
                            matches.append(q); break
                if matches:
                    self.add_finding("Credential form hedefi runtime trafikte doğrulandı", "critical",
                        "Hassas formun harici action hedefi ile tarayıcıda gözlenen veri gönderme isteği eşleşti.",
                        "credential_theft", "\n".join(f'{x.get("method")} {x.get("url","")[:300]}' for x in matches[:8]), .995)

                frames=payload.get("frames") or []; ext_frames=[]
                for fr in frames:
                    try:
                        rr=get_root_domain(urlparse(str(fr.get("src",""))).hostname or "")
                        if rr and rr != base_root: ext_frames.append(fr)
                    except Exception: pass
                if any(any(w in str(x.get("src","")).lower() for w in ("login","signin","auth","verify","otp","payment","wallet")) for x in ext_frames):
                    self.add_finding("Harici credential iframe zinciri", "high",
                        "Farklı kök domainden giriş/doğrulama/ödeme bağlamlı iframe yüklendi.", "phishing",
                        "\n".join(str(x.get("src",""))[:300] for x in ext_frames[:8]), .90)

                dm=payload.get("dom_mutations") or {}
                if int(dm.get("password_fields_added",0) or 0)>0:
                    self.add_finding("JavaScript sonrası parola alanı oluşturuldu", "high",
                        "Sayfa yüklenirken JavaScript DOM'a yeni parola alanı ekledi.", "javascript", str(dm), .90)
                ss=payload.get("script_signals") or {}
                obf_pts=min(int(ss.get("long_encoded_blobs",0) or 0),3)*2 + min(int(ss.get("hex_escape_blobs",0) or 0),3)*2 + min(int(ss.get("eval_like",0) or 0),3)*2 + min(int(ss.get("decoder_like",0) or 0),3)
                if obf_pts >= 6:
                    self.add_finding("Yoğun obfuscated JavaScript", "high",
                        "Birden fazla kod gizleme/çözme göstergesi runtime DOM içinde birlikte bulundu.", "javascript", str(ss), .90)

                # V14 runtime semantic phishing: görünür marka + hassas alan + domain uyumsuzluğu.
                sem=payload.get("semantic_dom") or {}
                sem_blob=" ".join([str(sem.get("title", "")), " ".join(sem.get("headings") or []),
                                   " ".join(sem.get("buttons") or []), str(sem.get("visible_text", ""))]).lower()
                claimed_runtime=[]
                for brand in BRAND_KEYWORDS:
                    if brand_present(brand, sem_blob) and not legitimate_brand_root(brand, base_root):
                        claimed_runtime.append(brand)
                sensitive_inputs=[]
                for inp in sem.get("inputs") or []:
                    blob=" ".join(str(inp.get(k,"")) for k in ("type","name","id","placeholder","autocomplete","label")).lower()
                    if inp.get("type")=="password" or re.search(r"otp|one.?time|verification|pin|cvv|cvc|cc-number|card|kart|iban|password|parola|şifre", blob, re.I):
                        sensitive_inputs.append(inp)
                if claimed_runtime:
                    self.add_finding("Runtime DOM'da marka/domain uyumsuzluğu", "high",
                        "Tarayıcıda render edilen görünür içerik tanınan bir marka adı kullanıyor ancak registrable domain markanın bilinen domaini değil.",
                        "phishing", f"host={base_root}; brands={', '.join(sorted(set(claimed_runtime))[:8])}", .92)
                if claimed_runtime and sensitive_inputs:
                    self.add_finding("Runtime marka taklidi + hassas bilgi isteme", "critical",
                        "Render edilmiş sayfa marka/domain uyumsuzluğu ile parola/OTP/kart benzeri hassas alanları birlikte içeriyor.",
                        "credential_theft", f"brands={claimed_runtime[:8]}; sensitive_fields={len(sensitive_inputs)}", .98)
                hooks=payload.get("runtime_hooks") or {}
                runtime_dest=(hooks.get("fetches") or [])+(hooks.get("xhr") or [])+(hooks.get("beacons") or [])+(hooks.get("form_submits") or [])
                ext_runtime=[]
                for rq in runtime_dest:
                    try:
                        rr=get_root_domain(urlparse(urljoin(final_url,str(rq.get("url") or rq.get("action") or ""))).hostname or "")
                        if rr and rr != base_root: ext_runtime.append(rq)
                    except Exception: pass
                if sensitive_inputs and ext_runtime:
                    self.add_finding("Hassas alan + harici runtime veri hedefi", "critical",
                        "Sayfada hassas giriş alanları bulunurken JavaScript/runtime trafiğinde farklı kök domaine giden veri hedefleri gözlendi.",
                        "credential_theft", str(ext_runtime[:8])[:1800], .97)

                for dl in payload.get("downloads") or []:
                    sh=str(dl.get("sha256") or "").lower()
                    if not re.fullmatch(r"[0-9a-f]{64}",sh): continue
                    hm=THREAT_INTEL_STORE.lookup_hash(sh)
                    if hm:
                        self.add_finding("İndirilen dosya SHA-256 IOC eşleşmesi","critical",
                            "İndirmenin SHA-256 özeti aktif malware IOC hafızasıyla eşleşti.","malware",
                            json.dumps({"sha256":sh,"filename":dl.get("suggested_filename"),"sources":[x.get("source") for x in hm]},ensure_ascii=False),.999)
                    else:
                        self.add_finding("İndirilen dosya SHA-256 hesaplandı","low",
                            "Dosya çalıştırılmadan SHA-256 özeti çıkarıldı; aktif yerel IOC eşleşmesi yok.","behavior",
                            json.dumps({"sha256":sh,"filename":dl.get("suggested_filename"),"size":dl.get("size")},ensure_ascii=False),.55)

                if len(payload.get("popups") or []) >= 2:
                    self.add_finding("Yoğun popup davranışı", "medium", "Sayfa yüklenirken birden fazla popup açma girişimi gözlendi.", "behavior", str(payload.get("popups")[:8]), .75)

                return html
        except subprocess.TimeoutExpired:
            b["available"] = True
            b["success"] = False
            b["decision"] = "browser_timeout"
            b["failure_kind"] = "parent_worker_deadline"
            b["timeout_seconds"] = timeout
            b["error"] = f"Browser worker {timeout}s zaman aşımına uğradı; HTTP/statik analiz korunuyor."
            b["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
            self.results["errors"].append({"module": "browser_worker", "error": b["error"]})
        except Exception as exc:
            b["error"] = str(exc)
            b["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
            self.results["errors"].append({"module": "browser_worker", "error": str(exc)})
        return None

    def finalize_content_acquisition_v32316(self, original_url):
        """Unifies what the engine actually managed to observe.

        This is an observation authority, not a WAF bypasser. It never solves
        CAPTCHAs, submits forms, changes identity, or treats a protected host as
        safe. It simply records which independent acquisition surface produced
        a real 2xx target body and which analyzers therefore had evidence.
        """
        http=self.results.get("http") or {}
        browser=self.results.get("browser") or {}
        recovery=self.results.get("observation_recovery_v32315") or {"attempted":False}
        hs=http.get("status_code"); bs=browser.get("status_code")
        try: hs=int(hs) if hs is not None else None
        except Exception: hs=None
        try: bs=int(bs) if bs is not None else None
        except Exception: bs=None
        http_body=bool(http.get("content_trusted_for_analysis") and hs is not None and 200 <= hs < 300)
        browser_body=bool(browser.get("success") and bs is not None and 200 <= bs < 300 and int(browser.get("dom_length") or 0)>0)
        body_observed=bool(http_body or browser_body)
        bdec=str(browser.get("decision") or browser.get("failure_kind") or "").lower()
        hdec=str(http.get("decision") or http.get("failure_kind") or "").lower()
        status=hs if hs is not None else bs
        challenge_status=status in {401,403,406,409,418,423,425,429,451}
        browser_blocked=any(x in bdec for x in ("timeout","challenge","blocked","access_restricted","deadline"))
        if body_observed:
            state="content_observed"
            display="Gerçek hedef içeriği gözlemlendi"
        elif challenge_status and browser_blocked:
            state="access_protection_or_challenge"
            display="Hedef erişim koruması / bot-WAF benzeri erişim kısıtı"
        elif challenge_status:
            state="http_access_restricted"
            display="HTTP erişim kısıtı"
        elif "timeout" in bdec:
            state="browser_timeout"
            display="Tarayıcı gözlemi zaman aşımına uğradı"
        elif status is not None and 400 <= status < 500:
            state="target_4xx_unavailable"
            display="Hedef içerik 4xx yanıtı nedeniyle alınamadı"
        elif status is not None and status >= 500:
            state="upstream_error"
            display="Hedef/upstream sunucu hatası"
        elif "network" in bdec or hdec in ("connection","proxy","tls"):
            state="network_observation_failure"
            display="Ağ/transport gözlemi tamamlanamadı"
        else:
            state="content_unverified"
            display="Hedef içerik doğrulanamadı"

        sem=browser.get("semantic_dom") or {}
        hooks=browser.get("runtime_hooks") or {}
        forms=browser.get("forms") or self.results.get("forms") or []
        scripts=(browser.get("script_signals") or {})
        analyzers={
            "url_domain": True,
            "dns_tls": True,
            "threat_intel": True,
            "static_html": bool(body_observed and self.results.get("static_semantic_v3232") is not None),
            "static_javascript": bool(body_observed and self.results.get("static_source_intelligence_v32317") is not None),
            "dom_semantics": browser_body,
            "forms_inputs": browser_body,
            "runtime_network": browser_body,
            "visual_runtime": browser_body,
        }
        out={
            "state":state,"display_name":display,"body_observed":body_observed,
            "http_body_observed":http_body,"browser_body_observed":browser_body,
            "http_status":hs,"browser_status":bs,
            "http_decision":http.get("decision") or "","browser_decision":browser.get("decision") or "",
            "bytes_observed":int(http.get("content_length") or 0) if http_body else 0,
            "dom_bytes_observed":int(browser.get("dom_length") or 0) if browser_body else 0,
            "final_url":browser.get("final_url") or self.results.get("final_url") or original_url,
            "recovery":recovery,
            "surface_inventory":{
                "forms":len(forms),"inputs":len(sem.get("inputs") or []),
                "frames":len(browser.get("frames") or []),"network_requests":len(browser.get("requests") or []),
                "runtime_hooks":sum(len(x) for x in hooks.values() if isinstance(x,list)),
                "script_signal_groups":len([k for k,v in scripts.items() if v]),
                "dom_mutations":sum(int(v or 0) for v in (browser.get("dom_mutations") or {}).values() if isinstance(v,(int,float))),
            },
            "analyzers":analyzers,
            "blind_spots":[k for k,v in analyzers.items() if not v],
            "rules":[
                "A 4xx/WAF/challenge body is never analyzed as if it were the target application.",
                "Access protection never suppresses independent URL/domain/IOC/DNS/TLS evidence.",
                "No CAPTCHA bypass, form submission, credential entry, or exploit is performed.",
                "Feed evidence is a sensor; content acquisition and behavioral analysis remain independent engine surfaces."
            ]
        }
        self.results["content_acquisition_v32316"]=out
        # Upgrade the older source report so diagnostics have one coherent view.
        self.results["source_analysis_v32315"]={
            "body_observed":body_observed,
            "bytes_observed":out["bytes_observed"]+out["dom_bytes_observed"],
            "static_code_analysis_available":body_observed,
            "reason":state,"recovery":recovery,
            "rule":"Source/DOM/JS claims require a real observed 2xx target body."
        }
        return out

    # ── Ana analiz ────────────────────────────────────────────────────────

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

    def check_url_intelligence(self, url):
        p = urlparse(url)
        host  = p.hostname or ""
        path  = p.path
        query = p.query

        # Çok katmanlı decode
        decoded_full = full_decode(url)
        double_encoded = decoded_full != url
        self.results["url_intelligence"]["double_encoded"] = double_encoded
        if double_encoded:
            self.add_finding(
                "Çok katmanlı URL encoding", "high",
                "URL birden fazla kez encode edilmiş. Güvenlik filtrelerini atlatmak için kullanılan bir tekniktir.",
                "url",
                f"Orijinal : {url[:200]}\nDecode   : {decoded_full[:200]}",
                0.93,
            )

        # Parametreleri decode edilmiş query ile çözümle
        decoded_query = full_decode(query)
        params = parse_qsl(decoded_query, keep_blank_values=True) or \
                 parse_qsl(query,         keep_blank_values=True)

        tracking_re = re.compile(
            r"^(utm_[a-z0-9_]+|gclid|fbclid|msclkid|ref|referrer|"
            r"affiliate|aff|campaign|click|pid|tracking)$", re.I,
        )
        # ── GENİŞLETİLMİŞ redirect regex — followup, next, service vs. dahil ──
        redirect_re = re.compile(
            r"^(url|uri|u|next|redirect|redirect_uri|return|return_to|"
            r"continue|dest|destination|target|goto|followup|follow_up|"
            r"after|after_login|success_url|callback|redir|r|forward|"
            r"location|link|out|exit|ref_url|service|from|back|jump|"
            r"forward_url|returnurl|redirecturl|nexturl|landingpage)$",
            re.I,
        )
        sensitive_re = re.compile(
            r"(token|secret|password|passwd|api[_-]?key|session|auth|"
            r"credential|access_token|refresh_token|private|apikey|key)$",
            re.I,
        )

        brand_in_params = []
        for k, v in params:
            decoded_v = full_decode(v)
            encoded   = decoded_v != v
            self.results["url_intelligence"]["parameters"].append({
                "name": k, "value_preview": decoded_v[:200], "encoded": encoded,
            })
            if encoded:
                self.results["url_intelligence"]["encoded_parameters"].append(k)
            if tracking_re.match(k):
                self.results["url_intelligence"]["tracking_parameters"].append(k)
            if redirect_re.match(k):
                self.results["url_intelligence"]["redirect_parameters"].append(k)
            if sensitive_re.search(k):
                self.results["url_intelligence"]["sensitive_parameter_names"].append(k)
                self.add_finding(
                    f"Hassas parametre adı URL'de görünüyor: {k}", "medium",
                    "Sorgu parametresinde kimlik/oturum bilgisi içerebilecek isim tespit edildi.",
                    "url", k, 0.85,
                )
            for brand in BRAND_KEYWORDS:
                if brand_present(brand, decoded_v):
                    brand_in_params.append(f"{k}={brand}")

        self.results["url_intelligence"]["brand_in_params"] = list(set(brand_in_params))
        self.results["url_intelligence"]["path"]        = path
        self.results["url_intelligence"]["query_count"] = len(params)

        # Giriş sayfası sinyali
        login_re = re.compile(
            r"(signin|sign.in|login|log.in|logon|auth|authenticate|"
            r"account|verify|verification|secure|security|banking|"
            r"giri[sş]|uyelik|üyelik)",
            re.I,
        )
        self.results["url_intelligence"]["login_page"] = (
            bool(login_re.search(path)) or bool(login_re.search(decoded_full))
        )

        # Path içindeki marka adları
        brand_in_path = [b for b in BRAND_KEYWORDS if b in (path + decoded_full).lower()]
        self.results["url_intelligence"]["brand_in_path"] = list(set(brand_in_path))

        # ── Credential Harvesting tespiti ──────────────────────────────────
        # IP/sahte host + gerçek markaya yönlendiren redirect parametresi
        rp_keys = self.results["url_intelligence"]["redirect_parameters"]
        if rp_keys:
            rp_values = " ".join(
                full_decode(v)
                for k, v in params
                if redirect_re.match(k)
            )
            trusted_dest = any(ld in rp_values.lower() for ld in LEGITIMATE_BRAND_DOMAINS)
            is_fake_host = host_is_raw_ip(host) or \
                           get_root_domain(host) not in LEGITIMATE_BRAND_DOMAINS

            if trusted_dest and is_fake_host:
                self.add_finding(
                    "Credential Harvesting: Güvenilir siteye yönlendirme tuzağı", "critical",
                    "Sahte/IP host üzerinden gerçek bir marka sitesine yönlendiren parametre bulundu. "
                    "Bilgi çalındıktan sonra gerçek siteye yönlendiren klasik phishing tekniğidir.",
                    "phishing",
                    f"Host: {host} | Redirect params: {', '.join(rp_keys)} | Değer: {rp_values[:300]}",
                    0.97,
                )
            else:
                self.add_finding(
                    "Potansiyel yönlendirme parametresi", "medium",
                    "URL'de dış yönlendirme amacıyla kullanılabilen parametre adı bulundu.",
                    "url", ", ".join(rp_keys), 0.75,
                )

        # Şüpheli TLD
        tld = "." + host.split(".")[-1] if "." in host else ""
        if tld.lower() in SUSPICIOUS_TLDS:
            self.results["url_intelligence"]["suspicious_tld"] = True
            self.add_finding(
                f"Şüpheli TLD: {tld}", "medium",
                "Bu TLD phishing ve kötü amaçlı siteler tarafından yoğun şekilde kullanılır.",
                "domain", host, 0.75,
            )

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 2 — PHİSHİNG HEURİSTİKLERİ
    # ═══════════════════════════════════════════════════════════════════════

    def check_phishing_heuristics(self, url):
        p           = urlparse(url)
        host        = p.hostname or ""
        path        = p.path
        is_ip       = host_is_raw_ip(host)
        root        = get_root_domain(host)
        decoded_url = full_decode(url)
        scheme      = p.scheme.lower()

        score   = 0
        signals = []

        # 1. Ham IP adresi
        if is_ip:
            score += 40
            signals.append(f"Ham IP adresi: {host}")
            self.add_finding(
                "Ham IP adresi ile erişim", "critical",
                "Meşru kurumsal siteler asla ham IP adresi üzerinden hizmet vermez. "
                "Phishing/malware altyapısının güçlü göstergesidir.",
                "phishing", f"Host: {host}", 0.95,
            )

        # 2. HTTP + login sayfası
        login_re = re.compile(
            r"(signin|sign.in|login|auth|account|verify|secure|giri[sş])", re.I,
        )
        if scheme == "http" and login_re.search(decoded_url):
            score += 35
            signals.append("HTTP üzerinden kimlik doğrulama sayfası")
            self.add_finding(
                "HTTP üzerinden giriş/kimlik doğrulama sayfası", "critical",
                "Şifresiz HTTP bağlantısı üzerinden giriş sayfası sunuluyor. "
                "Kimlik bilgileri ağda açık metin olarak iletilir.",
                "phishing", f"Scheme: {scheme} | Path: {path}", 1.0,
            )

        # 3. Marka taklidi (domain impersonation)
        found_brands = []
        for brand in BRAND_KEYWORDS:
            bc = brand.replace("-", "").replace(".", "")
            hc = host.replace("-",  "").replace(".", "")
            if bc in hc:
                real = any(
                    host.endswith(ld) or root == ld
                    for ld in LEGITIMATE_BRAND_DOMAINS
                    if brand_present(brand, ld)
                )
                if not real:
                    found_brands.append(brand)

        if found_brands:
            score += 35
            signals.append(f"Marka taklidi: {', '.join(found_brands)}")
            self.add_finding(
                f"Marka taklidi (Domain Impersonation): {', '.join(found_brands)}", "critical",
                "Domain adı tanınan bir markayı taklit ediyor ancak gerçek domain değil. "
                "Typosquatting veya brand impersonation saldırısının göstergesidir.",
                "phishing",
                f"Host: {host} | Markalar: {', '.join(found_brands)}",
                0.95,
            )

        # 4. Marka adı path/param'da var ama host IP/sahte
        brand_in_path   = self.results["url_intelligence"].get("brand_in_path",   [])
        brand_in_params = self.results["url_intelligence"].get("brand_in_params",  [])
        all_refs        = brand_in_path + brand_in_params

        if all_refs and (is_ip or root not in LEGITIMATE_BRAND_DOMAINS):
            score += 30
            signals.append(f"IP/sahte host + path/param'da marka: {', '.join(set(all_refs))}")
            already = any(
                f["title"].startswith("Credential Harvesting")
                for f in self.results["findings"]
            )
            if not already:
                self.add_finding(
                    "Marka referansı + sahte host (Phishing Tuzağı)", "critical",
                    "Sahte veya IP tabanlı bir host üzerinden tanınan marka adlarına atıf yapılıyor. "
                    "Kullanıcıyı kandırmak için tasarlanmış phishing tekniğidir.",
                    "phishing",
                    f"Host: {host} | Refs: {', '.join(set(all_refs))[:300]}",
                    0.96,
                )

        # 5. URL uzunluğu
        if len(url) > 100:
            score += 5
            signals.append(f"Uzun URL ({len(url)} karakter)")

        # 6. Aşırı alt domain
        subdomain_count = len(host.split(".")) - 2 if not is_ip else 0
        if subdomain_count >= 3:
            score += 15
            signals.append(f"Çok sayıda alt domain ({subdomain_count})")
            self.add_finding(
                "Aşırı alt domain kullanımı", "medium",
                "URL'de anormal sayıda alt domain bulunuyor. "
                "Gerçek domain izlenimi yaratmak için kullanılan phishing tekniğidir.",
                "phishing", host, 0.80,
            )

        # 7. @ işareti
        if "@" in p.netloc:
            score += 30
            signals.append("URL'de @ işareti")
            self.add_finding(
                "URL'de @ işareti tespit edildi", "high",
                "@ işaretinden önce gösterilen domain yanıltıcı olabilir; "
                "tarayıcı @ sonrasını gerçek host olarak kullanır.",
                "phishing", p.netloc, 1.0,
            )

        # 8. Punycode / IDN homograph
        if "xn--" in host.lower():
            score += 20
            signals.append("Punycode (IDN) domain")
            self.add_finding(
                "Punycode/IDN domain tespit edildi", "high",
                "Domain görsel olarak tanınan bir markayı taklit eden Punycode karakterler içerebilir "
                "(homograph saldırısı).",
                "phishing", host, 0.85,
            )

        # 9. Şüpheli keyword kombinasyonu
        kw_re = re.compile(
            r"(secure|update|verify|confirm|account|suspend|unusual|"
            r"alert|limited|validate|recover|unlock|free|win|prize|"
            r"güncelle|doğrula|hesap|askıya|uyarı|ücretsiz|kazan)",
            re.I,
        )
        kw_hits = list(set(kw_re.findall(decoded_url)))
        if len(kw_hits) >= 2:
            score += 10
            signals.append(f"Şüpheli keyword kombinasyonu: {', '.join(kw_hits)}")

        # Bilinen marka adının hostname içinde ek karakter/rakamla kullanılması.
        host_l=(host or "").lower()
        for brand in BRAND_KEYWORDS:
            if brand_present(brand, host_l) and not legitimate_brand_root(brand, get_root_domain(host_l)):
                # Örn. shopee1.example gibi. Marka tokeni tek başına hüküm değildir.
                if brand in host_l:
                    self.add_finding(
                        f"Alan adında marka benzeri ifade: {brand}", "medium",
                        f"Hostname '{host}' içinde '{brand}' ifadesi bulunuyor ancak registrable domain markanın bilinen resmi domainlerinden biri değil.",
                        "phishing", f"host={host}; brand={brand}", 0.82)
                    signals.append(f"brand-like hostname: {brand}")
                    break

        self.results["phishing_signals"] = signals

        # Genel phishing özet bulgusu
        if score >= 50 and not any(
            f["title"].startswith("YÜKSEK RİSK")
            for f in self.results["findings"]
        ):
            self.add_finding(
                "YÜKSEK RİSK: Phishing Sitesi Özellikleri Tespit Edildi", "critical",
                f"Bu URL {score} puanlık phishing sinyal skoru aldı. "
                f"Sinyaller: {'; '.join(signals)}",
                "phishing", "; ".join(signals), 0.97,
            )

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 3 — SAYFA İÇERİĞİ PHİSHİNG SİNYALLERİ
    # ═══════════════════════════════════════════════════════════════════════

    def check_page_phishing_signals(self, html, base_url):
        host = urlparse(base_url).hostname or ""
        root = get_root_domain(host)
        soup = BeautifulSoup(html, "html.parser")

        # ── Marka görseli kontrolü ─────────────────────────────────────────
        img_text = " ".join(
            img.get("alt", "").lower() + " " + img.get("src", "").lower()
            for img in soup.find_all("img")
        )
        for brand in BRAND_KEYWORDS:
            if brand_present(brand, img_text) and not legitimate_brand_root(brand, root):
                self.add_finding(
                    f"Sahte marka görseli: {brand}", "high",
                    f"Sayfa içeriğinde '{brand}' markasına ait görsel referans var "
                    f"ancak host ({host}) gerçek domain değil.",
                    "phishing", f"img references: {brand}", 0.85,
                )
                break

        # ── Form analizi: credential phishing ─────────────────────────────
        for form in soup.find_all("form"):
            action = full_decode(form.get("action", "")).lower()
            inputs      = form.find_all("input")
            input_types = [i.get("type", "").lower() for i in inputs]
            input_names = " ".join(i.get("name", "").lower() for i in inputs)

            has_password = "password" in input_types
            has_user     = any(
                n in input_names
                for n in ("email", "user", "login", "username", "phone", "mail", "tel")
            )

            if has_password and has_user:
                action_host = urlparse(urljoin(base_url, action)).hostname or ""
                if action_host and action_host != host:
                    self.add_finding(
                        "Kimlik bilgisi formu harici hosta gönderiyor", "critical",
                        "Şifre + kullanıcı adı içeren form sayfanın hostundan farklı bir "
                        "hedefe gönderiyor. Credential phishing'in kesin göstergesidir.",
                        "phishing",
                        f"Form action: {action[:200]} | Sayfa host: {host}",
                        0.99,
                    )
                elif host_is_raw_ip(host):
                    self.add_finding(
                        "IP tabanlı sitede kimlik bilgisi formu", "critical",
                        "Ham IP adresi üzerinden çalışan sitede email/şifre toplayan form var.",
                        "phishing", f"Form action: {action[:200]}", 0.98,
                    )

        # ── Sosyal mühendislik içerik analizi ─────────────────────────────
        urgency_re = re.compile(
            r"(hesab[ıi].{0,40}(askıya|donduruldu|kapatılacak|bloke)|"
            r"kimli[gğ]inizi.{0,30}do[gğ]rula|"
            r"your account.{0,40}(suspended|blocked|limited)|"
            r"verify.{0,30}identity|confirm.{0,30}account|"
            r"update.{0,30}(payment|billing|information)|"
            r"unusual.{0,30}activity|"
            r"güvenlik.{0,30}uyar|security.{0,30}alert)",
            re.I,
        )
        hits = urgency_re.findall(html)
        if hits:
            self.add_finding(
                "Sosyal mühendislik içeriği (Aciliyet/Baskı)", "high",
                "Kullanıcıyı panikletmeye yönlendiren ifadeler tespit edildi. "
                "Phishing sayfalarının tipik davranışıdır.",
                "phishing",
                "; ".join(set(m if isinstance(m, str) else m[0] for m in hits[:5])),
                0.88,
            )

        # ── Sayfa başlığında marka taklidi ────────────────────────────────
        title_tag  = soup.find("title")
        title_text = title_tag.get_text() if title_tag else ""
        for brand in BRAND_KEYWORDS:
            if brand_present(brand, title_text) and not legitimate_brand_root(brand, root):
                self.add_finding(
                    f"Sayfa başlığında marka taklidi: {brand}", "high",
                    f"<title> etiketi '{brand}' içeriyor ama host gerçek domain değil.",
                    "phishing",
                    f"Title: {title_text[:100]} | Host: {host}",
                    0.87,
                )
                break

        # ── Favicon gerçek markadan çekiliyor mu? ─────────────────────────
        fav = soup.find("link", rel=lambda r: r and "icon" in " ".join(r).lower())
        if fav:
            fav_href = fav.get("href", "")
            fav_host = urlparse(urljoin(base_url, fav_href)).hostname or ""
            if fav_host and fav_host != host:
                for brand in BRAND_KEYWORDS:
                    if brand in fav_host:
                        self.add_finding(
                            f"Favicon gerçek marka sitesinden çekiliyor: {brand}", "high",
                            "Sayfa ikonunu gerçek marka sitesinden çekiyor. "
                            "Meşru görünmek için kullanılan phishing tekniğidir.",
                            "phishing", fav_href[:200], 0.90,
                        )
                        break

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 4 — DNS
    # ═══════════════════════════════════════════════════════════════════════

    def check_dns(self, host):
        try:
            infos = socket.getaddrinfo(host, None)
            ips   = list(dict.fromkeys(i[4][0] for i in infos))
            self.results["dns"].update({"resolved": bool(ips), "addresses": ips})
            self.results["domain_info"]["ips"] = ips
        except Exception as exc:
            self.results["dns"]["error"] = str(exc)
            self.add_finding(
                "DNS çözümlemesi başarısız", "medium",
                "Domain için DNS kaydı bulunamadı veya çözümleme hatası oluştu.",
                "dns", str(exc)[:200], 0.9,
            )

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 5 — GÜVENLİK HEADER'LARI
    # ═══════════════════════════════════════════════════════════════════════

    def check_security_headers(self, headers):
        specs = {
            "Strict-Transport-Security":   ("HTTPS zorunluluğu",                    "medium"),
            "Content-Security-Policy":     ("Kaynak çalıştırma politikasını sınırlar","medium"),
            "X-Content-Type-Options":      ("MIME sniffing koruması",               "low"),
            "X-Frame-Options":             ("Clickjacking koruması",                "medium"),
            "Referrer-Policy":             ("Referrer bilgilerinin kontrolü",        "low"),
            "Permissions-Policy":          ("Tarayıcı özelliklerine erişimi sınırlar","low"),
            "Cross-Origin-Opener-Policy":  ("Cross-origin pencere izolasyonu",      "low"),
            "Cross-Origin-Resource-Policy":("Cross-origin kaynak erişimi",          "low"),
            "Cross-Origin-Embedder-Policy":("Cross-origin embed kontrolü",          "low"),
        }
        lower = {k.lower(): v for k, v in headers.items()}
        for name, (desc, sev) in specs.items():
            present = name.lower() in lower
            self.results["security_headers"][name] = {
                "present": present,
                "value":   lower.get(name.lower(), "")[:1000],
                "description": desc,
                "severity": sev,
            }

        proto = self.results["domain_info"]["protocol"]
        if proto == "https" and "strict-transport-security" not in lower:
            self.add_finding(
                "HSTS eksik", "medium",
                "HTTPS var ama Strict-Transport-Security header'ı bulunamadı.",
                "headers", "Strict-Transport-Security: missing", 1.0,
            )
        if "x-content-type-options" not in lower:
            self.add_finding(
                "MIME sniffing koruması eksik", "low",
                "X-Content-Type-Options header'ı bulunamadı.",
                "headers", "X-Content-Type-Options: missing", 1.0,
            )
        if "x-frame-options" not in lower and "content-security-policy" not in lower:
            self.add_finding(
                "Clickjacking koruması görünür değil", "medium",
                "X-Frame-Options veya CSP frame-ancestors direktifi bulunamadı.",
                "headers", "X-Frame-Options/CSP: missing", 1.0,
            )

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 6 — COOKIE'LER
    # ═══════════════════════════════════════════════════════════════════════

    def check_cookies(self, response):
        # Doğru yol: ham header listesi (birden fazla Set-Cookie için)
        try:
            raw_list = response.raw.headers.get_all("Set-Cookie") or []
        except Exception:
            raw_list = []
        if not raw_list:
            combined = response.headers.get("Set-Cookie", "")
            if combined:
                raw_list = [combined]

        proto = self.results["domain_info"]["protocol"]
        for value in raw_list:
            name    = value.split("=", 1)[0].strip()
            low     = value.lower()
            secure  = bool(re.search(r"(?:^|;)\s*secure(?:;|$|\s)", low))
            httponly= bool(re.search(r"(?:^|;)\s*httponly(?:;|$|\s)", low))
            same_m  = re.search(r"(?:^|;)\s*samesite\s*=\s*([^;\s]+)", low)
            issues  = []
            if not secure   and proto == "https": issues.append("Secure eksik")
            if not httponly:                       issues.append("HttpOnly eksik")
            if not same_m:                         issues.append("SameSite eksik")
            self.results["cookies"].append({
                "name": name, "secure": secure, "httponly": httponly,
                "samesite": same_m.group(1) if same_m else "",
                "issues": issues,
            })
            if issues:
                self.add_finding(
                    "Cookie güvenlik bayrakları eksik", "medium",
                    f"{name} cookie'sinde: {', '.join(issues)}.",
                    "cookies", name, 0.98,
                )

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 7 — CORS
    # ═══════════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 8 — CSP
    # ═══════════════════════════════════════════════════════════════════════

    def check_csp(self, headers):
        csp = headers.get("Content-Security-Policy", "")
        if not csp:
            return
        directives, issues = {}, []
        for part in csp.split(";"):
            bits = part.strip().split()
            if not bits:
                continue
            directives[bits[0]] = bits[1:]
            if "'unsafe-inline'" in bits[1:]: issues.append(f"{bits[0]}: unsafe-inline")
            if "'unsafe-eval'"   in bits[1:]: issues.append(f"{bits[0]}: unsafe-eval")
            if "*"               in bits[1:]: issues.append(f"{bits[0]}: wildcard")
        self.results["csp"] = {
            "present": True, "value": csp[:4000],
            "directives": directives, "issues": issues,
        }
        if "default-src" not in directives and "script-src" not in directives:
            self.add_finding(
                "CSP kapsamı sınırlı olabilir", "low",
                "CSP mevcut ama default-src/script-src direktifleri görünmüyor.",
                "csp", csp[:500], 0.9,
            )
        if issues:
            self.add_finding(
                "CSP içinde gevşek direktifler", "medium",
                "; ".join(issues), "csp", "; ".join(issues), 0.95,
            )

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 9 — TEKNOLOJİ TESPİTİ
    # ═══════════════════════════════════════════════════════════════════════

    def check_technology(self, response, body):
        tech = []
        server = response.headers.get("Server")
        powered = response.headers.get("X-Powered-By")
        if server:  tech.append(f"Server: {server}")
        if powered: tech.append(f"X-Powered-By: {powered}")

        patterns = {
            "WordPress": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
            "jQuery":    [r"jquery(?:\.min)?\.js", r"jquery[.-][0-9]"],
            "Bootstrap": [r"bootstrap(?:\.min)?\.(?:css|js)"],
            "React":     [r"react-dom", r"__react"],
            "Vue.js":    [r"vue(?:\.min)?\.js"],
            "Angular":   [r"ng-version", r"angular(?:\.min)?\.js"],
            "Next.js":   [r"/_next/static/", r"__NEXT_DATA__"],
            "PHP":       [r"\.php(?:[?#]|$)"],
            "Django":    [r"csrfmiddlewaretoken"],
            "ASP.NET":   [r"__VIEWSTATE"],
            "Cloudflare":[r"cf-ray"],
        }
        haystack = body + "\n" + "\n".join(
            f"{k}: {v}" for k, v in response.headers.items()
        )
        for name, pats in patterns.items():
            if any(re.search(pat, haystack, re.I) for pat in pats):
                tech.append(name)
        self.results["technology"] = list(dict.fromkeys(tech))

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 10 — HTML ANALİZİ
    # ═══════════════════════════════════════════════════════════════════════

    def check_html(self, html, base_url):
        soup      = BeautifulSoup(html, "html.parser")
        base_host = urlparse(base_url).hostname

        # V32.3.2: keep bounded strong semantic surfaces from a valid HTTP body.
        title_tag = soup.find("title")
        _static_inputs=[]
        for x in soup.find_all(["input","textarea","select"])[:200]:
            _static_inputs.append({
                "type": str(x.get("type") or ("textarea" if x.name=="textarea" else "text"))[:80],
                "name": str(x.get("name") or "")[:200], "id": str(x.get("id") or "")[:200],
                "placeholder": str(x.get("placeholder") or "")[:300],
                "autocomplete": str(x.get("autocomplete") or "")[:120],
                "label": ""
            })
        _og=soup.find("meta", attrs={"property":"og:title"}) or soup.find("meta", attrs={"name":"og:title"})
        _app=soup.find("meta", attrs={"name":re.compile(r"application-name",re.I)})
        _header=" ".join(x.get_text(" ",strip=True) for x in soup.find_all(["header","nav"])[:4])[:2500]
        _logo=" ".join((str(x.get("alt") or "")+" "+str(x.get("title") or "")) for x in soup.find_all("img")[:40] if re.search(r"logo|brand",str(x.get("class") or "")+" "+str(x.get("id") or "")+" "+str(x.get("src") or ""),re.I))[:1500]
        self.results["static_semantic_v3232"] = {
            "source": "http_body",
            "title": title_tag.get_text(" ", strip=True)[:1000] if title_tag else "",
            "headings": [x.get_text(" ", strip=True)[:500] for x in soup.find_all(["h1","h2"])[:20]],
            "buttons": [x.get_text(" ", strip=True)[:300] for x in soup.find_all("button")[:30]],
            "labels": [x.get_text(" ", strip=True)[:300] for x in soup.find_all("label")[:40]],
            "visible_text": " ".join(soup.stripped_strings)[:120000],
            "inputs": _static_inputs,
            "identity_surfaces": {
                "og_title": str((_og or {}).get("content") or "")[:1000] if _og else "",
                "app_name": str((_app or {}).get("content") or "")[:1000] if _app else "",
                "header_text": _header, "logo_text": _logo,
            },
            "dom_length": len(html),
        }

        for s in soup.find_all("script", src=True)[:100]:
            src = s.get("src", "")
            abs_url = urljoin(base_url, src)
            self.results["scripts"].append({
                "src": src[:500], "absolute_url": abs_url[:500],
                "type": "external",
                "same_origin": urlparse(abs_url).hostname == base_host,
            })
        for s in soup.find_all("script", src=False)[:100]:
            content = s.string or s.get_text() or ""
            self.results["scripts"].append({
                "src": "", "type": "inline", "length": len(content),
                "has_eval": bool(re.search(r"\beval\s*\(", content)),
            })

        for form in soup.find_all("form")[:100]:
            action   = urljoin(base_url, form.get("action", ""))
            method   = form.get("method", "GET").upper()
            inputs   = [
                {"name": x.get("name", ""), "type": x.get("type", "text")}
                for x in form.find_all(["input", "textarea", "select"])[:100]
            ]
            external = urlparse(action).hostname not in {base_host, None}
            _blob = " ".join((str(x.get("name",""))+" "+str(x.get("type",""))) for x in inputs).lower()
            _types = {str(x.get("type","")).lower() for x in inputs}
            self.results["forms"].append({
                "action": action[:1000], "method": method,
                "inputs": inputs, "input_count": len(inputs),
                "external_action": external,
                "has_password": "password" in _types,
                "has_otp": bool(re.search(r"otp|one.?time|verification|code|pin", _blob, re.I)),
                "has_card": bool(re.search(r"cvv|cvc|card|cc-number|kart", _blob, re.I)),
                "source": "http_static",
            })
            if external:
                self.add_finding(
                    "Form harici origin'e gönderiliyor", "medium",
                    "Form action adresi sayfanın origin'inden farklı bir hosta gidiyor.",
                    "forms", action[:300], 0.9,
                )

        for frame in soup.find_all("iframe")[:100]:
            src      = urljoin(base_url, frame.get("src", ""))
            external = urlparse(src).hostname not in {base_host, None}
            self.results["iframes"].append({
                "src": src[:1000], "sandbox": frame.get("sandbox", ""),
                "title": frame.get("title", ""), "external": external,
            })

        for a in soup.find_all("a", href=True)[:300]:
            href = urljoin(base_url, a["href"])
            self.results["links"].append({
                "url": href[:1000],
                "text": a.get_text(" ", strip=True)[:200],
                "external": urlparse(href).hostname not in {base_host, None},
            })

    def _v32326_static_js_dataflow(self, js, base_url):
        """Conservative static source->sink proof for inline JavaScript.

        This is deliberately *not* a full JavaScript taint engine. It only promotes a
        chain when the source and write sink are structurally close and the destination
        can be resolved to a different registrable domain. Mere API co-occurrence is
        telemetry and cannot vote in threat scoring.
        """
        page_root=get_root_domain((urlparse(base_url).hostname or "").lower())
        text=str(js or "")[:900000]
        source_rx=re.compile(
            r"document\.cookie|localStorage(?:\.[A-Za-z_$][\w$]*|\s*\[)|sessionStorage(?:\.[A-Za-z_$][\w$]*|\s*\[)|"
            r"\.value\b|getAttribute\s*\(\s*['\"]value['\"]|FormData\s*\(|"
            r"querySelector\s*\([^)]*(?:password|otp|passcode|cvv|cvc|card|iban)", re.I)
        sink_rx=re.compile(r"\bfetch\s*\(\s*(['\"])(?P<fetch>[^'\"]+)\1|"
                           r"\.open\s*\(\s*(['\"])(?:POST|PUT|PATCH)\2\s*,\s*(['\"])(?P<xhr>[^'\"]+)\3|"
                           r"sendBeacon\s*\(\s*(['\"])(?P<beacon>[^'\"]+)\4", re.I)
        sources=list(source_rx.finditer(text))[:120]
        sinks=[]
        for m in sink_rx.finditer(text):
            raw=m.groupdict().get("fetch") or m.groupdict().get("xhr") or m.groupdict().get("beacon") or ""
            try:
                u=urljoin(base_url,raw); rr=get_root_domain((urlparse(u).hostname or "").lower())
            except Exception:
                u=raw; rr=""
            relation="same_root" if rr and rr==page_root else ("cross_root" if rr else "unresolved")
            sinks.append({"start":m.start(),"raw":raw[:500],"url":u[:700],"root":rr,"relation":relation})
            if len(sinks)>=120: break

        # Bounded structural proof: source and explicit cross-root write target must be
        # in the same small JS region. We intentionally do not infer through arbitrary
        # variables/functions, because that recreates the old false-positive problem.
        edges=[]
        for sm in sources:
            for sk in sinks:
                distance=abs(sm.start()-sk["start"])
                if sk["relation"]!="cross_root" or distance>1800: continue
                lo=max(0,min(sm.start(),sk["start"])-250); hi=min(len(text),max(sm.end(),sk["start"])+900)
                region=text[lo:hi]
                # Require a write/body/data cue, not a GET-like resource request.
                write_cue=bool(re.search(r"\b(?:body|data|payload|credentials|password|passwd|otp|token)\b\s*[:=]|JSON\.stringify\s*\(|FormData\s*\(",region,re.I))
                if not write_cue: continue
                edges.append({"source":sm.group(0)[:180],"sink":sk["url"],"sink_root":sk["root"],"distance":distance,"proof":"bounded_source_to_explicit_cross_root_write"})
                if len(edges)>=12: break
            if len(edges)>=12: break
        return {"page_root":page_root,"source_count":len(sources),"literal_sink_count":len(sinks),
                "cross_root_literal_sinks":sum(1 for x in sinks if x["relation"]=="cross_root"),
                "proven_edges":edges,"proven_sensitive_to_unrelated_sink":bool(edges),
                "policy":"API co-occurrence is telemetry; scoring requires bounded source -> explicit cross-root write proof."}

    def _v324_static_interaction_graph(self, js, soup, base_url):
        """Bounded, non-executing reconstruction of interaction-triggered data flow.

        It never clicks, types, submits, or executes extracted JavaScript. It only inspects
        explicit handler source and HTML attributes. Strong proof requires a sensitive read
        and an explicit unrelated write sink inside the same bounded handler region.
        """
        js=(js or "")[:1000000]
        page_root=get_root_domain(urlparse(base_url).hostname or "")
        sensitive_read_re=re.compile(r"(?:\.value\b|getElementById\s*\([^)]*(?:pass|otp|cvv|card|pin|email|user)|querySelector\s*\([^)]*(?:password|otp|cvv|card|pin|email|user)|FormData\s*\()",re.I)
        write_re=re.compile(r"(?:fetch\s*\(\s*['\"]([^'\"]+)|\.open\s*\(\s*['\"](?:POST|PUT|PATCH)['\"]\s*,\s*['\"]([^'\"]+)|sendBeacon\s*\(\s*['\"]([^'\"]+)|(?:axios\.(?:post|put|patch)|\$\.post)\s*\(\s*['\"]([^'\"]+))",re.I)
        handlers=[]
        # Bounded extraction. This is intentionally conservative, not a JavaScript interpreter.
        patterns=[
          ("listener",re.compile(r"addEventListener\s*\(\s*['\"](submit|click|change|input)['\"]\s*,\s*(?:async\s*)?(?:function\s*\([^)]*\)|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)\s*\{(.{0,7000}?)\}\s*\)",re.I|re.S)),
          ("property",re.compile(r"on(submit|click|change|input)\s*=\s*(?:async\s*)?(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{(.{0,7000}?)\}",re.I|re.S)),
        ]
        for kind,pat in patterns:
            for m in pat.finditer(js):
                event=(m.group(1) or "").lower(); body=m.group(2) or ""
                sens=bool(sensitive_read_re.search(body))
                sinks=[]
                for wm in write_re.finditer(body):
                    raw=next((g for g in wm.groups() if g),"")
                    u=urljoin(base_url,raw); rr=get_root_domain(urlparse(u).hostname or "")
                    sinks.append({"url":u[:700],"root":rr,"cross_root":bool(rr and page_root and rr!=page_root)})
                cross=[x for x in sinks if x["cross_root"]]
                handlers.append({"kind":kind,"event":event,"sensitive_read":sens,"write_sinks":sinks[:12],"cross_root_sinks":cross[:12],"proven_sensitive_to_cross_root":bool(sens and cross)})
                if len(handlers)>=80: break
            if len(handlers)>=80: break
        html_handlers=[]
        for el in soup.find_all(True)[:1200]:
            for attr,event in (("onsubmit","submit"),("onclick","click"),("onchange","change"),("oninput","input")):
                code=str(el.get(attr) or "")
                if not code: continue
                sens=bool(sensitive_read_re.search(code)); sinks=[]
                for wm in write_re.finditer(code):
                    raw=next((g for g in wm.groups() if g),""); u=urljoin(base_url,raw); rr=get_root_domain(urlparse(u).hostname or "")
                    sinks.append({"url":u[:700],"root":rr,"cross_root":bool(rr and page_root and rr!=page_root)})
                html_handlers.append({"event":event,"tag":el.name,"sensitive_read":sens,"write_sinks":sinks[:8],"proven_sensitive_to_cross_root":bool(sens and any(x["cross_root"] for x in sinks))})
        proven=[x for x in handlers+html_handlers if x.get("proven_sensitive_to_cross_root")]
        return {"mode":"non_executing_static_reconstruction","handler_count":len(handlers)+len(html_handlers),"script_handlers":handlers[:80],"html_handlers":html_handlers[:40],"proven_paths":proven[:20],"proven_count":len(proven),"policy":"No live control is activated. Strong proof requires sensitive source and explicit unrelated write sink in the same bounded handler."}

    def static_source_intelligence_v32317(self, html, base_url):
        """Feed-independent static source expert over a verified 2xx target body.

        It does not execute source code. It extracts bounded HTML/JS evidence and
        only emits strong threat findings when independent source facts correlate.
        """
        soup=BeautifulSoup((html or "")[:1500000], "html.parser")
        host=(urlparse(base_url).hostname or "").lower(); root=get_root_domain(host)
        sem=self.results.get("static_semantic_v3232") or {}
        title=str(sem.get("title") or "")
        headings=" ".join(map(str,(sem.get("headings") or [])[:20]))
        ids=sem.get("identity_surfaces") or {}
        identity_blob=" ".join([title,headings,str(ids.get("og_title") or ""),str(ids.get("app_name") or ""),str(ids.get("header_text") or ""),str(ids.get("logo_text") or "")]).lower()[:30000]
        claims=[]
        for brand in BRAND_KEYWORDS:
            if brand_present(brand,identity_blob) and not legitimate_brand_root(brand,root): claims.append(brand)
        claims=list(dict.fromkeys(claims))[:12]

        # V32.3.27 Credential Flow Sensor: distinguish secret controls from identity/auth controls.
        # Email/username alone is not malicious. It becomes credential intent only when the
        # same first-party surface also expresses an authentication/account-verification intent.
        auth_surface_blob=(identity_blob+" "+" ".join(str(x.get_text(" ",strip=True)) for x in soup.find_all(["label","button"] )[:120])).lower()[:80000]
        auth_intent=bool(re.search(r"\b(login|log in|sign in|signin|verify|verification|account|continue|next|authenticate|"
                                   r"giriş|oturum aç|doğrula|doğrulama|hesap|devam|kimlik)\b",auth_surface_blob,re.I))
        sensitive=[]; identity_inputs=[]
        secret_re=re.compile(r"password|passwd|passcode|parola|şifre|otp|one.?time|verification.?code|pin|cvv|cvc|card.?number|cc-number|iban|seed|recovery.?phrase|wallet",re.I)
        identity_re=re.compile(r"email|e-mail|username|user.?name|user.?id|login|phone|telephone|mobile|account.?id|müşteri|kullanıcı|telefon|eposta|e-posta",re.I)
        for x in soup.find_all(["input","textarea","select"])[:250]:
            blob=" ".join(str(x.get(k) or "") for k in ("type","name","id","placeholder","autocomplete","aria-label")).lower()
            typ=str(x.get("type") or "").lower()
            row={"type":typ,"name":str(x.get("name") or "")[:120],"id":str(x.get("id") or "")[:120],"descriptor":blob[:400]}
            if typ=="password" or secret_re.search(blob): sensitive.append(row)
            elif typ in ("email","tel") or identity_re.search(blob): identity_inputs.append(row)

        forms=[]; external_sensitive=[]; credential_forms=[]
        for f in soup.find_all("form")[:120]:
            action=urljoin(base_url,str(f.get("action") or "")); ar=get_root_domain(urlparse(action).hostname or "")
            fields=f.find_all(["input","textarea","select"])[:150]
            fb=" ".join(" ".join(str(x.get(k) or "") for k in ("type","name","id","placeholder","autocomplete","aria-label")) for x in fields).lower()
            has_secret=bool(secret_re.search(fb))
            has_identity=bool(identity_re.search(fb) or any(str(x.get("type") or "").lower() in ("email","tel") for x in fields))
            fs=bool(has_secret or (has_identity and auth_intent))
            row={"action":action[:600],"action_root":ar,"method":str(f.get("method") or "GET").upper(),"sensitive":fs,
                 "has_secret":has_secret,"has_identity":has_identity,"auth_intent":auth_intent}
            forms.append(row)
            if fs: credential_forms.append(row)
            if fs and ar and ar!=root: external_sensitive.append(row)

        scripts=[]; js_blob=[]; external_candidates=[]
        for sc in soup.find_all("script")[:180]:
            if sc.get("src"):
                u=urljoin(base_url,str(sc.get("src"))); row={"type":"external","url":u[:600],"root":get_root_domain(urlparse(u).hostname or "")}
                scripts.append(row); external_candidates.append((u,row))
            else:
                code=(sc.string or sc.get_text() or "")[:250000]; js_blob.append(code); scripts.append({"type":"inline","bytes":len(code)})
        # V32.4.1 Deep Script Inspection: inspect a bounded set of referenced JS files too.
        # This is passive source retrieval only: no extracted code is executed. safe_get keeps
        # public-IP and redirect guards active. Large/binary/non-script responses are rejected.
        fetched_external=0; fetched_external_bytes=0
        if external_candidates:
            _ses=requests.Session(); _ses.trust_env=bool(RUNNING_ON_PYTHONANYWHERE)
            _ses.headers.update({"User-Agent":USER_AGENT,"Accept":"application/javascript,text/javascript,*/*;q=0.2","Connection":"close"})
            for _u,_row in external_candidates[:10]:
                try:
                    _r,_hist,_fu=self.safe_get(_ses,_u,timeout=5,max_redirects=3)
                    _ct=str(_r.headers.get("Content-Type") or "").lower(); _cl=int(_r.headers.get("Content-Length") or 0)
                    if int(_r.status_code) != 200 or (_cl and _cl>350000):
                        _row.update({"fetched":False,"status":int(_r.status_code)}); _r.close(); continue
                    _raw=_r.raw.read(350001,decode_content=True); _r.close()
                    if len(_raw)>350000:
                        _row.update({"fetched":False,"reason":"size_limit"}); continue
                    if not ("javascript" in _ct or "ecmascript" in _ct or _u.lower().split("?",1)[0].endswith((".js",".mjs"))):
                        _row.update({"fetched":False,"reason":"non_script_content_type","content_type":_ct[:120]}); continue
                    _code=_raw.decode("utf-8","replace")
                    js_blob.append("\n/* external: "+_fu[:300]+" */\n"+_code)
                    fetched_external+=1; fetched_external_bytes+=len(_raw)
                    _row.update({"fetched":True,"status":200,"bytes":len(_raw),"final_url":_fu[:600]})
                except Exception as _e:
                    _row.update({"fetched":False,"error":str(_e)[:180]})
        js="\n".join(js_blob)[:1800000]
        self.results["_javascript_sources"]={"inline_and_external":[{"origin":"combined","url":base_url,"body":js}],"bytes":len(js),"execution":"never"}

        # Bounded static reconstruction of JS-created credential UI and submission sinks.
        # No JavaScript is executed. We only recognize explicit literals/API calls.
        js_auth=bool(re.search(r"login|sign.?in|password|passcode|verify|verification|otp|account|giriş|oturum|parola|şifre|doğrula|hesap",js,re.I))
        js_identity_control=bool(re.search(r"(?:type|name|id|placeholder|autocomplete)\s*[=:]\s*['\"](?:email|tel|username|user.?id|login)|"
                                           r"setAttribute\s*\(\s*['\"](?:type|name|autocomplete)['\"]\s*,\s*['\"](?:email|tel|username)",js,re.I))
        js_secret_control=bool(re.search(r"type\s*[=:]\s*['\"]password|setAttribute\s*\(\s*['\"]type['\"]\s*,\s*['\"]password|"
                                         r"otp|one.?time|verification.?code|cvv|cvc|card.?number|recovery.?phrase",js,re.I))
        js_submit_handlers=bool(re.search(r"addEventListener\s*\(\s*['\"]submit|onsubmit\s*=|preventDefault\s*\(|"
                                          r"addEventListener\s*\(\s*['\"]click",js,re.I))
        js_sink_literals=[]
        sink_patterns=[
            r"fetch\s*\(\s*['\"]([^'\"]+)",
            r"\.open\s*\(\s*['\"](?:POST|PUT|PATCH)['\"]\s*,\s*['\"]([^'\"]+)",
            r"(?:axios\.(?:post|put|patch)|\$\.post)\s*\(\s*['\"]([^'\"]+)",
            r"sendBeacon\s*\(\s*['\"]([^'\"]+)"
        ]
        for pat in sink_patterns:
            for m in re.finditer(pat,js,re.I):
                u=urljoin(base_url,m.group(1)); rr=get_root_domain(urlparse(u).hostname or "")
                js_sink_literals.append({"url":u[:600],"root":rr,"external":bool(rr and root and rr!=root),"offset":m.start()})
                if len(js_sink_literals)>=40: break
            if len(js_sink_literals)>=40: break
        js_external_sinks=[x for x in js_sink_literals if x.get("external")]
        js_dynamic_credential=bool(js_secret_control or (js_identity_control and js_auth))

        js_features={
            "dynamic_eval":bool(re.search(r"\beval\s*\(|new\s+Function\s*\(",js,re.I)),
            "decode_obfuscation":bool(re.search(r"\batob\s*\(|String\.fromCharCode|unescape\s*\(",js,re.I)),
            "cookie_access":bool(re.search(r"document\.cookie",js,re.I)),
            "storage_access":bool(re.search(r"localStorage|sessionStorage",js,re.I)),
            "key_capture":bool(re.search(r"keydown|keypress|keyup|beforeinput|input",js,re.I)),
            "network_sink":bool(re.search(r"\bfetch\s*\(|XMLHttpRequest|sendBeacon\s*\(",js,re.I)),
            "location_redirect":bool(re.search(r"(?:window\.)?location(?:\.href)?\s*=|location\.replace\s*\(",js,re.I)),
            "password_dom":bool(re.search(r"type\s*[=:]\s*['\"]password|setAttribute\s*\(\s*['\"]type['\"]\s*,\s*['\"]password",js,re.I)),
        }
        # V32.3.26: lexical co-occurrence is NOT a causal data-flow proof.
        # A page may legitimately contain cookie/storage/input APIs and fetch/XHR in unrelated
        # modules (large first-party applications do this constantly).  Static JS contributes
        # attack evidence only when a bounded source -> sink chain is visible in the same code
        # region, and the sink is demonstrably cross-root/unrelated.
        dataflow=self._v32326_static_js_dataflow(js, base_url)
        js_causal=bool(dataflow.get("proven_sensitive_to_unrelated_sink"))
        credential_source=bool(sensitive or (identity_inputs and auth_intent) or any(x["sensitive"] for x in forms) or js_features["password_dom"] or js_dynamic_credential)
        # JS sink is only a submission/exfil candidate when credential UI + submit semantics are
        # present. A random analytics fetch on the same page is never promoted by this sensor.
        js_credential_sink=bool(js_dynamic_credential and js_submit_handlers and js_external_sinks)

        interaction_v324=self._v324_static_interaction_graph(js,soup,base_url)

        report={"body_bytes":len(html or ""),"host":host,"root":root,"brand_claims":claims,"sensitive_controls":len(sensitive),
                "identity_inputs":identity_inputs[:30],"auth_intent":auth_intent,"credential_forms":credential_forms[:30],
                "forms":forms[:30],"external_sensitive_forms":external_sensitive[:12],"scripts":scripts[:60],"inline_js_bytes":len(js),
                "js_features":js_features,"causal_dataflow_v32326":dataflow,
                "credential_flow_v32327":{"js_auth":js_auth,"js_identity_control":js_identity_control,"js_secret_control":js_secret_control,
                    "js_dynamic_credential":js_dynamic_credential,"js_submit_handlers":js_submit_handlers,
                    "js_sink_literals":js_sink_literals[:20],"js_external_sinks":js_external_sinks[:20],"js_credential_sink":js_credential_sink},
                "credential_source":credential_source,"non_executing_interaction_v324":interaction_v324,
                "external_script_inspection_v3241":{"fetched":fetched_external,"bytes":fetched_external_bytes,"candidate_count":len(external_candidates),"limit":10,"execution":"never"},
                "feed_independent":True,
                "rule":"Static source is evidence only when the verified 2xx target body was observed; source code is never executed."}
        self.results["static_source_intelligence_v32317"]=report

        # Strong, source-level correlations. No brand-only conviction.
        if claims and credential_source:
            self.add_finding("Statik kaynakta marka taklidi + hassas bilgi talebi","high",
                "Gerçek hedef HTML kaynağında güçlü marka kimliği yüzeyi ile parola/OTP/ödeme benzeri hassas bilgi talebi birlikte gözlendi.",
                "credential_theft",json.dumps({"brands":claims,"sensitive_controls":len(sensitive)},ensure_ascii=False),.95)
            self.results["findings"][-1].update({"producer":"static_source_intelligence_v32318","source_expert":"static_credential_intent","independent_group":"static_source","evidence_lineage_id":"static-source-identity-credential"})
        if js_credential_sink:
            self.add_finding("JavaScript ile oluşturulan kimlik yüzeyi → harici gönderim hedefi","high",
                "Statik kaynakta JavaScript ile oluşturulan kimlik/hassas giriş yüzeyi, submit etkileşimi ve farklı registrable domaine giden açık ağ hedefi aynı kaynakta gözlendi. Kod çalıştırılmadı.",
                "credential_theft",json.dumps({"external_sinks":js_external_sinks[:8],"submit_handler":js_submit_handlers},ensure_ascii=False),.96)
            self.results["findings"][-1].update({"producer":"credential_flow_sensor_v32327","source_expert":"static_submission_exfil","independent_group":"static_source","evidence_lineage_id":"v32327-js-credential-sink"})
        elif js_dynamic_credential:
            self.add_finding("JavaScript ile oluşturulan kimlik doğrulama yüzeyi","medium",
                "Statik JavaScript kaynağında dinamik kimlik/hassas giriş kontrolü gözlendi; harici gönderim hedefi doğrulanmadığı için bu bulgu tek başına veri sızdırma kanıtı değildir.",
                "credential_theft",json.dumps({"auth":js_auth,"identity_control":js_identity_control,"secret_control":js_secret_control},ensure_ascii=False),.78)
            self.results["findings"][-1].update({"producer":"credential_flow_sensor_v32327","source_expert":"static_credential_intent","independent_group":"static_source","context_only":True,"score_hint_v32327":24,"evidence_lineage_id":"v32327-js-credential-surface"})

        if external_sensitive:
            self.add_finding("Statik kaynakta hassas form harici domaine gönderiliyor","critical",
                "Gerçek hedef HTML kaynağındaki hassas veri formunun action hedefi farklı bir registrable domaine gidiyor.",
                "credential_theft",json.dumps(external_sensitive[:6],ensure_ascii=False),.99)
            self.results["findings"][-1].update({"producer":"static_source_intelligence_v32318","source_expert":"static_submission_exfil","independent_group":"static_source","evidence_lineage_id":"static-source-sensitive-form-sink"})
        if js_causal and credential_source:
            self.add_finding("Statik JavaScript'te hassas kaynak + ağ aktarım zinciri","high",
                "Gerçek hedef kaynağında hassas giriş bağlamı ile giriş/cookie erişimi, ağ API'si ve kod gizleme/dinamik çalıştırma göstergeleri birlikte bulundu. Kod çalıştırılmadı.",
                "javascript",json.dumps(js_features,ensure_ascii=False),.93)
            self.results["findings"][-1].update({"producer":"static_source_intelligence_v32318","source_expert":"static_javascript","independent_group":"static_source","evidence_lineage_id":"static-source-js-causal"})
        return report

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 11 — MIXED CONTENT
    # ═══════════════════════════════════════════════════════════════════════

    def check_mixed_content(self, html, base_url):
        if urlparse(base_url).scheme != "https":
            return
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["img", "script", "iframe", "link",
                                   "audio", "video", "source"]):
            attr  = "href" if tag.name == "link" else "src"
            value = tag.get(attr)
            if value and value.lower().startswith("http://"):
                self.results["mixed_content"].append({"tag": tag.name, "url": value[:1000]})
        if self.results["mixed_content"]:
            self.add_finding(
                "Mixed Content", "medium",
                f"HTTPS sayfada {len(self.results['mixed_content'])} HTTP kaynak bulundu.",
                "mixed_content",
                "; ".join(x["url"] for x in self.results["mixed_content"][:5]),
                1.0,
            )

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 12 — ŞÜPHELİ PATTERN'LER
    # ═══════════════════════════════════════════════════════════════════════

    def check_suspicious_patterns(self, html):
        checks = [
            ("eval()",              r"\beval\s*\(",                                  "medium", "Dinamik JavaScript çalıştırma"),
            ("document.write",      r"document\.write\s*\(",                         "low",    "Dinamik HTML yazımı"),
            ("atob()",              r"\batob\s*\(",                                  "low",    "Base64 çözme"),
            ("String.fromCharCode", r"String[.]fromCharCode",                         "medium", "Kod gizleme"),
            ("document.cookie",     r"document\.cookie",                             "medium", "Cookie erişimi"),
            ("localStorage.get",    r"localStorage\.getItem\s*\(",                   "low",    "LocalStorage okuma"),
            ("window.location=",    r"window\.location\s*=|window\.location\.href\s*=","medium","JS yönlendirme"),
            ("shell_exec",          r"\bshell_exec\s*\(",                            "high",   "Sunucu komutu çalıştırma"),
            ("system()",            r"\bsystem\s*\(",                                "high",   "Sunucu komutu çalıştırma"),
            ("exec()",              r"\bexec\s*\(",                                  "high",   "Komut çalıştırma"),
            ("base64_decode",       r"\bbase64_decode\s*\(",                         "high",   "PHP base64 decode — kod gizleme"),
            ("keylogger keyword",   r"\bkeylogger\b",                                "high",   "Keylogger ifadesi"),
            ("backdoor keyword",    r"\bbackdoor\b",                                 "high",   "Backdoor ifadesi"),
        ]
        for name, pattern, sev, desc in checks:
            count = len(re.findall(pattern, html, re.I))
            if count:
                self.results["suspicious_patterns"].append({
                    "pattern": name, "count": count, "risk": sev, "description": desc,
                })

        # eval + obfuscation kombinasyonu
        has_eval = bool(re.search(r"\beval\s*\(", html, re.I))
        has_obf  = bool(re.search(r"\batob\s*\(|String[.]fromCharCode|unescape\s*\(", html, re.I))
        if has_eval and has_obf:
            self.add_finding(
                "JavaScript obfuscation sinyali (eval + decode)", "high",
                "eval() ile birlikte kod gizleme/çözme teknikleri görüldü. İncelenmelidir.",
                "javascript", "eval + obfuscation", 0.92,
            )

        # Cookie exfiltration
        if re.search(
            r"document\.cookie.{0,500}(?:fetch|XMLHttpRequest|sendBeacon|location)",
            html, re.I | re.S,
        ):
            self.add_finding(
                "Cookie Exfiltration sinyali", "high",
                "document.cookie ile birlikte ağ/yönlendirme API'si yakın bağlamda görüldü.",
                "javascript", "document.cookie + network API", 0.90,
            )

        # Keylogger davranışı (keydown + network)
        if re.search(
            r"(?:keydown|keypress|addEventListener\s*\(\s*['\"]key).{0,500}"
            r"(?:fetch|XMLHttpRequest|sendBeacon|location)",
            html, re.I | re.S,
        ):
            self.add_finding(
                "Keylogger davranış sinyali", "critical",
                "Klavye olayı dinleyicisi + ağ isteği birlikte tespit edildi. "
                "Kullanıcı girişlerini çalmaya yönelik teknik olabilir.",
                "javascript", "keyevent + network", 0.88,
            )

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 13 — SSL / TLS
    # ═══════════════════════════════════════════════════════════════════════

    def check_ssl_certificate(self, host, port):
        self.results["ssl_info"]["checked"] = True
        proto = self.results["domain_info"]["protocol"]

        if proto != "https":
            self.results["ssl_info"]["error"] = "Hedef HTTP; TLS kontrolü atlandı."
            self.add_finding(
                "HTTPS kullanılmıyor", "high",
                "Site HTTP üzerinden çalışıyor. Tüm veri iletimi şifresizdir.",
                "tls", f"Protocol: {proto}", 1.0,
            )
            return

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert      = ssock.getpeercert()
                    expiry_raw= cert.get("notAfter", "")
                    days      = None
                    if expiry_raw:
                        expiry = datetime.strptime(
                            expiry_raw, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        days = (expiry - datetime.now(timezone.utc)).days

                    issuer  = dict(x[0] for x in cert.get("issuer",  []))
                    subject = dict(x[0] for x in cert.get("subject", []))

                    self.results["ssl_info"].update({
                        "valid": True, "version": ssock.version() or "",
                        "issuer": issuer, "subject": subject,
                        "not_before": cert.get("notBefore", ""),
                        "not_after":  expiry_raw, "days_remaining": days,
                        "subject_alt_names": cert.get("subjectAltName", []),
                    })

                    if days is not None and days < 30:
                        self.add_finding(
                            "TLS sertifikası yakında sona eriyor",
                            "medium" if days >= 0 else "high",
                            f"Sertifikanın kalan süresi: {days} gün.",
                            "tls", expiry_raw, 1.0,
                        )
                    if issuer == subject:
                        self.add_finding(
                            "Self-signed TLS sertifikası", "high",
                            "Sertifika güvenilir bir CA tarafından imzalanmamış (self-signed). "
                            "Phishing altyapısının göstergesi olabilir.",
                            "tls", f"Issuer: {issuer}", 0.90,
                        )
        except ssl.SSLCertVerificationError as exc:
            self.results["ssl_info"].update({"valid": False, "error": str(exc)})
            self.add_finding(
                "TLS sertifika doğrulaması başarısız", "high",
                "TLS bağlantısı kuruldu ancak sertifika doğrulanamadı.",
                "tls", str(exc)[:500], 0.98,
            )
        except (ConnectionRefusedError, socket.timeout, TimeoutError, OSError) as exc:
            self.results["ssl_info"].update({"valid": False, "error": str(exc)})
            self.add_finding(
                "TLS bağlantısı doğrulanamadı",
                "info" if RUNNING_ON_PYTHONANYWHERE else "low",
                "Raw TLS bağlantısı kurulamadı. Bu sonuç tek başına geçersiz/sahte sertifika kanıtı değildir.",
                "network", str(exc)[:500],
                0.55 if RUNNING_ON_PYTHONANYWHERE else 0.70,
            )
        except Exception as exc:
            self.results["ssl_info"].update({"valid": False, "error": str(exc)})
            self.add_finding(
                "TLS kontrolü tamamlanamadı", "low",
                "TLS modülü kesin sertifika hükmü üretemedi.",
                "network", str(exc)[:500], 0.60,
            )

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 14 — WELL-KNOWN
    # ═══════════════════════════════════════════════════════════════════════

    def check_well_known(self, session, base_url, path, key):
        target = urljoin(base_url, "/" + path.lstrip("/"))
        try:
            r, _, final = self.safe_get(session, target, timeout=10, max_redirects=4)
            body = read_limited_response(r, 512 * 1024)
            self.results["well_known"][key] = {
                "status_code": r.status_code, "exists": r.status_code == 200,
                "url": final, "size": len(body),
            }
            r.close()
        except Exception as exc:
            self.results["well_known"][key] = {
                "status_code": None, "exists": False,
                "url": target, "error": str(exc),
            }

    # ═══════════════════════════════════════════════════════════════════════
    # MODÜL 15 — WEB DEFENDER DAVRANIŞ / DOWNLOAD / KORELASYON MOTORU
    # ═══════════════════════════════════════════════════════════════════════

    def check_advanced_defender(self, html, base_url):
        soup = BeautifulSoup(html, "html.parser")
        host = (urlparse(base_url).hostname or "").lower()
        root = get_root_domain(host)
        defender = self.results["defender"]

        # 1) İndirme bağlantıları. Dosyayı indirmiyoruz/çalıştırmıyoruz; yalnızca link davranışını inceliyoruz.
        for a in soup.find_all("a", href=True)[:500]:
            href = urljoin(base_url, a.get("href", ""))
            path = urlparse(href).path.lower()
            ext = os.path.splitext(path)[1]
            download_attr = a.has_attr("download")
            if ext in DANGEROUS_EXTENSIONS or ext in ARCHIVE_EXTENSIONS or download_attr:
                item = {"url": href[:1200], "extension": ext, "download_attribute": download_attr,
                        "dangerous_type": ext in DANGEROUS_EXTENSIONS,
                        "external": (urlparse(href).hostname or "") != host}
                self.results["downloads"].append(item)
        dangerous = [x for x in self.results["downloads"] if x["dangerous_type"]]
        if dangerous:
            self.add_finding("Çalıştırılabilir/aktif içerik indirme bağlantısı", "high",
                f"Sayfada {len(dangerous)} adet çalıştırılabilir veya aktif içerik türünde indirme bağlantısı bulundu. Dosya otomatik olarak indirilmedi.",
                "malware", "; ".join(x["url"] for x in dangerous[:5]), 0.86)

        # 2) Meta refresh / JS redirect / popup / otomatik tetikleme davranışları.
        meta_refresh=[]
        for meta in soup.find_all("meta"):
            if (meta.get("http-equiv") or "").lower() == "refresh":
                content=meta.get("content", "")
                if "url=" in content.lower(): meta_refresh.append(content[:500])
        if meta_refresh:
            self.add_finding("Meta Refresh yönlendirmesi", "medium",
                "Sayfa tarayıcıyı meta refresh ile başka hedefe yönlendirebilir.", "redirect",
                "; ".join(meta_refresh[:5]), 0.82)

        js_redirect = bool(re.search(r"(?:window\.)?location(?:\.href|\.replace|\.assign)?\s*(?:=|\()", html, re.I))
        popup = bool(re.search(r"\bwindow\.open\s*\(", html, re.I))
        dyn_script = bool(re.search(r"createElement\s*\(\s*['\"]script['\"]|\.src\s*=.{0,250}(?:https?:)?//", html, re.I|re.S))
        if dyn_script:
            self.add_finding("Dinamik harici script yükleme davranışı", "medium",
                "JavaScript çalışma anında script oluşturuyor veya harici script adresi atıyor.",
                "javascript", "dynamic script loader", 0.78)

        # 3) Hassas veri erişimi + ağ aktarımı korelasyonu.
        reads_cookie = bool(re.search(r"document\.cookie", html, re.I))
        reads_storage = bool(re.search(r"(?:localStorage|sessionStorage)\.(?:getItem|\w+)", html, re.I))
        clipboard = bool(re.search(r"navigator\.clipboard|clipboardData", html, re.I))
        key_events = bool(re.search(r"(?:keydown|keyup|keypress|input).{0,180}(?:addEventListener|onkeydown|onkeyup|onkeypress|oninput)|addEventListener\s*\(\s*['\"](?:keydown|keyup|keypress|input)", html, re.I|re.S))
        network = bool(re.search(r"\bfetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket\s*\(|\.send\s*\(", html, re.I))
        obfuscation = bool(re.search(r"\beval\s*\(|\batob\s*\(|String[.]fromCharCode|unescape\s*\(|decodeURIComponent\s*\(", html, re.I))
        if (reads_cookie or reads_storage) and network and obfuscation:
            self.add_finding("Token/Cookie veri sızdırma korelasyonu", "critical",
                "Depolama/cookie erişimi, ağ gönderimi ve kod gizleme davranışları birlikte görüldü.",
                "credential_theft", "storage/cookie + network + obfuscation", 0.94)
        if key_events and network and obfuscation:
            self.add_finding("Girdi yakalama ve aktarım korelasyonu", "critical",
                "Klavye/girdi dinleme, ağ aktarımı ve obfuscation birlikte tespit edildi.",
                "credential_theft", "input events + network + obfuscation", 0.93)
        if clipboard and network:
            self.add_finding("Clipboard erişimi + ağ iletişimi", "high",
                "Sayfa pano verisine erişim ve ağ iletişimi davranışlarını birlikte içeriyor.",
                "privacy", "clipboard + network", 0.82)

        # 4) Credential form derin analizi.
        credential_forms=0; external_credential_forms=0; insecure_credential_forms=0
        for form in soup.find_all("form")[:100]:
            inputs=form.find_all(["input","textarea"])
            types=[(i.get("type") or "text").lower() for i in inputs]
            names=" ".join((i.get("name") or "")+" "+(i.get("autocomplete") or "") for i in inputs).lower()
            has_secret = "password" in types or bool(re.search(r"pass|otp|pin|cvv|cvc|card|token", names))
            has_identity = bool(re.search(r"email|user|login|phone|mail|account|kart|card", names))
            if has_secret and has_identity:
                credential_forms += 1
                action=urljoin(base_url, form.get("action") or base_url)
                ahost=(urlparse(action).hostname or host).lower()
                if get_root_domain(ahost) != root:
                    external_credential_forms += 1
                if urlparse(action).scheme != "https": insecure_credential_forms += 1
        if external_credential_forms:
            self.add_finding("Credential form farklı registrable domaine gönderiyor", "critical",
                f"{external_credential_forms} kimlik bilgisi formu sayfanın ana domaininden farklı bir domaine veri gönderiyor.",
                "credential_theft", f"page={root}; external_forms={external_credential_forms}", 0.98)
        if insecure_credential_forms:
            self.add_finding("Credential form HTTPS kullanmıyor", "critical",
                f"{insecure_credential_forms} hassas formun hedefi HTTPS değil.", "credential_theft",
                f"insecure_forms={insecure_credential_forms}", 0.99)

        # 5) Marka taklidi: title + görünür metin + form + domain kombinasyonu.
        title=(soup.title.get_text(" ", strip=True) if soup.title else "").lower()
        visible=soup.get_text(" ", strip=True).lower()[:250000]
        claimed=[]
        for brand in BRAND_KEYWORDS:
            if brand_present(brand, title) or brand_present(brand, visible):
                if not legitimate_brand_root(brand, root): claimed.append(brand)
        if claimed and credential_forms:
            self.add_finding("Marka taklidi + kimlik bilgisi toplama", "critical",
                "Sayfa tanınan marka isimleri kullanıyor ve kimlik bilgisi isteyen form içeriyor; domain ilgili markanın bilinen domaini değil.",
                "phishing", f"host={host}; brands={', '.join(sorted(set(claimed))[:8])}", 0.96)

        # 6) URL kısaltıcı / data URI / blob tabanlı indirme ve otomatik click sinyalleri.
        if root in SHORTENER_HOSTS:
            self.add_finding("URL kısaltıcı kullanımı", "medium",
                "Kısaltılmış URL gerçek hedefi kullanıcıdan gizleyebilir.", "url", host, 0.72)
        data_blob = bool(re.search(r"(?:href|src)\s*=\s*['\"](?:data:|blob:)", html, re.I))
        auto_click = bool(re.search(r"\.click\s*\(\)", html, re.I))
        if data_blob and auto_click:
            self.add_finding("Tarayıcı içinde üretilen otomatik indirme davranışı", "high",
                "data:/blob: kaynağı ile programatik click davranışı birlikte görüldü.",
                "malware", "data/blob + .click()", 0.88)

        # 7) V13.7 Sosyal mühendislik + malware aile sinyalleri.
        # Web taraması kanal/kurban bağlamını her zaman bilemez. Spear phishing, smishing,
        # vishing ve whaling yalnızca sayfa üzerinde destekleyici kanıt varsa "olası" olarak işaretlenir.
        social = self.results["defender"].setdefault("social_engineering", [])
        malware_families = self.results["defender"].setdefault("malware_families", [])
        lower = (title + " " + visible)[:250000]

        def family(name, confidence, evidence, category="social_engineering"):
            target = social if category == "social_engineering" else malware_families
            if not any(x.get("type") == name for x in target):
                target.append({"type": name, "confidence": round(confidence, 2), "evidence": evidence[:600]})

        # Phishing is supported by credential collection + impersonation/redirect evidence.
        if credential_forms and (claimed or external_credential_forms or js_redirect or meta_refresh):
            family("phishing", .94 if claimed or external_credential_forms else .78,
                   f"credential_forms={credential_forms}; brands={claimed[:5]}; external_forms={external_credential_forms}")

        # Targeted/whaling language is contextual evidence, never a definitive attribution.
        targeted_words = re.findall(r"\b(?:employee|staff|personnel|muhasebe|finans|ik|human resources|kurumsal|şirket hesabı|company account)\b", lower, re.I)
        executive_words = re.findall(r"\b(?:ceo|cfo|cto|chief executive|chief financial|genel müdür|yönetim kurulu|director|executive)\b", lower, re.I)
        if credential_forms and targeted_words:
            family("possible_spear_phishing", .66, "targeted language: " + ", ".join(sorted(set(targeted_words))[:8]))
        if credential_forms and executive_words:
            family("possible_whaling", .72, "executive language: " + ", ".join(sorted(set(executive_words))[:8]))

        # Channel references can suggest smishing/vishing, but a URL scan cannot prove delivery channel.
        sms_words = re.findall(r"\b(?:sms|whatsapp|mesaj|text message|doğrulama kodu|sms kodu)\b", lower, re.I)
        voice_words = re.findall(r"\b(?:telefonla ara|call us|call now|müşteri hizmetleri|polis|savcı|bankacı|kargo görevlisi)\b", lower, re.I)
        if credential_forms and sms_words:
            family("possible_smishing_landing_page", .60, "messaging/SMS context: " + ", ".join(sorted(set(sms_words))[:8]))
        if credential_forms and voice_words:
            family("possible_vishing_support_page", .58, "voice/call context: " + ", ".join(sorted(set(voice_words))[:8]))

        bait_words = re.findall(r"\b(?:free download|ücretsiz indir|crack|keygen|bedava oyun|ücretsiz film|hediye|ödül|prize|gift)\b", lower, re.I)
        if bait_words and (dangerous or self.results.get("downloads")):
            family("baiting", .82, "lure + download: " + ", ".join(sorted(set(bait_words))[:8]))
            self.add_finding("Yemleme / baiting sinyali", "high",
                "Ücretsiz içerik/ödül yemi ile indirme davranışı aynı sayfada birlikte görüldü.",
                "social_engineering", ", ".join(sorted(set(bait_words))[:8]), .82)

        # Browser-deliverable malware families are heuristic labels, not binary/file-signature verdicts.
        ransom_words = re.findall(r"\b(?:ransom|bitcoin payment|pay bitcoin|files encrypted|dosyalarınız şifrelendi|fidye|decrypt key)\b", lower, re.I)
        if ransom_words and dangerous:
            family("possible_ransomware_delivery", .78, ", ".join(sorted(set(ransom_words))[:8]), "malware")
        if dangerous and bait_words:
            family("possible_trojan_delivery", .76, "executable download disguised by lure", "malware")

        spyware_api = bool(re.search(r"getUserMedia\s*\(|getDisplayMedia\s*\(|MediaRecorder\s*\(|geolocation\.getCurrentPosition", html, re.I))
        if spyware_api and network:
            family("spyware_like_web_behavior", .74, "sensitive browser API + network", "malware")
            self.add_finding("Casus yazılım benzeri web davranışı", "high",
                "Kamera/mikrofon/ekran/konum gibi hassas tarayıcı API'leri ile ağ iletişimi birlikte görüldü.",
                "privacy", "sensitive browser API + network", .74)
        if key_events and network:
            family("keylogger_like_behavior", .86 if obfuscation else .70, "keyboard/input capture + network", "malware")
        if popup:
            family("adware_like_behavior", .55, "window.open / popup behavior", "malware")

        # Worm, DDoS and MITM cannot be established from a single passive page scan.
        # We expose related observable signals without falsely naming an attack.
        if self.results["domain_info"]["protocol"] == "https" and self.results["ssl_info"].get("checked") and not self.results["ssl_info"].get("valid"):
            self.add_finding("TLS güven zinciri problemi", "high",
                "TLS doğrulaması başarısız. Bu durum MITM kanıtı değildir ancak güvenli kanal doğrulanamadı.",
                "transport_security", self.results["ssl_info"].get("error", "")[:400], .88)

        # 8) Korelasyon motoru: tek zayıf sinyal yerine birleşik davranışlar.
        correlations=[]
        if claimed and credential_forms: correlations.append("brand_impersonation + credential_form")
        if external_credential_forms: correlations.append("credential_form + external_destination")
        if obfuscation and network and (reads_cookie or reads_storage): correlations.append("obfuscation + sensitive_storage + network")
        if key_events and network: correlations.append("input_capture + network")
        if dangerous and (obfuscation or js_redirect): correlations.append("dangerous_download + scripted_behavior")
        if meta_refresh and self.results["http"]["redirect_count"]: correlations.append("meta_redirect + http_redirect_chain")
        defender["correlations"] = correlations
        if len(correlations) >= 2:
            self.add_finding("Çoklu tehdit davranışı korelasyonu", "critical",
                f"Birbirini güçlendiren {len(correlations)} bağımsız davranış zinciri tespit edildi.",
                "behavior", "; ".join(correlations), 0.95)

        types=[]
        cats={f.get("category") for f in self.results["findings"]}
        if "phishing" in cats or "credential_theft" in cats: types.append("PHISHING / CREDENTIAL THEFT")
        if "malware" in cats: types.append("MALICIOUS DOWNLOAD / MALWARE DELIVERY")
        if "javascript" in cats or "behavior" in cats: types.append("SUSPICIOUS WEB BEHAVIOR")
        if "privacy" in cats: types.append("PRIVACY / DATA EXFILTRATION RISK")
        if "social_engineering" in cats or defender.get("social_engineering"): types.append("SOCIAL ENGINEERING")
        if defender.get("malware_families") and "MALICIOUS DOWNLOAD / MALWARE DELIVERY" not in types: types.append("MALWARE-LIKE BEHAVIOR")
        defender["threat_types"] = types
        defender["recommendations"] = (["Bu sayfaya parola, kart veya kişisel bilgi girmeyin.", "Dosya indirmeyin veya çalıştırmayın."] if types else ["Belirgin zararlı davranış korelasyonu bulunmadı; yine de alan adını ve içeriği doğrulayın."])

    def check_passive_defender(self, url):
        """İçerik erişilemese bile yalnızca yerel URL/DNS/TLS/ağ metadatasını değerlendirir.
        Bu katman phishing/malware hükmü üretmez; sadece pasif risk seviyesini yükseltir.
        """
        p = urlparse(url)
        host = (p.hostname or "").lower().rstrip(".")
        root = self.results["domain_info"].get("root_domain") or host
        labels = [x for x in host.split(".") if x]
        root_label = root.split(".")[0] if root else ""
        signals=[]
        score=0

        def sig(code, points, text, evidence=""):
            nonlocal score
            score += points
            signals.append({"code":code,"points":points,"description":text,"evidence":evidence})

        # URL/host yapısı. Bunlar kanıt değil, risk göstergesidir.
        if len(host) >= 55: sig("long_hostname", 7, "Hostname olağandışı uzun.", str(len(host)))
        if len(labels) >= 5: sig("deep_subdomain", 8, "Çok katmanlı subdomain yapısı kullanılıyor.", str(len(labels)))
        if host.startswith("xn--") or ".xn--" in host: sig("punycode", 14, "Punycode/IDN hostname kullanılıyor.", host)
        hyphens=host.count("-")
        if hyphens >= 4: sig("many_hyphens", 6, "Hostname çok sayıda tire içeriyor.", str(hyphens))
        digits=sum(ch.isdigit() for ch in host)
        if digits >= 6: sig("many_digits", 5, "Hostname çok sayıda rakam içeriyor.", str(digits))
        if len(url) >= 180: sig("long_url", 6, "URL olağandışı uzun.", str(len(url)))
        if "@" in urlparse(url).netloc: sig("userinfo", 18, "URL authority bölümünde @ işareti var.", p.netloc)

        # Basit Shannon entropy. Random/otomatik üretilmiş label için yardımcı sinyal.
        if root_label:
            counts={c:root_label.count(c) for c in set(root_label)}
            entropy=-sum((n/len(root_label))*math.log2(n/len(root_label)) for n in counts.values())
            if len(root_label) >= 14 and entropy >= 3.6:
                sig("high_entropy_label", 7, "Ana domain etiketi yüksek karakter entropisine sahip.", f"entropy={entropy:.2f}")

        ui=self.results["url_intelligence"]
        if ui.get("suspicious_tld"): sig("suspicious_tld", 8, "TLD yerel risk listesinde.", root)
        if ui.get("double_encoded"): sig("double_encoding", 12, "Çok katmanlı URL encoding bulundu.")
        if ui.get("redirect_parameters"): sig("redirect_parameter", 6, "URL yönlendirme parametresi taşıyor.")
        if ui.get("sensitive_parameter_names"): sig("sensitive_parameter", 7, "URL hassas isimli parametre taşıyor.")
        if ui.get("brand_in_path") or ui.get("brand_in_params"):
            sig("brand_reference", 12, "URL yolu/parametresi bilinen marka adı içeriyor.")
        if ui.get("typosquatting_signals"):
            sig("typosquatting", 18, "Marka benzerliği/typosquatting sinyali bulundu.", "; ".join(map(str,ui.get("typosquatting_signals",[])[:3])))

        # Ağ metadatası. Connection refused tek başına kötü niyet değildir.
        http=self.results["http"]
        probe=self.results.get("network_probe",{})
        ports=probe.get("ports",{})
        p80=ports.get("80",{})
        p443=ports.get("443",{})
        # Kapalı/refused port tek başına kötü niyet göstergesi değildir; puan üretmez.
        # Yalnızca teşhis sinyali olarak raporlanır. Timeout da saldırı kanıtı değildir.
        if p80.get("status") in {"refused","timeout","network_error"}:
            signals.append({"code":"port80_"+p80.get("status","unknown"),"points":0,"description":"TCP/80 erişim durumu: "+p80.get("status","unknown"),"evidence":p80.get("error","")[:160]})
        if p443.get("status") in {"refused","timeout","network_error"}:
            signals.append({"code":"port443_"+p443.get("status","unknown"),"points":0,"description":"TCP/443 erişim durumu: "+p443.get("status","unknown"),"evidence":p443.get("error","")[:160]})
        if http.get("failure_kind") == "tls": sig("tls_transport_failure", 4, "TLS taşıma katmanında hata oluştu.")
        ssl_info=self.results["ssl_info"]
        if p.scheme=="https" and ssl_info.get("checked") and not ssl_info.get("valid"):
            sig("tls_unavailable", 6, "HTTPS hedefinde TLS doğrulaması tamamlanamadı.", ssl_info.get("error","")[:160])
        if not self.results["dns"].get("resolved"):
            sig("dns_failure", 5, "DNS çözümlemesi başarısız.")

        # Birden çok bağımsız pasif sinyal birlikteyse korelasyon bonusu.
        independent=sum(1 for x in signals if x["points"] >= 7)
        if independent >= 3: score += 8
        score=min(score,100)
        classification = "low"
        if score >= 55: classification="high"
        elif score >= 30: classification="elevated"
        elif score >= 15: classification="guarded"
        pa={"score":score,"signals":signals,"classification":classification}
        self.results["defender"]["passive_analysis"]=pa

        if score >= 55:
            self.add_finding("Pasif altyapı/URL riski yüksek", "high",
                "İçerikten bağımsız birden fazla URL, DNS, TLS veya ağ sinyali birlikte görüldü. Bu bulgu malware/phishing kanıtı değildir.",
                "passive", json.dumps(signals[:8], ensure_ascii=False), 0.72)
        elif score >= 30:
            self.add_finding("Pasif risk sinyalleri", "medium",
                "URL ve ağ metadatasında dikkat gerektiren birden fazla sinyal görüldü.",
                "passive", json.dumps(signals[:8], ensure_ascii=False), 0.65)

    def build_feature_vector(self):
        cats=[f.get("category") for f in self.results["findings"]]
        sev=[f.get("severity") for f in self.results["findings"]]
        ui=self.results["url_intelligence"]
        html_forms=self.results["forms"]
        patterns=self.results["suspicious_patterns"]
        features={
            "raw_ip": self.results["domain_info"]["is_ip"],
            "http": self.results["domain_info"]["protocol"] == "http",
            "double_encoded": ui.get("double_encoded",False),
            "suspicious_tld": ui.get("suspicious_tld",False),
            "login_page": ui.get("login_page",False),
            "brand_path": bool(ui.get("brand_in_path")),
            "brand_params": bool(ui.get("brand_in_params")),
            "redirect_params": bool(ui.get("redirect_parameters")),
            "sensitive_params": bool(ui.get("sensitive_parameter_names")),
            "many_redirects": self.results["http"]["redirect_count"] >= 3,
            "external_redirect": any(x.get("external") for x in self.results["http"]["redirects"]),
            "external_form": any(x.get("external_action") for x in html_forms),
            "password_form": any(any((i.get("type") or "").lower()=="password" for i in x.get("inputs",[])) for x in html_forms),
            "dangerous_download": any(x.get("dangerous_type") for x in self.results["downloads"]),
            "obfuscation": any(x.get("pattern") in {"eval()","atob()","String.fromCharCode"} for x in patterns),
            "mixed_content": bool(self.results["mixed_content"]),
            "critical_finding": "critical" in sev,
            "high_finding": "high" in sev,
            "phishing_category": "phishing" in cats,
            "credential_theft_category": "credential_theft" in cats,
            "malware_category": "malware" in cats,
            "behavior_category": "behavior" in cats,
            "multiple_correlations": len(self.results["defender"].get("correlations",[])) >= 2,
            "tls_invalid": self.results["domain_info"]["protocol"]=="https" and self.results["ssl_info"].get("checked") and not self.results["ssl_info"].get("valid"),
            "passive_guarded": self.results["defender"].get("passive_analysis",{}).get("score",0) >= 15,
            "passive_elevated": self.results["defender"].get("passive_analysis",{}).get("score",0) >= 30,
            "passive_high": self.results["defender"].get("passive_analysis",{}).get("score",0) >= 55,
        }
        self.results["defender"]["feature_vector"] = {k: bool(v) for k,v in features.items()}

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

    def check_generic_runtime_risk(self, original_url):
        """Marka listesine bağımlı kalmadan runtime phishing/credential sinyallerini korele eder."""
        b=self.results.get("browser",{}) or {}
        final=b.get("final_url") or self.results.get("final_url") or original_url
        host=(urlparse(final).hostname or "").lower(); root=get_root_domain(host)
        initial=(urlparse(original_url).path or "/").lower(); fp=(urlparse(final).path or "/").lower()
        sem=b.get("semantic_dom") or {}; forms=b.get("forms") or self.results.get("forms") or []
        inputs=sem.get("inputs") or []
        sensitive=[]
        for i in inputs:
            blob=" ".join(str(i.get(k,"")) for k in ("type","name","id","placeholder","autocomplete","label")).lower()
            if i.get("type")=="password" or re.search(r"password|passwd|parola|şifre|otp|one.?time|verification|verify|pin|cvv|cvc|card|kart|iban|wallet|seed|recovery",blob,re.I): sensitive.append(i)
        loginish=bool(re.search(r"/(login|signin|sign-in|auth|account|verify|verification|secure|wallet|payment)(?:/|$)",fp,re.I))
        if loginish and fp != initial:
            self.add_finding("Tarayıcı giriş/doğrulama sayfasına yönlendi","medium","Başlangıç adresi browser çalıştıktan sonra giriş/doğrulama bağlamlı bir path'e geçti.","redirect",f"{original_url} -> {final}",.82)
        # Marka adı hostname içinde taklit ediliyorsa sayfa metninden bağımsız güçlü sinyal.
        labels=[x for x in host.split('.') if x and x not in {'www','com','net','org','app','site','online'}]
        impersonated=[]; typo=[]
        for brand in BRAND_KEYWORDS:
            if legitimate_brand_root(brand,root): continue
            if any(brand_present(brand,x) for x in labels): impersonated.append(brand)
            elif len(brand)>=5:
                for x in labels:
                    token=re.sub(r'[^a-z0-9]','',x.lower())
                    if len(token)>=4 and difflib.SequenceMatcher(None,brand,token).ratio()>=.82:
                        typo.append((brand,x)); break
        if impersonated:
            self.add_finding("Alan adında marka taklidi sinyali","high","Hostname tanınan bir marka adını içeriyor ancak kök domain o markanın bilinen resmi alan adı değil.","phishing",f"host={host}; brand={','.join(sorted(set(impersonated))[:8])}",.96)
        if typo:
            self.add_finding("Alan adında typosquatting benzerliği","high","Domain etiketi bilinen bir markaya yazım olarak çok benziyor ancak resmi alan adı değil.","phishing",str(typo[:8]),.88)
        if sensitive:
            self.add_finding("Runtime DOM hassas bilgi alanı içeriyor","medium","Render edilen DOM parola/OTP/kart/hesap benzeri hassas giriş alanı içeriyor. Tek başına saldırı kanıtı değildir; diğer sinyallerle korele edilir.","forms",f"sensitive_fields={len(sensitive)}; final={final}",.82)
        if sensitive and (impersonated or typo):
            self.add_finding("Marka taklidi ile hassas bilgi isteme birlikte","critical","Şüpheli marka/domain yapısı ile hassas bilgi alanları aynı sayfada birlikte gözlendi.","credential_theft",f"host={host}; sensitive_fields={len(sensitive)}",.995)
        if sensitive and loginish and (self.results.get('defender',{}).get('passive_analysis',{}).get('score',0)>=10):
            self.add_finding("Şüpheli domain + login + hassas alan korelasyonu","high","Login/doğrulama sayfası, hassas giriş alanı ve yükselmiş domain riski birlikte gözlendi.","credential_theft",f"final={final}; sensitive_fields={len(sensitive)}",.92)
        # Tüm form action hedeflerini değerlendir, formu asla submit etme.
        for f in forms[:100]:
            action=str(f.get('action') or final)
            try: ar=get_root_domain(urlparse(urljoin(final,action)).hostname or '')
            except Exception: ar=''
            fsens=bool(f.get('has_password') or f.get('has_otp') or f.get('has_card'))
            if fsens and ar and ar!=root:
                self.add_finding("Hassas form farklı kök domaine gönderiliyor","critical","Parola/OTP/kart içeren formun action hedefi sayfanın kök domaininden farklı.","credential_theft",action[:500],.995)

    def check_live_threat_intelligence(self, url):
        """Canlı IOC kaynakları yardımcı kanıt olarak kullanılır; davranış motorunun yerine geçmez."""
        ti=self.results['threat_intelligence']; ti['checked']=True
        headers={'User-Agent':f'WebDefender/{APP_VERSION} security-scanner'}
        # PhishTank doğrudan URL lookup. app_key opsiyonel, anahtarsız kullanım daha sık rate-limit olabilir.
        try:
            data={'url':url,'format':'json'}
            key=os.getenv('PHISHTANK_APP_KEY','').strip()
            if key: data['app_key']=key
            r=requests.post('https://checkurl.phishtank.com/checkurl/',data=data,headers=headers,timeout=6)
            ti['sources'].append({'name':'PhishTank','status':r.status_code})
            if r.ok:
                j=r.json(); rr=j.get('results') or {}
                if rr.get('in_database') and rr.get('valid') and rr.get('verified'):
                    ti['matches'].append({'source':'PhishTank','type':'verified_phishing','url':url})
                    self.add_finding('PhishTank doğrulanmış phishing eşleşmesi','critical','URL PhishTank veritabanında doğrulanmış aktif phishing kaydıyla eşleşti.','phishing',url,.999)
        except Exception as e: ti['errors'].append({'source':'PhishTank','error':str(e)[:220]})
        # OpenPhish community feed. İsteğe bağlı kapatılabilir; feed bellekte sadece bu tarama için kontrol edilir.
        if os.getenv('ENABLE_OPENPHISH','1').lower() not in ('0','false','no','off'):
            try:
                r=requests.get('https://openphish.com/feed.txt',headers=headers,timeout=7,stream=True)
                ti['sources'].append({'name':'OpenPhish Community','status':r.status_code})
                if r.ok:
                    _chunks=[]; _total=0
                    for _chunk in r.iter_content(65536,decode_unicode=False):
                        if not _chunk: continue
                        _chunks.append(_chunk); _total += len(_chunk)
                        if _total >= 10*1024*1024: break
                    _feed_raw=b''.join(_chunks)[:10*1024*1024]
                    norm=url.rstrip('/').lower(); host=(urlparse(url).hostname or '').lower()
                    lines=_feed_raw.decode('utf-8','replace').splitlines()[:100000]
                    exact=any(x.strip().rstrip('/').lower()==norm for x in lines)
                    hostmatch=any((urlparse(x.strip()).hostname or '').lower()==host for x in lines if x.startswith(('http://','https://')))
                    if exact or hostmatch:
                        ti['matches'].append({'source':'OpenPhish','type':'phishing_feed','match':'exact' if exact else 'host'})
                        self.add_finding('OpenPhish güncel feed eşleşmesi','critical','URL veya host güncel OpenPhish phishing feed içinde bulundu.','phishing',f"match={'exact' if exact else 'host'}; {url}",.995 if exact else .97)
            except Exception as e: ti['errors'].append({'source':'OpenPhish','error':str(e)[:220]})

    def check_cve_intelligence(self):
        """Gözlenen teknoloji/sürüm için NVD adaylarını getirir. Aktif exploit/probe yapmaz."""
        if os.getenv('ENABLE_CVE_INTEL','1').lower() in ('0','false','no','off'): return
        tech=self.results.get('technology') or []
        products=[]
        for item in tech:
            m=re.search(r'(?i)(wordpress|jquery|bootstrap|next\\.js|php|django|angular|vue(?:\\.js)?)[ /:_-]*v?([0-9]+(?:\\.[0-9]+){1,3})',str(item))
            if m: products.append((m.group(1),m.group(2)))
        self.results['cve_intelligence']['products']=[{'product':a,'version':b} for a,b in products[:4]]
        for product,version in products[:3]:
            try:
                q=requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0',params={'keywordSearch':f'{product} {version}','resultsPerPage':8},headers={'User-Agent':f'WebDefender/{APP_VERSION}'},timeout=7)
                if not q.ok: continue
                for v in q.json().get('vulnerabilities',[])[:8]:
                    c=v.get('cve') or {}; cid=c.get('id'); desc=''
                    for d in c.get('descriptions',[]):
                        if d.get('lang')=='en': desc=d.get('value',''); break
                    if cid: self.results['cve_intelligence']['candidates'].append({'cve':cid,'product':product,'version':version,'description':desc[:500],'status':'candidate_not_confirmed'})
            except Exception as e:
                self.results['errors'].append({'module':'cve_intelligence','error':str(e)[:220]})

    def build_multi_evidence_fusion(self):
        """V16 Multi-Evidence Fusion Engine.
        Tek bulguya hüküm vermez. Aynı saldırı hipotezini destekleyen farklı uzman
        ailelerinden gelen kanıtları korele eder. Puanlar olasılık değildir.
        """
        findings=self.results.get("findings",[])
        sev={"critical":32,"high":20,"medium":10,"low":3,"info":1}

        def expert_for(f):
            cat=(f.get("category") or "").lower(); title=(f.get("title") or "").lower()
            if "phishtank" in title or "openphish" in title or "urlhaus" in title or "threatfox" in title: return "threat_intel"
            if cat in {"credential_theft","forms"}: return "credential"
            if cat in {"malware"}: return "malware"
            if cat in {"javascript","behavior"}: return "javascript_runtime"
            if cat in {"privacy"}: return "network_exfil"
            if cat in {"redirect"}: return "redirect"
            if cat in {"phishing","social_engineering"}: return "brand_social"
            if cat in {"url","passive"}: return "url_domain"
            if cat in {"network","tls","transport_security"}: return "infrastructure"
            return "other"

        hypotheses={
            "Phishing / Marka Taklidi":{"cats":{"phishing","social_engineering"},"experts":{"brand_social","url_domain","redirect","credential","threat_intel"}},
            "Kimlik Bilgisi Hırsızlığı":{"cats":{"credential_theft","forms","phishing"},"experts":{"credential","brand_social","redirect","network_exfil","threat_intel"}},
            "Malware / Zararlı İndirme":{"cats":{"malware","javascript","behavior"},"experts":{"malware","javascript_runtime","redirect","threat_intel","network_exfil"}},
            "Şüpheli JavaScript / Davranış":{"cats":{"javascript","behavior"},"experts":{"javascript_runtime","network_exfil","redirect"}},
            "Gizlilik / Veri Sızdırma Riski":{"cats":{"privacy","credential_theft"},"experts":{"network_exfil","credential","javascript_runtime"}},
            "Yönlendirme Kötüye Kullanımı":{"cats":{"redirect","phishing","malware"},"experts":{"redirect","brand_social","javascript_runtime","malware"}},
        }
        expert_rows={}
        for f in findings:
            if f.get("score_eligible_v322") is False: continue
            e=expert_for(f)
            if e in {"other","infrastructure"}: continue
            # Header/TLS/configuration bulguları threat fusion'a girmez.
            if (f.get("category") or "").lower() in {"headers","cookies","cors","csp","tls","transport_security","network"}: continue
            val=sev.get(f.get("severity"),0)*float(f.get("confidence",1))
            expert_rows.setdefault(e,[]).append((val,f))

        expert_summary=[]
        for e,rows in expert_rows.items():
            rows=sorted(rows,key=lambda x:x[0],reverse=True)
            # Aynı uzmandan gelen tekrarları azalan ağırlıkla say.
            score=min(100, round(sum(v*w for (v,_),w in zip(rows,[1,.45,.25,.15,.1]))))
            expert_summary.append({"expert":e,"score":score,"evidence":[r[1] for r in rows[:4]]})
        expert_summary.sort(key=lambda x:x["score"],reverse=True)

        category_rows=[]; chains=[]
        for name,h in hypotheses.items():
            relevant=[]; experts=set()
            for f in findings:
                if f.get("score_eligible_v322") is False: continue
                cat=(f.get("category") or "").lower(); e=expert_for(f)
                if cat in h["cats"] and e in h["experts"]:
                    relevant.append(f); experts.add(e)
            vals=sorted([sev.get(f.get("severity"),0)*float(f.get("confidence",1)) for f in relevant], reverse=True)
            base=sum(v*w for v,w in zip(vals,[1,.55,.30,.20,.12,.08]))
            # Gerçek fusion bonusu sadece farklı uzmanlar aynı hipotezi doğrularsa gelir.
            independent=len(experts)
            bonus={0:0,1:0,2:14,3:28,4:40}.get(independent,48)
            score=min(100,round(base+bonus))
            if independent>=2:
                chains.append({"type":name,"experts":sorted(experts),"evidence_count":len(relevant),"score":score})
            category_rows.append({"name":name,"score":score,"independent_experts":independent,"experts":sorted(experts),"evidence":sorted(relevant,key=lambda f:{"critical":0,"high":1,"medium":2,"low":3}.get(f.get("severity"),9))[:6]})
        category_rows.sort(key=lambda x:x["score"],reverse=True)
        primary=category_rows[0] if category_rows else {"name":"","score":0,"independent_experts":0}

        # Tek uzman critical IOC ise yüksek olabilir; davranışsal iddiada iki bağımsız uzman tercih edilir.
        verified_ioc=any(f.get("score_eligible_v322") is not False and expert_for(f)=="threat_intel" and f.get("severity")=="critical" for f in findings)
        score=primary.get("score",0)
        if primary.get("independent_experts",0)<2 and not verified_ioc:
            score=min(score,39)
        verdict="critical" if score>=75 else "high" if score>=50 else "guarded" if score>=20 else "low" if score>0 else "no_evidence"
        fusion={"score":score,"verdict":verdict,"primary":primary.get("name","") if score else "","categories":category_rows,"experts":expert_summary,"chains":chains,"independent_experts":primary.get("independent_experts",0),"verified_ioc":verified_ioc}
        self.results["defender"]["fusion"]=fusion
        self.results["defender"]["correlations"]=[f"{c['type']}: {' + '.join(c['experts'])}" for c in chains]
        types=[c["name"] for c in category_rows if c["score"]>=20]
        self.results["defender"]["threat_types"]=types

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

    def check_malware_intelligence(self, url):
        """URLhaus + ThreatFox canlı zenginleştirme; sonuçları Web Defender'ın kendi IOC hafızasına da yazar."""
        ti=self.results['threat_intelligence']; host=(urlparse(url).hostname or '').lower()
        # URLhaus Community API artık Auth-Key gerektiriyor.
        key=os.getenv('ABUSECH_AUTH_KEY','').strip()
        if not key:
            ti['sources'].append({'name':'URLhaus/ThreatFox','status':'not_configured','note':'ABUSECH_AUTH_KEY gerekli'})
            return
        headers={'Auth-Key':key,'User-Agent':f'WebDefender/{APP_VERSION}'}
        try:
            r=requests.post('https://urlhaus-api.abuse.ch/v1/url/',data={'url':url},headers=headers,timeout=7)
            ti['sources'].append({'name':'URLhaus','status':r.status_code})
            if r.ok:
                j=r.json()
                if j.get('query_status')=='ok':
                    ti['matches'].append({'source':'URLhaus','type':'malware_url','status':j.get('url_status'),'threat':j.get('threat')})
                    payloads=j.get("payloads") if isinstance(j.get("payloads"),list) else []
                    THREAT_INTEL_STORE.upsert("url",url,"URLhaus",threat_type=j.get("threat") or "malware_url",malware_family=payloads[0].get("signature") if payloads else None,confidence=100,last_seen=j.get("last_online"),raw=j)
                    for px in payloads[:100]:
                        sh=str(px.get("response_sha256") or px.get("sha256_hash") or px.get("sha256") or "").lower()
                        if re.fullmatch(r"[0-9a-f]{64}",sh):
                            THREAT_INTEL_STORE.upsert("sha256",sh,"URLhaus",threat_type="malware_payload",
                                malware_family=px.get("signature"),confidence=100,first_seen=px.get("firstseen"),last_seen=px.get("lastseen"),
                                expires_at=_expiry(px.get("lastseen") or px.get("firstseen"),180),raw=px)
                    self.add_finding('URLhaus malware URL eşleşmesi','critical','URL, URLhaus malware dağıtım verisinde eşleşti.','malware',json.dumps({'status':j.get('url_status'),'threat':j.get('threat'),'tags':j.get('tags')},ensure_ascii=False)[:800],.995)
        except Exception as e: ti['errors'].append({'source':'URLhaus','error':str(e)[:220]})
        # ThreatFox: URL ve domain IOC araması.
        for term in [url,host]:
            if not term: continue
            try:
                r=requests.post('https://threatfox-api.abuse.ch/api/v1/',json={'query':'search_ioc','search_term':term,'exact_match':True},headers=headers,timeout=7)
                ti['sources'].append({'name':'ThreatFox','status':r.status_code,'term':term[:120]})
                if r.ok:
                    j=r.json(); data=j.get('data') if j.get('query_status')=='ok' else []
                    if isinstance(data,list) and data:
                        x=data[0]; ti['matches'].append({'source':'ThreatFox','type':x.get('threat_type'),'ioc':x.get('ioc'),'malware':x.get('malware_printable')})
                        ioc_type='url' if str(x.get('ioc_type','')).lower()=='url' else ('ip' if 'ip' in str(x.get('ioc_type','')).lower() else 'domain')
                        THREAT_INTEL_STORE.upsert(ioc_type,x.get('ioc'),'ThreatFox',threat_type=x.get('threat_type'),malware_family=x.get('malware_printable') or x.get('malware'),confidence=x.get('confidence_level'),first_seen=x.get('first_seen'),last_seen=x.get('last_seen'),raw=x)
                        self.add_finding('ThreatFox malware IOC eşleşmesi','critical','URL/domain güncel malware IOC verisiyle eşleşti.','malware',json.dumps({'ioc':x.get('ioc'),'threat_type':x.get('threat_type'),'malware':x.get('malware_printable'),'confidence':x.get('confidence_level')},ensure_ascii=False)[:800],.99)
            except Exception as e: ti['errors'].append({'source':'ThreatFox','error':str(e)[:220]})

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

    # ═══════════════════════════════════════════════════════════════════════
    # SKOR HESAPLAMA
    # ═══════════════════════════════════════════════════════════════════════

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

    def check_rdap_domain_v21(self, domain):
        """IANA RDAP bootstrap -> authoritative registry RDAP. Cached 24h."""
        domain=registrable_domain_v21(domain)
        cached=_cache_get("rdap:"+domain)
        if cached is not None: return cached
        out={"domain":domain,"observed":False,"age_days":None,"created":None,"expires":None,"registrar":None,"source":"IANA RDAP bootstrap"}
        try:
            global _RDAP_BOOTSTRAP
            now=time.time()
            with _TRUST_CACHE_LOCK:
                if not _RDAP_BOOTSTRAP["services"] or now-_RDAP_BOOTSTRAP["loaded_at"]>86400:
                    r=requests.get("https://data.iana.org/rdap/dns.json",timeout=(3,5),headers={"User-Agent":USER_AGENT})
                    r.raise_for_status()
                    _RDAP_BOOTSTRAP={"loaded_at":now,"services":r.json().get("services",[])}
            tld=domain.rsplit(".",1)[-1].lower()
            bases=[]
            for tlds,urls in _RDAP_BOOTSTRAP["services"]:
                if tld in [x.lower() for x in tlds]:
                    bases=urls; break
            if not bases: raise ValueError("TLD için RDAP bootstrap servisi bulunamadı")
            data=None
            for base in bases[:2]:
                try:
                    rr=requests.get(base.rstrip("/")+"/domain/"+quote(domain,safe=".-"),timeout=(3,6),
                                    headers={"Accept":"application/rdap+json, application/json","User-Agent":USER_AGENT})
                    if rr.status_code==200: data=rr.json(); break
                except Exception: continue
            if not data: raise ValueError("RDAP domain yanıtı alınamadı")
            events={str(e.get("eventAction","")).lower():e.get("eventDate") for e in data.get("events",[]) if isinstance(e,dict)}
            created=events.get("registration") or events.get("registered")
            expiry=events.get("expiration") or events.get("expiry")
            age=None
            if created:
                try:
                    dt=datetime.fromisoformat(created.replace("Z","+00:00"))
                    age=(datetime.now(timezone.utc)-dt.astimezone(timezone.utc)).days
                except Exception: pass
            registrar=None
            for ent in data.get("entities",[]) or []:
                roles=[str(x).lower() for x in ent.get("roles",[])]
                if "registrar" in roles:
                    vc=ent.get("vcardArray")
                    if isinstance(vc,list) and len(vc)>1:
                        for item in vc[1]:
                            if item and item[0]=="fn": registrar=item[3]; break
                    break
            out.update({"observed":True,"age_days":age,"created":created,"expires":expiry,"registrar":registrar})
        except Exception as exc:
            out["error"]=str(exc)[:300]
        _cache_put("rdap:"+domain,out,24)
        return out

    def check_email_dns_v21(self, domain):
        """SPF/DMARC/CAA are organization-context signals, not proof of web safety."""
        domain=registrable_domain_v21(domain)
        cached=_cache_get("maildns:"+domain)
        if cached is not None: return cached
        out={"domain":domain,"spf":None,"dmarc":None,"dmarc_policy":None,"caa":[],"observed":False}
        try:
            import dns.resolver
            resolver=dns.resolver.Resolver(); resolver.timeout=1.5; resolver.lifetime=2.5
            try:
                for a in resolver.resolve(domain,"TXT"):
                    txt="".join(x.decode(errors="replace") if isinstance(x,bytes) else str(x) for x in getattr(a,"strings",[])) or a.to_text().strip('"')
                    if txt.lower().startswith("v=spf1"): out["spf"]=txt[:700]; break
            except Exception: pass
            try:
                for a in resolver.resolve("_dmarc."+domain,"TXT"):
                    txt="".join(x.decode(errors="replace") if isinstance(x,bytes) else str(x) for x in getattr(a,"strings",[])) or a.to_text().strip('"')
                    if "v=dmarc1" in txt.lower():
                        out["dmarc"]=txt[:700]
                        m=re.search(r"(?:^|;)\s*p\s*=\s*([a-z]+)",txt,re.I)
                        out["dmarc_policy"]=m.group(1).lower() if m else None
                        break
            except Exception: pass
            try: out["caa"]=[x.to_text()[:300] for x in resolver.resolve(domain,"CAA")][:20]
            except Exception: pass
            out["observed"]=True
        except Exception as exc: out["error"]=str(exc)[:250]
        _cache_put("maildns:"+domain,out,12)
        return out

    def check_asn_context_v21(self, ips):
        """ASN is infrastructure context only. Cloud hosting is never a safety verdict."""
        cached_key="asn:"+",".join(sorted(ips or [])[:4])
        cached=_cache_get(cached_key)
        if cached is not None: return cached
        out={"items":[],"observed":False,"source":"Team Cymru DNS"}
        known={"13335":"Cloudflare","15169":"Google","16509":"Amazon AWS","8075":"Microsoft","54113":"Fastly","20940":"Akamai","32934":"Meta"}
        try:
            import dns.resolver
            resolver=dns.resolver.Resolver(); resolver.timeout=1.5; resolver.lifetime=2.5
            for ip in (ips or [])[:4]:
                try:
                    obj=ipaddress.ip_address(ip)
                    if obj.version!=4: continue
                    q=".".join(reversed(ip.split(".")))+".origin.asn.cymru.com"
                    txt=resolver.resolve(q,"TXT")[0].to_text().strip('"')
                    parts=[x.strip() for x in txt.split("|")]
                    asn=parts[0].split()[0] if parts else ""
                    out["items"].append({"ip":ip,"asn":"AS"+asn if asn else None,
                        "provider_context":known.get(asn),"prefix":parts[1] if len(parts)>1 else None,
                        "country":parts[2] if len(parts)>2 else None})
                except Exception: continue
            out["observed"]=bool(out["items"])
        except Exception as exc: out["error"]=str(exc)[:250]
        _cache_put(cached_key,out,12)
        return out

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

    def run_trust_context_v21(self):
        root=registrable_domain_v21(self.results.get("domain_info",{}).get("hostname") or "")
        ips=self.results.get("dns",{}).get("addresses") or []
        out={}
        jobs={}
        with ThreadPoolExecutor(max_workers=4) as ex:
            jobs[ex.submit(self.check_rdap_domain_v21,root)]="rdap"
            jobs[ex.submit(self.check_email_dns_v21,root)]="email_dns"
            jobs[ex.submit(self.check_asn_context_v21,ips)]="asn"
            jobs[ex.submit(tranco_rank_v21,root)]="tranco"
            for fut in as_completed(jobs):
                name=jobs[fut]
                try: out[name]=fut.result()
                except Exception as exc: out[name]={"error":str(exc)[:250]}
        # Positive/context score. Never subtracted from threat.
        score=0; ev=[]
        rd=out.get("rdap",{}); age=rd.get("age_days")
        if isinstance(age,int):
            if age>=365*5: score+=22; ev.append("Domain 5+ yıllık")
            elif age>=365*2: score+=15; ev.append("Domain 2+ yıllık")
            elif age<7:
                self.add_finding("Çok yeni kayıtlı domain","high",f"RDAP kaydına göre domain yaklaşık {age} günlük.","domain_age",str(rd),.85)
            elif age<30:
                self.add_finding("Yeni kayıtlı domain","medium",f"RDAP kaydına göre domain yaklaşık {age} günlük.","domain_age",str(rd),.72)
        tr=out.get("tranco",{}); rank=tr.get("rank")
        if isinstance(rank,int):
            if rank<=10000: score+=25; ev.append("Tranco top-10k bağlamı")
            elif rank<=100000: score+=16; ev.append("Tranco top-100k bağlamı")
            elif rank<=1000000: score+=8; ev.append("Tranco top-1M bağlamı")
        md=out.get("email_dns",{})
        if md.get("spf"): score+=4; ev.append("SPF mevcut")
        if md.get("dmarc"): score+=5; ev.append("DMARC mevcut")
        if md.get("dmarc_policy") in ("reject","quarantine"): score+=3; ev.append("DMARC politikası sıkı")
        if md.get("caa"): score+=3; ev.append("CAA mevcut")
        ai=out.get("asn",{})
        if any(x.get("provider_context") for x in ai.get("items",[])): score+=3; ev.append("Bilinen büyük altyapı sağlayıcısı bağlamı")
        self.results["trust_context_v21"]={"score":min(score,100),"signals":ev,"sensors":out,
            "principle":"Trust Context yalnızca bağlamdır; Threat Evidence skorundan çıkarılmaz."}
        self.build_identity_trust_v21()

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

    def run_network_behavior_v22(self):
        b=self.results.get("browser",{}) or {}; final=b.get("final_url") or self.results.get("final_url") or ""
        root=registrable_domain_v21(urlparse(final).hostname or "")
        hooks=b.get("runtime_hooks") or {}; sem=b.get("semantic_dom") or {}; inputs=sem.get("inputs") or []
        sensitive=any(str(i.get("type","")).lower()=="password" or re.search(
            r"otp|one.?time|verification|cvv|cvc|cc-number|card|iban|password|parola|şifre",
            " ".join(str(i.get(k,"")) for k in ("type","name","id","placeholder","autocomplete","label")),re.I) for i in inputs)
        events=[]
        for kind,rows in (("fetch",hooks.get("fetches") or []),("xhr",hooks.get("xhr") or []),
                          ("beacon",hooks.get("beacons") or []),("form_submit",hooks.get("form_submits") or [])):
            for x in rows[:100]:
                u=urljoin(final,str(x.get("url") or x.get("action") or "")); rr=registrable_domain_v21(urlparse(u).hostname or "")
                if rr: events.append({"kind":kind,"url":u[:700],"root":rr,"cross_site":rr!=root,
                                      "has_body":bool(x.get("has_body")),"method":str(x.get("method") or "")[:20]})
        for x in (b.get("requests") or [])[:250]:
            if str(x.get("method","")).upper() in ("POST","PUT","PATCH"):
                u=str(x.get("url") or ""); rr=registrable_domain_v21(urlparse(u).hostname or "")
                if rr: events.append({"kind":"network_write","url":u[:700],"root":rr,"cross_site":rr!=root,
                                      "has_body":bool(x.get("has_post_data")),"method":str(x.get("method") or "")})
        for x in b.get("websockets") or []:
            u=str(x.get("url") or ""); rr=registrable_domain_v21(urlparse(u).hostname or "")
            if rr: events.append({"kind":"websocket","url":u[:700],"root":rr,"cross_site":rr!=root,"has_body":False,"method":"WS"})
        cross=[e for e in events if e["cross_site"]]; writes=[e for e in cross if e["has_body"] or e["kind"] in ("beacon","form_submit")]
        if sensitive and writes:
            self.add_finding("Hassas arayüz + harici veri gönderimi","critical",
                "Hassas giriş alanları varken farklı registrable domaine veri taşıyabilen runtime istekleri gözlendi.",
                "data_exfiltration",json.dumps(writes[:12],ensure_ascii=False),.985)
        elif writes:
            self.add_finding("Harici runtime veri gönderimi","medium",
                "Farklı registrable domaine gövdeli runtime trafiği gözlendi; tek başına saldırı kanıtı değildir.",
                "network_exfil",json.dumps(writes[:12],ensure_ascii=False),.72)
        self.results["network_behavior_v22"]={"page_root":root,"sensitive_ui":sensitive,"events":events[:220],
            "cross_site_count":len(cross),"cross_site_write_count":len(writes)}

    def run_js_payload_v23(self):
        b=self.results.get("browser",{}) or {}; h=self.results.get("http",{}) or {}; html=str(b.get("html") or h.get("html") or "")
        if not html: self.results["js_payload_v23"]={"observed":False,"reason":"HTML yok"}; return
        soup=BeautifulSoup(html[:700000],"html.parser")
        scripts="\n".join((x.string or x.get_text() or "") for x in soup.find_all("script"))[:600000]
        decoded=[]; indicators=Counter()
        for m in re.finditer(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{80,}={0,2})(?![A-Za-z0-9+/])',scripts):
            if len(decoded)>=20: break
            try:
                raw=base64.b64decode(m.group(1),validate=True)
                if len(raw)<=65536:
                    text=raw.decode("utf-8","replace")
                    if sum(c.isprintable() or c in "\\r\\n\\t" for c in text)/max(1,len(text))>.82:
                        decoded.append({"encoding":"base64","sample":text[:900]})
            except Exception: pass
        corpus=(scripts+" "+" ".join(x["sample"] for x in decoded)).lower()
        pats={"dynamic_code":r"\beval\s*\(|new\s+function\s*\(","decoder_chain":r"atob\s*\(|fromcharcode|decodeuricomponent\s*\(",
              "credential_terms":r"password|passwd|otp|one.?time|cvv|cvc|credit.?card|seed.?phrase",
              "exfil_api":r"sendbeacon\s*\(|fetch\s*\(|xmlhttprequest","anti_analysis":r"webdriver|devtools|debugger\s*;|headless"}
        for k,p in pats.items(): indicators[k]=len(re.findall(p,corpus,re.I))
        score=min(100,indicators["dynamic_code"]*12+indicators["decoder_chain"]*7+min(indicators["credential_terms"],5)*8+min(indicators["anti_analysis"],5)*8)
        if decoded and indicators["dynamic_code"] and indicators["credential_terms"]:
            self.add_finding("Decode edilmiş scriptte hassas veri + dinamik kod zinciri","high",
                "Statik çözülen metinde hassas veri terimleri ve dinamik kod göstergeleri birlikte bulundu; içerik çalıştırılmadı.",
                "javascript",json.dumps({"indicators":dict(indicators),"samples":decoded[:4]},ensure_ascii=False),.91)
        self.results["js_payload_v23"]={"observed":True,"decoded_count":len(decoded),"indicators":dict(indicators),
            "score":score,"decoded_samples":decoded[:8],"execution_policy":"decoded content never executed"}

    def run_visual_impersonation_v24(self):
        b=self.results.get("browser",{}) or {}; sem=b.get("semantic_dom") or {}; final=b.get("final_url") or self.results.get("final_url") or ""
        root=registrable_domain_v21(urlparse(final).hostname or ""); html=str(b.get("html") or "")
        soup=BeautifulSoup(html[:500000],"html.parser") if html else None; logos=[]; assets=[]
        if soup:
            for tag in soup.find_all(["img","svg","link"],limit=180):
                src=tag.get("src") or tag.get("href") or ""; alt=" ".join(str(tag.get(k,"")) for k in ("alt","title","aria-label","class","id"))
                if src: assets.append(urljoin(final,src)[:700])
                if re.search(r"logo|brand|facebook|google|microsoft|airbnb|paypal|apple|instagram",alt+" "+src,re.I):
                    logos.append({"src":urljoin(final,src)[:700],"label":alt[:300]})
        blob=" ".join([str(sem.get("title",""))," ".join(sem.get("headings") or [])," ".join(sem.get("buttons") or []),str(sem.get("visible_text",""))[:50000]]).lower()
        brands=[x for x in BRAND_KEYWORDS if brand_present(x,blob)]
        mism=(self.results.get("identity_semantic_v18",{}) or {}).get("brand_mismatches") or []
        if mism and logos:
            self.add_finding("Görsel marka kimliği + domain uyuşmazlığı","high",
                "DOM içindeki logo/brand göstergeleri ile marka-domain uyuşmazlığı birlikte gözlendi.",
                "phishing",json.dumps({"brands":brands[:10],"logos":logos[:8],"page_root":root},ensure_ascii=False),.90)
        roots=Counter(registrable_domain_v21(urlparse(x).hostname or "") for x in assets if urlparse(x).hostname)
        self.results["visual_impersonation_v24"]={"page_root":root,"brand_tokens":brands[:20],"logo_candidates":logos[:20],
            "asset_roots":roots.most_common(15),"screenshot_sha256":b.get("screenshot_sha256"),
            "note":"Görsel/DOM kanıtı tek başına güvenlik hükmü değildir."}

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

    def _hamming_hex_v27(self,a,b):
        try:
            if not a or not b or len(a)!=len(b): return None
            return sum(bin(int(x,16)^int(y,16)).count("1") for x,y in zip(a,b))
        except Exception: return None

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
            if resp.status_code!=200: raise RuntimeError("HTTP "+str(resp.status_code))
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
            for u in normalized:
                r=self.enqueue_discovery_v301(u,source=f"v31:{source_id}",source_ref=name,priority=int(cfg.get("priority") or 65))
                if r.get("ok"): accepted+=1
                else: rejected+=1
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
            return {"ok":False,"run_id":run_id,"error":str(exc)[:500],"backoff_seconds":backoff}

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
        independent={e["group"] for e in strong}
        meaningful=independent-{"graph_context","infrastructure"}
        if len(nodes)<3 or not strong or (len(independent)<2 and not meaningful):
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
        status="high_confidence_candidate" if conf>=.80 and len(independent)>=2 else "candidate"
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
          "verified_threat_families":sorted(families),"summary":summary},
          "policy":"Campaign candidate ground truth değildir; shared hosting/IP tek başına malicious hüküm üretmez."}

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
        """Hard evidence is based on provenance/causality, never severity alone."""
        text=self._v322_blob(finding) if hasattr(self,"_v322_blob") else str(finding).lower()
        if any(x in text for x in ("urlhaus","threatfox","sha-256","sha256","known malicious",
                                   "malware family","c2","command and control","exact ioc")):
            return True
        source=any(x in text for x in ("password","parola","otp","cvv","cvc","cookie","token","credential"))
        sink=any(x in text for x in ("cross-origin","cross origin","external destination","harici hedef",
                                     "sendbeacon","websocket","xhr post","fetch post","form action",
                                     "destination_host","sink_host"))
        generic=("storage/cookie + network + obfuscation" in text or
                 "input events + network + obfuscation" in text)
        return bool(source and sink and not generic)


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
        """V32.3.21 single decision authority.

        Canonical sensor findings remain observable, but legacy URL/brand summary rules
        cannot directly become the phishing category score. Phishing authority belongs
        to the post-guard independent phishing hypothesis. Other threat families keep
        their canonical, guarded scores so malware/exfil/JS evidence is never erased.

        External intelligence is already held at zero contribution by Feed OFF guard.
        """
        canonical=self.results.get("canonical_scoring_v3222") or {}
        cats=dict(canonical.get("category_scores") or {})
        ip=(self.results.get("post_guard_phishing_fusion_v32310") or
            self.results.get("independent_phishing_v323") or {})
        phishing_score=max(0,min(100,int(ip.get("score") or 0)))
        legacy_phishing=int(cats.get("phishing") or 0)
        temporal=self.results.get("temporal_threat_memory_v3241") or self.results.get("temporal_history") or {}
        temporal_context=bool(temporal.get("score_eligible") and temporal.get("prior_hard_evidence"))
        cats["phishing"]=phishing_score

        # Overall engine authority is the strongest guarded threat-family hypothesis.
        # Do not add unrelated categories together merely to manufacture corroboration.
        threat=max([int(v or 0) for v in cats.values()] or [0])

        canonical["legacy_phishing_diagnostic_score_v32321"]=legacy_phishing
        canonical["phishing_score"]=phishing_score
        canonical["category_scores"]=cats
        canonical["threat_score"]=threat
        canonical["decision_authority"]="guarded_family_hypotheses_v32321"
        self.results["canonical_scoring_v3222"]=canonical
        self.results["canonical_category_scores_v3222"]=cats
        self.results["threat_score"]=threat
        self.results.setdefault("scores",{})["threat"]=threat
        self.results["risk_score"]=threat

        # Keep legacy containers synchronized, never authoritative.
        legacy=self.results.get("category_scores")
        if isinstance(legacy,dict):
            mapping={
              "Phishing / Marka Taklidi":"phishing","Kimlik Bilgisi Hırsızlığı":"credential_theft",
              "Malware / Zararlı İndirme":"malware","Şüpheli JavaScript / Davranış":"javascript",
              "Yönlendirme Kötüye Kullanımı":"redirect","Gizlilik / Veri Sızdırma Riski":"privacy",
              "Sosyal Mühendislik":"social_engineering"
            }
            for label,key in mapping.items(): legacy[label]=int(cats.get(key) or 0)

        out={
          "engine_score":threat,
          "category_scores":cats,
          "phishing_authority":"post_guard_phishing_fusion_v32310",
          "phishing_engine_score":phishing_score,"historical_threat_context":temporal_context,
          "legacy_phishing_diagnostic_score":legacy_phishing,
          "legacy_phishing_can_decide":False,
          "feed_off":bool(self.results.get("_feed_off_v3231")),
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

    def source_level_behavior_guard_v322(self):
        """
        Remove/demote generic modern-web behavior at the source-of-truth finding layer.
        Hard IOC / explicit cross-origin credential exfil / malware-hash evidence is preserved.
        """
        causal=self._v322_sensitive_external_causal_chain()
        findings=list(self.results.get("findings") or [])
        kept=[]; suppressed=[]

        generic_titles=(
            "token/cookie veri sızdırma korelasyonu",
            "girdi yakalama ve aktarım korelasyonu",
            "çoklu tehdit davranışı korelasyonu",
            "çoklu davranış korelasyonu"
        )
        for f0 in findings:
            f=dict(f0)
            text=self._v322_blob(f)
            hard=False
            if hasattr(self,"_v321_is_hard_evidence"):
                try: hard=self._v321_is_hard_evidence(f)
                except Exception: hard=False
            hard = hard or any(x in text for x in (
                "urlhaus","threatfox","openphish","phishtank","sha256 ioc","sha-256 ioc",
                "malware hash","known malicious","cross-origin credential","credential exfil"))

            generic_title=any(t in text for t in generic_titles)
            generic_pattern=(
                (("storage" in text or "cookie" in text or "input event" in text or "girdi yakalama" in text)
                 and "network" in text)
                or ("dynamic script loader" in text)
            )

            if (generic_title or generic_pattern) and not hard and not causal:
                # Keep only as contextual telemetry; it must not enter threat-category/fusion scoring.
                f["severity"]="info"
                f["confidence"]=min(float(f.get("confidence") or .5),.20)
                f["score_eligible_v322"]=False
                f["source_guard_v322"]="generic_web_behavior_without_causal_exfil"
                suppressed.append(f)
                continue

            f["score_eligible_v322"]=True
            kept.append(f)

        # Score/fusion source of truth contains only eligible evidence.
        self.results["contextual_findings_v322"]=suppressed
        self.results["findings"]=kept
        report={"causal_sensitive_external_chain":causal,
                "score_eligible_findings":len(kept),
                "context_only_findings":len(suppressed)}
        self.results["source_level_behavior_guard_v322"]=report
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

    def _v323_add(self,title,severity,description,category,evidence,confidence,expert):
        self.add_finding(title,severity,description,category,evidence,confidence)
        f=self.results["findings"][-1]
        f["source_expert"]=expert
        f["producer"]="independent_phishing_v323"
        f["feed_independent"]=True
        return f

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

    def phishing_sensor_observatory_v3231(self):
        """Explain what the phishing engine could actually observe.
        This is diagnostic only and never manufactures threat evidence.
        """
        b=self.results.get("browser") or {}
        h=self.results.get("http") or {}
        ip=self.results.get("independent_phishing_v323") or {}
        final=b.get("final_url") or self.results.get("final_url") or self.results.get("url") or ""
        sem=b.get("semantic_dom") or self.results.get("static_semantic_v3232") or {}
        hooks=b.get("runtime_hooks") or {}
        reqs=b.get("requests") or []

        def state(observed, available=True, detail=None):
            return {
                "state":"observed" if observed else ("not_observed" if available else "unavailable"),
                "detail":detail
            }

        inputs=sem.get("inputs") or []
        forms=b.get("forms") or self.results.get("forms") or []
        iframes=sem.get("iframes") or b.get("frames") or self.results.get("iframes") or []
        frame_surfaces=b.get("frame_surfaces") or []
        shadow_inputs=int(sem.get("shadow_input_count") or 0)
        shadow_forms=int(b.get("shadow_form_count") or 0)
        frame_sensitive=0
        for fs in frame_surfaces:
            for inp in (fs.get("inputs") or []):
                blob=" ".join(str(inp.get(k,"")) for k in ("type","name","id","placeholder","autocomplete")).lower()
                if str(inp.get("type","")).lower()=="password" or re.search(r"password|passwd|otp|one.?time|verification|pin|cvv|cvc|cc-number|card|iban|wallet",blob,re.I):
                    frame_sensitive+=1
        mutations=b.get("dom_mutations") or {}
        runtime_writes=(hooks.get("fetches") or [])+(hooks.get("xhr") or [])+(hooks.get("beacons") or [])+(hooks.get("form_submits") or [])
        browser_ok=bool(b.get("success"))
        http_ok=bool(h.get("body_analyzed") or h.get("success"))
        visible=sem.get("visible_text") or ""
        title=sem.get("title") or b.get("title") or h.get("title") or ""

        sensors={
          "http_body":state(http_ok, True, f"status={h.get('status') or h.get('status_code')}; content_type={h.get('content_type')}"),
          "browser_navigation":state(browser_ok, True, f"final_url={final}"),
          "rendered_dom":state(bool(visible or title or inputs or forms), browser_ok,
                               f"inputs={len(inputs)}; forms={len(forms)}; visible_chars={len(str(visible))}"),
          "iframes":state(bool(iframes or frame_surfaces), browser_ok, f"declared={len(iframes)}; inspected={len(frame_surfaces)}"),
          "shadow_dom":state(bool(shadow_inputs or shadow_forms), browser_ok, f"shadow_inputs={shadow_inputs}; shadow_forms={shadow_forms}"),
          "frame_credential_surface":state(bool(frame_sensitive), browser_ok, f"sensitive_controls={frame_sensitive}; diagnostic_only=true"),
          "credential_surface":state(bool(ip.get("credential_intent")), browser_ok,
                                     f"sensitive_count={ip.get('sensitive_count',0)}"),
          "dom_mutation":state(bool(mutations), browser_ok, str(mutations)[:1000]),
          "runtime_network":state(bool(reqs or runtime_writes), browser_ok,
                                  f"requests={len(reqs)}; runtime_writes={len(runtime_writes)}"),
          "cross_origin_sink":state(bool(ip.get("cross_form_count") or ip.get("cross_write_count")), browser_ok,
                                    f"cross_forms={ip.get('cross_form_count',0)}; cross_writes={ip.get('cross_write_count',0)}"),
          "identity":state(bool(ip.get("brand_claims")), browser_ok,
                           f"claims={ip.get('brand_claims',[])[:5]}"),
          "visual":state(bool(ip.get("visual_score")), browser_ok,
                         f"score={ip.get('visual_score',0)}; mismatch={ip.get('visual_mismatch',False)}")
        }

        unavailable=[k for k,v in sensors.items() if v["state"]=="unavailable"]
        not_observed=[k for k,v in sensors.items() if v["state"]=="not_observed"]
        observed=[k for k,v in sensors.items() if v["state"]=="observed"]

        # Diagnostic reason for low engine score. Absence is not safety.
        reasons=[]
        if not browser_ok:
            reasons.append("browser_navigation_unavailable")
            if b.get("decision")=="browser_timeout" or b.get("failure_kind") in ("browser_timeout","parent_worker_deadline"):
                reasons.append("browser_worker_timeout")
        if sensors["rendered_dom"]["state"]!="observed": reasons.append("rendered_dom_not_observed")
        if sensors["credential_surface"]["state"]!="observed": reasons.append("credential_surface_not_observed")
        if sensors["cross_origin_sink"]["state"]!="observed": reasons.append("cross_origin_sink_not_observed")
        if len(ip.get("decisive_experts") or [])<2: reasons.append("fewer_than_two_decisive_experts")

        report={
          "mode":"diagnostic_only",
          "final_url":final,
          "engine_only_score":int(ip.get("score") or 0),
          "engine_only_verdict":ip.get("verdict") or "not_run",
          "decisive_experts":ip.get("decisive_experts") or [],
          "sensors":sensors,
          "observed":observed,
          "not_observed":not_observed,
          "unavailable":unavailable,
          "diagnostic_reasons":reasons,
          "browser_decision":b.get("decision"),
          "browser_failure_kind":b.get("failure_kind"),
          "browser_timings_ms":b.get("timings_ms") or {},
          "tls_observation_mode":b.get("tls_observation_mode") or "strict_or_not_run",
          "static_http_dom_length":int((self.results.get("static_semantic_v3232") or {}).get("dom_length") or 0),
          "warning":"not_observed/unavailable never means safe"
        }
        self.results["phishing_observatory_v3231"]=report
        return report


    def credential_flow_deep_observatory_v32328(self):
        """V32.3.28 diagnostic lens for credential-flow misses.

        Never submits a form, clicks a live control, executes extracted source, or adds threat score.
        It compares verified static HTML with the rendered browser surface and reports exactly
        which credential-flow stage was observed or missed.
        """
        static=self.results.get("static_source_intelligence_v32317") or {}
        sem=self.results.get("static_semantic_v3232") or {}
        b=self.results.get("browser") or {}
        bsem=b.get("semantic_dom") or {}
        hooks=b.get("runtime_hooks") or {}
        page_url=b.get("final_url") or self.results.get("final_url") or self.results.get("url") or ""
        page_root=get_root_domain(urlparse(page_url).hostname or "")

        def inp_rows(src):
            out=[]
            for x in (src or [])[:120]:
                if not isinstance(x,dict): continue
                blob=" ".join(str(x.get(k) or "") for k in ("type","name","id","placeholder","autocomplete","aria-label","label","role")).lower()
                out.append({"type":x.get("type"),"name":x.get("name"),"id":x.get("id"),"descriptor":blob[:500],
                            "secret":bool(re.search(r"password|passwd|passcode|parola|şifre|otp|one.?time|verification.?code|pin|cvv|cvc|card|iban|seed|recovery",blob,re.I)),
                            "identity":bool(re.search(r"email|e-mail|username|user.?name|login|phone|mobile|account|müşteri|kullanıcı|telefon|eposta",blob,re.I))})
            return out

        static_inputs=inp_rows(sem.get("inputs") or [])
        rendered_inputs=inp_rows(bsem.get("inputs") or [])
        static_forms=static.get("forms") or []
        rendered_forms=b.get("forms") or []
        frame_surfaces=b.get("frame_surfaces") or []
        frame_inputs=[]
        for fr in frame_surfaces[:40]:
            for x in inp_rows(fr.get("inputs") or []):
                y=dict(x); y["frame_url"]=fr.get("url"); frame_inputs.append(y)

        flow=static.get("credential_flow_v32327") or {}
        sinks=[]
        for x in (flow.get("js_sink_literals") or []):
            if isinstance(x,dict): sinks.append(dict(x))
        runtime=[]
        for kind in ("fetches","xhr","beacons","form_submits"):
            for x in (hooks.get(kind) or [])[:80]:
                if isinstance(x,dict):
                    u=x.get("url") or x.get("action") or x.get("target") or ""
                    rr=get_root_domain(urlparse(urljoin(page_url,str(u))).hostname or "") if u else ""
                    runtime.append({"kind":kind,"url":str(u)[:700],"root":rr,"cross_root":bool(rr and page_root and rr!=page_root),
                                    "method":x.get("method")})

        script_text=""
        try:
            # bounded verified static source only; diagnostic extraction, never execution
            raw=(self.results.get("http") or {}).get("body") or self.results.get("raw_html") or ""
            if raw:
                sp=BeautifulSoup(str(raw)[:1500000],"html.parser")
                script_text="\n".join((z.string or z.get_text() or "")[:200000] for z in sp.find_all("script")[:160] if not z.get("src"))[:800000]
        except Exception:
            script_text=""
        # Fall back to already extracted static report if raw body is intentionally not retained.
        handler_patterns={
          "submit_listener":r"addEventListener\s*\(\s*['\"]submit|onsubmit\s*=",
          "click_listener":r"addEventListener\s*\(\s*['\"]click|onclick\s*=",
          "prevent_default":r"preventDefault\s*\(",
          "formdata":r"new\s+FormData\s*\(|FormData\s*\(",
          "password_value_read":r"password[^\n]{0,160}\.value|querySelector\s*\([^)]*password[^)]*\)[^\n]{0,120}\.value",
          "identity_value_read":r"(?:email|username|login)[^\n]{0,160}\.value",
          "network_write":r"fetch\s*\(|XMLHttpRequest|axios\.(?:post|put|patch)|sendBeacon\s*\(",
          "dynamic_dom":r"createElement\s*\(|innerHTML\s*=|insertAdjacentHTML\s*\("
        }
        handlers={k:bool(re.search(v,script_text,re.I)) if script_text else bool(flow.get("js_submit_handlers")) if k in ("submit_listener","click_listener","prevent_default") else False for k,v in handler_patterns.items()}

        static_secret=sum(1 for x in static_inputs if x["secret"]); static_ident=sum(1 for x in static_inputs if x["identity"])
        render_secret=sum(1 for x in rendered_inputs if x["secret"]); render_ident=sum(1 for x in rendered_inputs if x["identity"])
        frame_secret=sum(1 for x in frame_inputs if x["secret"]); frame_ident=sum(1 for x in frame_inputs if x["identity"])
        cross_runtime=[x for x in runtime if x.get("cross_root")]
        cross_static=[x for x in sinks if x.get("external")]
        source_seen=bool(static_secret or static_ident or static.get("credential_source") or flow.get("js_dynamic_credential"))
        rendered_seen=bool(render_secret or render_ident or frame_secret or frame_ident)
        handler_seen=bool(any(handlers.values()) or flow.get("js_submit_handlers"))
        sink_seen=bool(cross_runtime or cross_static or static.get("external_sensitive_forms"))

        if not ((self.results.get("http") or {}).get("body_analyzed") or (b.get("success"))): stage="observation_unavailable"
        elif not source_seen and not rendered_seen and bool((b.get("stateful_surface") or {}).get("interaction_gate_suspected")): stage="interaction_gated_surface_not_reached"
        elif not source_seen and not rendered_seen: stage="credential_surface_not_observed"
        elif source_seen and not rendered_seen: stage="static_surface_not_rendered_or_interaction_gated"
        elif rendered_seen and not handler_seen: stage="credential_surface_seen_handler_not_observed"
        elif handler_seen and not sink_seen: stage="handler_seen_destination_not_observed"
        elif sink_seen: stage="credential_flow_components_observed_check_causality_fusion"
        else: stage="inconclusive"

        report={
          "mode":"diagnostic_only_no_score", "version":APP_VERSION, "page_root":page_root, "miss_stage":stage,
          "static":{"inputs":len(static_inputs),"identity":static_ident,"secret":static_secret,"forms":len(static_forms),
                    "credential_source":bool(static.get("credential_source")),"auth_intent":bool(static.get("auth_intent")),
                    "js_dynamic_credential":bool(flow.get("js_dynamic_credential")),"js_submit_handlers":bool(flow.get("js_submit_handlers"))},
          "rendered":{"inputs":len(rendered_inputs),"identity":render_ident,"secret":render_secret,"forms":len(rendered_forms),
                      "shadow_inputs":int(bsem.get("shadow_input_count") or 0),"shadow_forms":int(b.get("shadow_form_count") or 0),
                      "frames_inspected":len(frame_surfaces),"frame_identity":frame_ident,"frame_secret":frame_secret},
          "handlers":handlers,
          "destinations":{"static_literals":sinks[:30],"static_cross_root":cross_static[:20],"runtime":runtime[:50],
                          "runtime_cross_root":cross_runtime[:20],"external_sensitive_forms":(static.get("external_sensitive_forms") or [])[:20]},
          "comparison":{"static_surface_seen":source_seen,"rendered_surface_seen":rendered_seen,"handler_seen":handler_seen,"sink_seen":sink_seen,
                        "dom_delta_inputs":len(rendered_inputs)-len(static_inputs),"dom_delta_forms":len(rendered_forms)-len(static_forms)},
          "stateful_surface": b.get("stateful_surface") or {},
          "surface_samples":{
              "static_inputs":static_inputs[:40], "rendered_inputs":rendered_inputs[:40], "frame_inputs":frame_inputs[:40],
              "static_forms":static_forms[:30], "rendered_forms":rendered_forms[:30],
              "frame_surfaces":[{"url":x.get("url"),"title":x.get("title"),"input_count":len(x.get("inputs") or []),"form_count":len(x.get("forms") or [])} for x in frame_surfaces[:30] if isinstance(x,dict)],
          },
          "pipeline_handoff":{
              "static_credential_source":bool(static.get("credential_source")),
              "static_external_sensitive_forms":len(static.get("external_sensitive_forms") or []),
              "static_proven_edges":len(((static.get("js_dataflow") or {}).get("proven_edges") or [])),
              "independent_phishing_score":int((self.results.get("independent_phishing_v323") or {}).get("score") or 0),
              "canonical_credential_score":int(((self.results.get("canonical_category_scores_v3222") or {}).get("credential_theft") or 0)),
              "canonical_phishing_score":int(((self.results.get("canonical_category_scores_v3222") or {}).get("phishing") or 0)),
          },
          "safety":"Live controls are not clicked and forms are never submitted. Extracted JavaScript is not executed by this diagnostic.",
          "interpretation":"A missing stage is an observation/sensor gap, not evidence that the target is safe."
        }
        self.results["credential_deep_observatory_v32328"]=report
        return report

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

    def independent_phishing_engine_v323(self):
        """
        Feed-independent phishing engine.
        OpenPhish/PhishTank/reputation are deliberately excluded from this decision.
        Independent experts: identity, credential intent, submission/exfil, visual,
        runtime/interaction, URL/infrastructure and social-engineering semantics.
        """
        b=self.results.get("browser") or {}
        h=self.results.get("http") or {}
        final=b.get("final_url") or self.results.get("final_url") or self.results.get("url") or ""
        host=(urlparse(final).hostname or "").lower()
        root=get_root_domain(host)
        static_sem=self.results.get("static_semantic_v3232") or {}
        sem=b.get("semantic_dom") or static_sem or {}
        forms=b.get("forms") or self.results.get("forms") or []
        reqs=b.get("requests") or []
        hooks=b.get("runtime_hooks") or {}
        static_src=self.results.get("static_source_intelligence_v32317") or {}

        title=str(sem.get("title") or b.get("title") or h.get("title") or "")
        headings=" ".join(map(str,sem.get("headings") or []))
        buttons=" ".join(map(str,sem.get("buttons") or []))
        visible=str(sem.get("visible_text") or "")[:120000]
        identity_surfaces=sem.get("identity_surfaces") or {}

        # V32.3.11 Strong Identity Claim Gate.
        # A brand mention in body/footer/help/partner text is NOT an identity claim.
        # Only first-party identity surfaces may activate the identity expert.
        identity_parts=[title]
        identity_parts.extend(list(map(str,(sem.get("headings") or [])[:8])))
        for k in ("og_title","app_name","header_text","logo_text"):
            if identity_surfaces.get(k): identity_parts.append(str(identity_surfaces.get(k)))
        identity_blob=" ".join(identity_parts).lower()[:20000]
        context_blob=(" ".join((title,headings,buttons,visible))).lower()

        claims=[]; contextual_brand_mentions=[]
        ambiguous_identity_tokens={"live"}
        for brand in BRAND_KEYWORDS:
            if brand in ambiguous_identity_tokens:
                continue
            strong_claim=brand_present(brand,identity_blob)
            context_mention=brand_present(brand,context_blob)
            if strong_claim:
                claims.append({"brand":brand,"related":self._v323_identity_relation(brand,root),
                               "claim_strength":"strong_first_party_surface"})
            elif context_mention:
                contextual_brand_mentions.append(brand)
        # V32.3.18 source-to-fusion bridge: verified 2xx static source is a real sensor.
        # It can restore identity evidence when Chromium/DOM observation is unavailable.
        for brand in (static_src.get("brand_claims") or []):
            if not any(x.get("brand")==brand for x in claims):
                claims.append({"brand":brand,"related":self._v323_identity_relation(brand,root),
                               "claim_strength":"verified_static_first_party_surface","sensor":"static_source"})
        mismatches=[x for x in claims if not x["related"]]

        # Expert 2: credential/payment/identity intent.
        sensitive=[]
        for inp in sem.get("inputs") or []:
            blob=" ".join(str(inp.get(k,"")) for k in
                          ("type","name","id","placeholder","autocomplete","label")).lower()
            if str(inp.get("type","")).lower()=="password" or re.search(
                r"password|passwd|parola|şifre|otp|one.?time|verification|verify|pin|cvv|cvc|cc-number|card|kart|iban|seed|recovery|wallet|ssn|identity",
                blob,re.I):
                sensitive.append(inp)
        for f in forms:
            if f.get("has_password") or f.get("has_otp") or f.get("has_card"):
                sensitive.append({"form":True,"action":f.get("action")})
        intent_terms=re.findall(
            r"\b(sign\s?in|log\s?in|verify|verification|confirm|account|password|payment|billing|wallet|otp|security alert|suspended|blocked|limited)\b",
            context_blob,re.I)
        intent_term_count=len(set(x.lower() for x in intent_terms))
        # V32.3.11 Credential Intent Gate.
        # Semantic words alone are contextual. A decisive credential vote requires
        # an observed sensitive control/form. This prevents normal account/help copy
        # from becoming a credential-theft expert.
        static_sensitive_count=int(static_src.get("sensitive_controls") or 0)
        static_credential=bool(static_src.get("credential_source"))
        if static_credential and not sensitive:
            sensitive.append({"static_source":True,"count":static_sensitive_count})
        credential_intent=bool(sensitive or static_credential)
        credential_context=bool(intent_term_count)

        # Expert 3: concrete submission/exfil destination.
        cross_forms=[]; writes=[]; cross_writes=[]
        for f in forms:
            try:
                u=urljoin(final,str(f.get("action") or ""))
                rr=get_root_domain(urlparse(u).hostname or "")
                if rr and rr!=root and (f.get("has_password") or f.get("has_otp") or f.get("has_card")):
                    cross_forms.append({"url":u,"root":rr})
            except Exception: pass
        for q in reqs:
            if str(q.get("method") or "").upper() not in ("POST","PUT","PATCH"): continue
            u=str(q.get("url") or "")
            writes.append(u)
            try:
                rr=get_root_domain(urlparse(u).hostname or "")
                if rr and rr!=root: cross_writes.append({"url":u,"root":rr})
            except Exception: pass
        for q in (hooks.get("fetches") or [])+(hooks.get("xhr") or [])+(hooks.get("beacons") or [])+(hooks.get("form_submits") or []):
            u=urljoin(final,str(q.get("url") or q.get("action") or ""))
            method=str(q.get("method") or "POST").upper()
            if method not in ("POST","PUT","PATCH") and q not in (hooks.get("beacons") or []): continue
            try:
                rr=get_root_domain(urlparse(u).hostname or "")
                if rr and rr!=root: cross_writes.append({"url":u,"root":rr})
            except Exception: pass
        static_external=list(static_src.get("external_sensitive_forms") or [])
        if static_external:
            cross_forms.extend({"url":x.get("action"),"root":x.get("action_root"),"sensor":"static_source"} for x in static_external)
        flow327=static_src.get("credential_flow_v32327") or {}
        if flow327.get("js_credential_sink"):
            cross_forms.extend({"url":x.get("url"),"root":x.get("root"),"sensor":"credential_flow_v32327"}
                               for x in (flow327.get("js_external_sinks") or [])[:12])
        exfil=bool(cross_forms or (credential_intent and cross_writes))

        # Expert 4: verified visual baseline mismatch.
        vs=self.results.get("visual_similarity_v27") or {}
        best=vs.get("best") or {}
        visual_score=float(best.get("score") or 0)
        visual_mismatch=False
        if best and visual_score>=82:
            try: visual_mismatch=get_root_domain(best.get("baseline_domain") or "")!=root
            except Exception: pass

        # Expert 5: staged/runtime interaction.
        dm=b.get("dom_mutations") or {}
        js_added=int(dm.get("password_fields_added",0) or 0)>0
        final_path=(urlparse(final).path or "/").lower()
        staged_auth=js_added or any(x in final_path for x in ("login","signin","verify","verification","auth","wallet","payment","checkout","otp"))
        staged_auth=bool(staged_auth and credential_intent)

        # V32.3.9: once the destination ownership graph exists, it is authoritative
        # for credential/exfil causality. Cross-origin telemetry by itself is not exfiltration.
        graph_v3238=self.results.get("causal_destination_graph_v3238") or {}
        if graph_v3238:
            graph_exfil=bool(graph_v3238.get("concrete_exfil"))
            strong_edges=list(graph_v3238.get("strong_causal_edges") or [])
            # A verified static <form action> edge is concrete causality too. Runtime graph
            # may be empty when Chromium times out, so it must not erase static evidence.
            static_exfil=bool(static_external)
            exfil=bool(graph_exfil or static_exfil)
            if graph_exfil:
                cross_writes=[{"url":e.get("sink"),"root":e.get("sink_root"),"edge_id":e.get("edge_id")} for e in strong_edges]
            elif not static_exfil:
                cross_forms=[]
                cross_writes=[]

        # Expert 6: URL/infrastructure context. Never sufficient alone.
        shared=next((x for x in ("vercel.app","netlify.app","pages.dev","github.io","firebaseapp.com","web.app","workers.dev")
                     if host==x or host.endswith("."+x)),None)
        url_blob=(host+" "+(urlparse(final).path or "")).lower()
        lexical=bool(re.search(r"(login|signin|verify|account|secure|wallet|payment|support|auth|recover|unlock)",url_blob))
        raw_ip=host_is_raw_ip(host)
        infrastructure_context=bool(shared or lexical or raw_ip)

        # Expert 7: social-engineering semantics. Context unless corroborated.
        urgency=bool(re.search(
            r"(account.{0,35}(suspended|blocked|limited|locked)|verify.{0,30}(identity|account)|"
            r"confirm.{0,30}account|update.{0,30}(payment|billing|information)|unusual.{0,30}activity|"
            r"security.{0,30}alert|hesab.{0,35}(askıya|bloke|kapat)|kimli.{0,30}doğrula)",
            context_blob,re.I))

        experts={}
        if mismatches:
            experts["identity"]={"weight":34,"detail":"strong brand claim on unrelated registrable domain",
                                 "brands":[x["brand"] for x in mismatches[:6]]}
        if credential_intent:
            experts["credential_intent"]={"weight":26,"detail":f"sensitive_fields={len(sensitive)}; intent_terms={intent_term_count}",
                                          "gate":"observed_sensitive_control"}
        elif credential_context:
            experts["credential_context"]={"weight":0,"detail":f"intent_terms={intent_term_count}; no sensitive control observed",
                                           "gate":"context_only_no_vote"}
        if exfil:
            experts["submission_exfil"]={"weight":38,"detail":f"cross_forms={len(cross_forms)}; cross_writes={len(cross_writes)}"}
        if visual_mismatch:
            experts["visual"]={"weight":30,"detail":f"verified_baseline_similarity={visual_score}"}
        if staged_auth:
            experts["runtime_stage"]={"weight":18,"detail":f"js_added_password={js_added}; final_path={final_path[:180]}"}
        if infrastructure_context:
            experts["infrastructure"]={"weight":10,"detail":f"shared={shared}; lexical={lexical}; raw_ip={raw_ip}"}
        if urgency:
            experts["social_engineering"]={"weight":12,"detail":"urgency/account-pressure language"}
        if contextual_brand_mentions:
            experts["brand_context"]={"weight":0,"detail":"passive/contextual brand mentions",
                                      "brands":contextual_brand_mentions[:12],"gate":"context_only_no_vote"}

        # Causal/corroboration rules. Feed evidence is intentionally absent.
        score=0; reasons=[]
        if mismatches and credential_intent:
            score+=48; reasons.append("identity_mismatch+credential_intent")
        if mismatches and exfil:
            score+=34; reasons.append("identity_mismatch+submission_exfil")
        if credential_intent and exfil:
            score+=52; reasons.append("credential_intent+submission_exfil")
        if visual_mismatch and credential_intent:
            score+=35; reasons.append("visual_impersonation+credential_intent")
        if staged_auth and (mismatches or exfil):
            score+=18; reasons.append("runtime_stage+independent_risk")
        if infrastructure_context and mismatches and credential_intent:
            score+=10; reasons.append("infrastructure+identity+credential")
        if urgency and mismatches and credential_intent:
            score+=10; reasons.append("social_engineering+identity+credential")

        # Structural phishing without a recognized brand: sensitive collection plus external sink.
        if not mismatches and credential_intent and exfil:
            score=max(score,72)
        # Brand impersonation with sensitive collection should be high even before a submit is observed.
        if mismatches and credential_intent:
            score=max(score,68)
        if visual_mismatch and credential_intent and mismatches:
            score=max(score,82)

        independent=set()
        for name in experts:
            if name in ("identity","credential_intent","submission_exfil","visual","runtime_stage","infrastructure","social_engineering"):
                independent.add(name)
        # Context-only experts cannot manufacture a verdict.
        decisive={x for x in independent if x in ("identity","credential_intent","submission_exfil","visual","runtime_stage")}
        if len(decisive)<2:
            score=min(score,39)
        score=min(100,int(round(score)))

        verdict=("high_confidence_phishing" if score>=75 else
                 "probable_phishing" if score>=55 else
                 "suspicious" if score>=25 else "insufficient_independent_evidence")

        report={"feed_independent":True,"host":host,"root":root,"score":score,"verdict":verdict,
                "experts":experts,"decisive_experts":sorted(decisive),"reasons":reasons,
                "brand_claims":claims[:12],"brand_mismatches":mismatches[:12],
                "contextual_brand_mentions":contextual_brand_mentions[:20],
                "credential_intent":credential_intent,"credential_context":credential_context,
                "static_source_bridge":{"active":bool(static_src),"credential_source":static_credential,"sensitive_controls":static_sensitive_count,"external_sensitive_forms":len(static_external)},
                "intent_term_count":intent_term_count,"sensitive_count":len(sensitive),
                "cross_form_count":len(cross_forms),"cross_write_count":len(cross_writes),
                "visual_mismatch":visual_mismatch,"visual_score":visual_score,
                "post_guard":bool(graph_v3238),
                "expert_status":{
                    "identity":{"active":bool(mismatches),"reason":"unrelated_brand_claim" if mismatches else "no_unrelated_brand_claim"},
                    "credential_intent":{"active":bool(credential_intent),"reason":f"sensitive_count={len(sensitive)}; intent_terms={intent_term_count}",
                                         "guard":"observed_sensitive_control_required" if credential_intent else "context_only_no_sensitive_control"},
                    "submission_exfil":{"active":bool(exfil),"reason":"concrete_sensitive_source_to_unrelated_sink" if exfil else ("rejected_by_destination_ownership_graph" if graph_v3238 else "not_observed")},
                    "visual":{"active":bool(visual_mismatch),"reason":"verified_visual_mismatch" if visual_mismatch else "not_observed"},
                    "runtime_stage":{"active":bool(staged_auth),"reason":"staged_auth_behavior" if staged_auth else "not_observed"},
                    "social_engineering":{"active":bool(urgency),"reason":"corroborated_only" if urgency else "not_observed"}
                },
                "policy":"feed/reputation is an independent sensor, never a prerequisite; identity requires a first-party claim surface; credential intent requires an observed sensitive control; post-guard fusion reads only causal destination ownership; derived fusion summaries never vote"}
        self.results["independent_phishing_v323"]=report

        if score>=55 and len(decisive)>=2:
            sev="critical" if score>=85 and ("submission_exfil" in decisive or "visual" in decisive) else "high"
            self._v323_add("Bağımsız phishing motoru: çoklu kanıt korelasyonu",sev,
                "Feed/reputation kullanılmadan birden fazla bağımsız phishing uzmanı aynı saldırı hipotezini destekledi.",
                "phishing",json.dumps({"score":score,"reasons":reasons,"experts":experts},ensure_ascii=False)[:5000],
                min(.98,.72+.06*len(decisive)),"independent_phishing")
        if exfil and credential_intent:
            self._v323_add("Hassas veri kaynağı → harici gönderim zinciri","critical",
                "Hassas giriş yüzeyi ile farklı registrable domaine giden yazma/gönderim hedefi aynı taramada gözlendi.",
                "credential_theft",json.dumps({"cross_forms":cross_forms[:8],"cross_writes":cross_writes[:8]},ensure_ascii=False)[:5000],
                .98,"submission_exfil")
        return report

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

    def behavioral_brain_v3234(self):
        """Fuse strong credential intent with concrete interaction/sink evidence.

        This module is deliberately causal: generic words, a password field alone,
        or generic network activity cannot create a high-confidence verdict.
        """
        b = self.results.get("browser") or {}
        sem = b.get("semantic_dom") or self.results.get("static_semantic_v3232") or {}
        forms = b.get("forms") or self.results.get("forms") or []
        hooks = b.get("runtime_hooks") or {}
        requests = b.get("requests") or []
        final_url = b.get("final_url") or (self.results.get("http") or {}).get("final_url") or self.results.get("analyzed_url") or ""
        root = get_root_domain(urlparse(final_url).hostname or "") if final_url else ""

        strong_text_parts = []
        for key in ("title", "headings", "buttons", "labels", "visible_text"):
            v = sem.get(key)
            if isinstance(v, list):
                strong_text_parts.extend(str(x) for x in v[:80])
            elif v:
                strong_text_parts.append(str(v))
        text = " ".join(strong_text_parts).lower()[:160000]

        # Credential intent is semantic, not tied to one HTML input type.
        cred_terms = re.compile(
            r"\b(login|log in|sign in|signin|password|passcode|username|user id|email address|"
            r"verification code|one[- ]?time|otp|pin|security code|cvv|cvc|card number|"
            r"giriş|oturum aç|parola|şifre|doğrulama kodu|tek kullanımlık|kart numarası)\b", re.I
        )
        cred_semantic = bool(cred_terms.search(text))

        sensitive_controls = []
        for f in forms:
            if f.get("has_password") or f.get("has_otp") or f.get("has_card"):
                sensitive_controls.append({
                    "source": f.get("source") or "form",
                    "action": str(f.get("action") or "")[:500],
                    "external_action": bool(f.get("external_action")),
                    "password": bool(f.get("has_password")),
                    "otp": bool(f.get("has_otp")),
                    "card": bool(f.get("has_card")),
                })

        # Browser semantic snapshots may expose custom controls without normal <form>.
        for inp in (sem.get("inputs") or [])[:120]:
            blob = " ".join(str(inp.get(k, "")) for k in ("type","name","id","placeholder","autocomplete","aria_label")).lower()
            if re.search(r"password|passcode|otp|one.?time|verification|pin|cvv|cvc|card|username|email", blob, re.I):
                sensitive_controls.append({"source":"semantic_dom","descriptor":blob[:500]})

        def _targets(items):
            out=[]
            for x in items or []:
                if isinstance(x, str):
                    u=x
                elif isinstance(x, dict):
                    u=x.get("url") or x.get("target") or x.get("action") or ""
                else:
                    continue
                if not u:
                    continue
                try:
                    h=urlparse(urljoin(final_url, u)).hostname or ""
                    rr=get_root_domain(h) if h else ""
                    out.append({"url":str(u)[:700],"root":rr,"external":bool(rr and root and rr != root)})
                except Exception:
                    pass
            return out

        runtime_targets=[]
        for k in ("fetches","xhr","beacons","form_submits"):
            runtime_targets += _targets(hooks.get(k) or [])
        # Request telemetry is context unless it is a write request.
        write_targets=[]
        for r in requests[:500]:
            if not isinstance(r, dict):
                continue
            method=str(r.get("method") or "").upper()
            if method not in ("POST","PUT","PATCH"):
                continue
            write_targets += _targets([r])

        form_targets=[]
        for f in forms:
            if f.get("action"):
                form_targets += _targets([{"url":f.get("action")}])

        external_runtime=[x for x in runtime_targets if x.get("external")]
        external_writes=[x for x in write_targets if x.get("external")]
        external_forms=[x for x in form_targets if x.get("external")]

        credential_surface = bool(sensitive_controls) or cred_semantic
        concrete_sink = bool(external_runtime or external_writes or external_forms)
        independent_experts=[]

        if credential_surface:
            independent_experts.append("credential_intent")
        if concrete_sink:
            independent_experts.append("external_sink")

        # Staged UI / mutation is independent context, but never sufficient alone.
        mutations = b.get("dom_mutations") or []
        staged = bool(mutations) and credential_surface
        if staged:
            independent_experts.append("runtime_stage")

        score = 0
        if cred_semantic:
            score += 14
        if sensitive_controls:
            score += 18
        if concrete_sink:
            score += 24
        if credential_surface and concrete_sink:
            score += 26
        if staged and concrete_sink:
            score += 8
        score = min(100, score)

        report = {
            "score": score,
            "credential_semantic": cred_semantic,
            "sensitive_controls": sensitive_controls[:30],
            "external_runtime_targets": external_runtime[:30],
            "external_write_targets": external_writes[:30],
            "external_form_targets": external_forms[:30],
            "staged_sensitive_ui": staged,
            "independent_experts": independent_experts,
            "causal_chain": bool(credential_surface and concrete_sink),
            "note": "Generic telemetry alone is not promoted to threat evidence."
        }
        self.results["behavioral_brain_v3234"] = report

        # Only a real source -> sink chain becomes strong threat evidence.
        if credential_surface and concrete_sink:
            self._v323_add(
                "Hassas veri arayüzü → harici veri hedefi",
                "high" if score < 75 else "critical",
                "Sayfa hassas kimlik/veri girişi istiyor ve bağımsız bir harici gönderim hedefi gözlendi.",
                "credential_theft",
                {"causal_source":"credential_surface","causal_sink":"external_network_target",
                 "score":score,"targets":(external_runtime+external_writes+external_forms)[:10]},
                .98,
                "credential_causality"
            )
            self.results["findings"][-1]["producer"]="behavioral_brain_v3234"
        elif credential_surface:
            # Keep useful but non-conclusive evidence below the hard-threat boundary.
            self._v323_add(
                "Hassas giriş / kimlik doğrulama yüzeyi",
                "medium",
                "Kimlik veya hassas veri girişi isteyen bir yüzey gözlendi; bağımsız harici veri hedefi doğrulanmadı.",
                "credential_theft",
                {"context_only":True,"score_hint":min(score,29)},
                .72,
                "credential_intent"
            )
            self.results["findings"][-1].update({"producer":"behavioral_brain_v3234","context_only":True})
        return report

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

    def causal_destination_ownership_graph_v3238(self):
        """V32.3.8: classify sensitive-data destinations before calling them exfiltration.

        A cross-origin request is not automatically malicious. The graph separates
        first-party, identity-related, unrelated and unknown destinations, and only
        promotes a credential/exfil chain when the sensitive source is causally tied
        to an unrelated sink. Unknown third-party telemetry remains context.
        """
        b=self.results.get("browser") or {}
        final=b.get("final_url") or self.results.get("final_url") or self.results.get("url") or ""
        page_root=get_root_domain(urlparse(final).hostname or "")
        sem=b.get("semantic_dom") or self.results.get("static_semantic_v3232") or {}
        forms=b.get("forms") or self.results.get("forms") or []
        hooks=b.get("runtime_hooks") or {}
        reqs=b.get("requests") or []
        ident=self.results.get("identity_semantic_v18") or {}
        ip=self.results.get("independent_phishing_v323") or {}

        brands=set()
        for x in (ident.get("detected_brands") or []) + (ip.get("brand_claims") or []):
            if isinstance(x,dict): v=x.get("brand") or x.get("name")
            else: v=x
            if v: brands.add(str(v).strip().lower())

        def abs_target(v):
            try:
                u=urljoin(final,str(v or "")); h=(urlparse(u).hostname or "").lower()
                return u,h,get_root_domain(h)
            except Exception: return "","",""

        def relation(root):
            if not root: return "invalid"
            if root==page_root: return "first_party"
            # Identity relationship is context, never a safety override.
            if any(self._v323_identity_relation(br,root) for br in brands): return "identity_related"
            return "unknown_external"

        sensitive_terms=re.compile(r"password|passwd|passcode|parola|şifre|otp|one.?time|verification|pin|cvv|cvc|card.?number|cc-number|kart.?num|iban|seed|recovery.?phrase|ssn",re.I)
        sensitive_sources=[]
        for i,inp in enumerate(sem.get("inputs") or []):
            if not isinstance(inp,dict): continue
            blob=" ".join(str(inp.get(k,"")) for k in ("type","name","id","placeholder","autocomplete","label","aria_label"))
            if str(inp.get("type","")).lower()=="password" or sensitive_terms.search(blob):
                sensitive_sources.append({"source_id":f"input:{i}","kind":"input","descriptor":blob[:400]})
        for i,f in enumerate(forms):
            if not isinstance(f,dict): continue
            if f.get("has_password") or f.get("has_otp") or f.get("has_card"):
                sensitive_sources.append({"source_id":f"form:{i}","kind":"form","descriptor":"sensitive_form"})

        edges=[]
        strong_edges=[]
        # A sensitive form action is a direct structural source->sink edge even if the
        # worker never submits the form.
        for i,f in enumerate(forms):
            if not isinstance(f,dict) or not (f.get("has_password") or f.get("has_otp") or f.get("has_card")): continue
            u,h,rr=abs_target(f.get("action") or final); rel=relation(rr)
            e={"edge_id":f"form:{i}","source":"sensitive_form","sink":u[:800],"sink_root":rr,
               "relation":rel,"causality":"direct_form_action","observed_write":False}
            # Unknown external is suspicious context, but not automatically exfiltration.
            if rel=="unknown_external":
                e["decision"]="candidate_unrelated_sink"
                # A form explicitly posting credentials to a different registrable domain
                # is strong only when the page itself claims a different first-party identity.
                mismatch=bool(ip.get("brand_mismatches"))
                if mismatch:
                    e["relation"]="unrelated"; e["decision"]="strong_causal_exfil"; strong_edges.append(e)
            else: e["decision"]="benign_or_related_destination"
            edges.append(e)

        def runtime_items():
            for kind in ("fetches","xhr","beacons","form_submits"):
                vals=hooks.get(kind) or []
                if isinstance(vals,dict): vals=[vals]
                for x in vals:
                    yield kind,x
            for x in reqs[:700]:
                if isinstance(x,dict) and str(x.get("method") or "").upper() in ("POST","PUT","PATCH"):
                    yield "request_write",x

        for idx,(kind,x) in enumerate(runtime_items()):
            if isinstance(x,dict):
                target=x.get("url") or x.get("action") or x.get("target") or x.get("href")
                payload=x.get("body") or x.get("post_data") or x.get("data") or x.get("payload")
                source_ref=x.get("source") or x.get("source_id") or x.get("input") or x.get("form")
            else: target=x; payload=None; source_ref=None
            if not target: continue
            u,h,rr=abs_target(target); rel=relation(rr)
            payload_blob=json.dumps(payload,ensure_ascii=False,default=str) if payload is not None else ""
            # Source linkage must be concrete. Generic POST/fetch is not credential theft.
            source_linked=bool(source_ref or (payload_blob and sensitive_terms.search(payload_blob)))
            e={"edge_id":f"runtime:{idx}","source":"sensitive_source" if source_linked else "unbound_runtime",
               "sink":u[:800],"sink_root":rr,"relation":rel,"causality":"runtime_payload" if source_linked else "telemetry_only",
               "observed_write":True,"source_linked":source_linked}
            if rel=="unknown_external" and source_linked:
                e["relation"]="unrelated"; e["decision"]="strong_causal_exfil"; strong_edges.append(e)
            elif rel in ("first_party","identity_related"):
                e["decision"]="benign_or_related_destination"
            else: e["decision"]="unbound_external_write"
            edges.append(e)

        out={"page_root":page_root,"claimed_brands":sorted(brands),"sensitive_source_count":len(sensitive_sources),
             "edges":edges[:160],"strong_causal_edges":strong_edges[:40],"concrete_exfil":bool(strong_edges),
             "counts":{"first_party":sum(e.get("relation")=="first_party" for e in edges),
                       "identity_related":sum(e.get("relation")=="identity_related" for e in edges),
                       "unrelated":sum(e.get("relation")=="unrelated" for e in edges),
                       "unknown_external":sum(e.get("relation")=="unknown_external" for e in edges)},
             "principle":"Cross-origin is context; credential theft requires a concrete sensitive source -> unrelated sink edge."}
        self.results["causal_destination_graph_v3238"]=out

        # Remove/demote only causality-derived credential/exfil findings when the graph
        # cannot prove the edge. IOC/hash/C2/feed evidence is untouched.
        if not out["concrete_exfil"]:
            kept=[]; ctx=list(self.results.get("contextual_findings_v322") or [])
            for f0 in self.results.get("findings") or []:
                f=dict(f0); blob=self._v322_blob(f).lower(); prod=str(f.get("producer") or "").lower(); exp=str(f.get("source_expert") or "").lower()
                protected=any(k in blob for k in ("openphish","phishtank","urlhaus","threatfox","malicious hash","sha256","command and control"," c2 "))
                causal_cred=(exp in ("credential_theft","network_exfil","credential_causality","submission_exfil") or
                             "hassas veri" in blob or "credential_flow" in blob) and prod in ("evidence_bus_v3236","behavioral_brain_v3234","independent_phishing_v323","zero_day_behavior_v32")
                if causal_cred and not protected:
                    f["score_eligible_v322"]=False; f["v3238_causality_reject"]="no_sensitive_source_to_unrelated_sink_edge"
                    f["original_severity_v3238"]=f.get("severity"); f["severity"]="info"; ctx.append(f)
                else: kept.append(f)
            self.results["findings"]=kept; self.results["contextual_findings_v322"]=ctx
        return out

    def behavior_semantics_identity_causality_gate_v3237(self):
        """V32.3.7: observation != malicious intent.

        Validates producer findings against concrete DOM/runtime causality before they
        can reach canonical fusion. This is generic, domain-relationship aware and
        never suppresses known IOC, malicious file/hash, C2 or concrete exfil evidence.
        """
        browser=self.results.get("browser") or {}
        final=browser.get("final_url") or self.results.get("final_url") or self.results.get("url") or ""
        root=get_root_domain(urlparse(final).hostname or "")
        sem=browser.get("semantic_dom") or self.results.get("static_semantic_v3232") or {}
        forms=browser.get("forms") or self.results.get("forms") or []
        hooks=browser.get("runtime_hooks") or {}
        reqs=browser.get("requests") or []

        def target_root(v):
            try:
                u=urljoin(final,str(v or "")); return get_root_domain(urlparse(u).hostname or "")
            except Exception: return ""

        # Concrete sensitive sources. Text such as 'account/security/payment' is not a source.
        sensitive_inputs=[]
        for inp in sem.get("inputs") or []:
            if not isinstance(inp,dict): continue
            blob=" ".join(str(inp.get(k,"")) for k in ("type","name","id","placeholder","autocomplete","label")).lower()
            if str(inp.get("type","")).lower()=="password" or re.search(
                r"password|passwd|parola|şifre|otp|one.?time|verification.?code|pin|cvv|cvc|cc-number|card.?number|kart.?num|iban|seed|recovery.?phrase|ssn",blob,re.I):
                sensitive_inputs.append(inp)
        sensitive_forms=[]; cross_sensitive_forms=[]
        for f in forms:
            if not isinstance(f,dict): continue
            sens=bool(f.get("has_password") or f.get("has_otp") or f.get("has_card"))
            if sens:
                sensitive_forms.append(f)
                rr=target_root(f.get("action"))
                if rr and root and rr!=root: cross_sensitive_forms.append(f)
        concrete_sensitive=bool(sensitive_inputs or sensitive_forms)

        # Concrete runtime writes. Merely loading a third-party asset is not exfiltration.
        writes=[]
        for key in ("fetches","xhr","beacons","form_submits"):
            vals=hooks.get(key) or []
            if isinstance(vals,dict): vals=[vals]
            for x in vals:
                if isinstance(x,dict):
                    u=x.get("url") or x.get("action") or x.get("target") or x.get("href")
                    method=str(x.get("method") or "").upper()
                    body=x.get("body") or x.get("post_data") or x.get("data")
                else: u=x; method=""; body=None
                rr=target_root(u)
                if u and (method in ("POST","PUT","PATCH") or key in ("beacons","form_submits") or body):
                    writes.append({"url":str(u),"root":rr,"cross":bool(rr and root and rr!=root),"kind":key})
        cross_writes=[x for x in writes if x["cross"]]
        graph_v3238=self.results.get("causal_destination_graph_v3238") or {}
        concrete_exfil=bool(graph_v3238.get("concrete_exfil")) if graph_v3238 else bool(concrete_sensitive and (cross_sensitive_forms or cross_writes))

        # Cloaking requires observed content divergence plus an actual anti-analysis primitive.
        anti_blob=json.dumps(browser.get("script_signals") or {},ensure_ascii=False,default=str).lower()
        anti=bool(re.search(r"webdriver|devtools|navigator\.webdriver|headless|debugger",anti_blob,re.I))
        http=self.results.get("http") or {}
        obs=self.results.get("phishing_observatory_v3231") or {}
        discrepancy=bool(browser.get("content_discrepancy") or browser.get("http_browser_discrepancy") or
                         obs.get("content_discrepancy") or obs.get("cloaking_observed"))
        concrete_cloaking=bool(anti and discrepancy)

        # Redirect abuse needs a chain and a cross-root hop. Meta refresh alone is navigation telemetry.
        navs=browser.get("navigations") or browser.get("redirects") or http.get("redirect_history") or []
        if isinstance(navs,dict): navs=[navs]
        nav_roots=[]
        for n in navs:
            u=n.get("url") if isinstance(n,dict) else n
            rr=target_root(u)
            if rr: nav_roots.append(rr)
        cross_redirect=bool(len(navs)>=2 and any(rr!=root for rr in nav_roots if root))

        # Official identity relation invalidates impersonation only, never independent malicious evidence.
        official_claims=set()
        ident=self.results.get("identity_semantic_v18") or {}
        for x in ident.get("detected_brands") or []:
            if isinstance(x,dict):
                b=str(x.get("brand") or "").lower()
                if b and self._v323_identity_relation(b,root): official_claims.add(b)

        protected_terms=("openphish","phishtank","urlhaus","threatfox","malicious hash","sha256","c2","command and control")
        kept=[]; contextual=list(self.results.get("contextual_findings_v322") or []); demoted=[]
        for f0 in self.results.get("findings") or []:
            f=dict(f0); text=self._v322_blob(f).lower(); title=str(f.get("title") or "").lower()
            if any(t in text for t in protected_terms): kept.append(f); continue
            reject=None
            if ("hassas veri + harici yazma" in title or "credential_flow" in text or
                (str(f.get("source_expert") or "").lower()=="credential_theft" and str(f.get("producer") or "").lower()=="evidence_bus_v3236")):
                if not concrete_exfil: reject="credential_event_without_concrete_sensitive_source_to_cross_origin_sink"
            elif ("anti-analysis + içerik ayrışması" in title or
                  (str(f.get("source_expert") or "").lower()=="cloaking" and str(f.get("producer") or "").lower()=="evidence_bus_v3236")):
                if not concrete_cloaking: reject="cloaking_event_without_observed_divergence_and_anti_analysis_primitive"
            elif "meta refresh yönlendirmesi" in title:
                if not cross_redirect: reject="meta_refresh_without_cross_root_redirect_chain"
            elif "sosyal mühendislik içeriği" in title:
                # Language is context until identity mismatch or a concrete credential/exfil chain corroborates it.
                ip=self.results.get("independent_phishing_v323") or {}
                if not concrete_exfil and not (ip.get("identity_mismatch") and concrete_sensitive):
                    reject="urgency_language_without_attack_causality"
            elif any(k in title for k in ("marka kimliği / domain uyuşmazlığı","marka taklidi + hassas işlem","sayfa başlığında marka taklidi")):
                if official_claims: reject="official_identity_relationship"
            if reject:
                f["score_eligible_v322"]=False; f["v3237_semantic_reject"]=reject
                f["original_severity_v3237"]=f.get("severity"); f["severity"]="info"
                contextual.append(f); demoted.append({"title":f.get("title"),"reason":reject})
            else: kept.append(f)
        self.results["findings"]=kept
        self.results["contextual_findings_v322"]=contextual
        out={"root":root,"concrete_sensitive_source":concrete_sensitive,
             "cross_origin_sensitive_form_count":len(cross_sensitive_forms),
             "cross_origin_runtime_write_count":len(cross_writes),"concrete_exfil":concrete_exfil,
             "destination_graph_v3238":graph_v3238,
             "anti_analysis_primitive":anti,"content_discrepancy":discrepancy,"concrete_cloaking":concrete_cloaking,
             "cross_root_redirect_chain":cross_redirect,"official_identity_claims":sorted(official_claims),
             "demoted":demoted,"principle":"Observation != attack intent; canonical threat evidence requires concrete causality."}
        self.results["behavior_semantics_gate_v3237"]=out
        return out


    def evidence_independence_ownership_guard_v32325(self):
        """V32.3.25 producer-level guard for evidence independence and ownership.

        Identity relationships can invalidate only impersonation hypotheses. They are
        never a safety allowlist and never suppress IOC/hash/C2/concrete exfil evidence.
        Redirect and source->sink claims require concrete cross-root causality. Derived
        summaries cannot become an independent corroborator of their own parents.
        """
        host=(urlparse(self.results.get("final_url") or self.results.get("analyzed_url") or "").hostname or "").lower()
        root=get_root_domain(host) if host else ""
        browser=self.results.get("browser") or {}
        http=self.results.get("http") or {}
        graph=self.results.get("causal_destination_graph_v3238") or {}

        # Organization/identity registry. This is relation data, not a trust override.
        org_groups={
          "meta":{"facebook.com","instagram.com","meta.com","whatsapp.com","fb.com"},
          "google":{"google.com","gmail.com","youtube.com"},
          "microsoft":{"microsoft.com","live.com","office.com","outlook.com"},
          "amazon":{"amazon.com","amazon.com.tr","amazon.co.uk","amazon.de","amazon.fr","amazon.it","amazon.es","amazon.co.jp","amazon.ca","amazon.com.au","amazon.in","amazon.com.br","amazon.com.mx"},
          "apple":{"apple.com","icloud.com"}
        }
        related_brands=set()
        brand_to_roots={
          "facebook":{"facebook.com","meta.com","fb.com"}, "instagram":{"instagram.com"},
          "meta":{"meta.com","facebook.com"}, "whatsapp":{"whatsapp.com"},
          "google":{"google.com","gmail.com"}, "youtube":{"youtube.com"},
          "microsoft":{"microsoft.com","live.com","office.com","outlook.com"},
          "amazon":org_groups["amazon"], "apple":{"apple.com","icloud.com"}
        }
        for brand,roots in brand_to_roots.items():
            if root in roots: related_brands.add(brand)
        for members in org_groups.values():
            if root in members:
                for brand,roots in brand_to_roots.items():
                    if roots & members: related_brands.add(brand)

        def target_root(u):
            try: return get_root_domain((urlparse(str(u)).hostname or "").lower())
            except Exception: return ""
        navs=browser.get("navigations") or browser.get("redirects") or http.get("redirect_history") or http.get("redirects") or []
        if isinstance(navs,dict): navs=[navs]
        nav_roots=[]
        for n in navs:
            u=n.get("url") if isinstance(n,dict) else n
            rr=target_root(u)
            if rr: nav_roots.append(rr)
        concrete_cross_root_redirect=bool(root and any(rr and rr!=root for rr in nav_roots))

        strong_edges=graph.get("strong_causal_edges") or []
        concrete_exfil=bool(graph.get("concrete_exfil") or strong_edges)

        protected=("openphish","phishtank","urlhaus","threatfox","malicious hash","sha256","c2","command and control")
        kept=[]; contextual=list(self.results.get("contextual_findings_v322") or []); demoted=[]
        for f0 in self.results.get("findings") or []:
            f=dict(f0); text=self._v322_blob(f).lower(); title=str(f.get("title") or "").lower()
            if any(x in text for x in protected):
                kept.append(f); continue
            reason=None

            # Related first-party brand mentions cannot support impersonation.
            brand_hits={b for b in brand_to_roots if re.search(r"(?<![a-z0-9])"+re.escape(b)+r"(?![a-z0-9])",text)}
            if brand_hits and brand_hits.issubset(related_brands) and any(k in title for k in (
                "marka taklidi","marka kimliği","domain uyuşmaz","görsel marka kimliği","sahte host")):
                reason="related_first_party_identity_not_impersonation"

            # Navigation telemetry is contextual until a concrete cross-root chain exists.
            if not reason and ("meta refresh" in title or str(f.get("category") or "").lower() in ("redirect","redirect_abuse")):
                if not concrete_cross_root_redirect:
                    reason="redirect_without_concrete_cross_root_destination"

            # Static source+network vocabulary is not exfiltration without a causal edge.
            if not reason and any(k in title for k in ("hassas kaynak","ağ aktarım zinciri","veri gönderim akışı")):
                if not concrete_exfil:
                    reason="sensitive_source_network_without_causal_sink_edge"

            # A correlation/summary cannot vote as a new expert. Keep it diagnostic only.
            if not reason and any(k in title for k in ("çoklu tehdit davranışı korelasyonu","yüksek risk: phishing sitesi özellikleri","bağımsız davranış uzmanları aynı tehdidi destekliyor")):
                f["derived_evidence"]=True
                f["score_eligible_v322"]=False
                reason="derived_summary_cannot_be_independent_vote"

            if reason:
                f["score_eligible_v322"]=False; f["v32325_reject"]=reason
                f["original_severity_v32325"]=f.get("severity"); f["severity"]="info"
                contextual.append(f); demoted.append({"title":f.get("title"),"reason":reason})
            else:
                kept.append(f)
        self.results["findings"]=kept
        self.results["contextual_findings_v322"]=contextual
        out={"root":root,"related_brand_tokens":sorted(related_brands),
             "concrete_cross_root_redirect":concrete_cross_root_redirect,
             "concrete_exfil":concrete_exfil,"demoted":demoted,
             "invariant":"ownership invalidates impersonation only; redirect/exfil require causal destination evidence; derived summaries never vote"}
        self.results["evidence_independence_ownership_v32325"]=out
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

    def behavioral_intent_gate_v3226(self):
        """V32.2.6: generic JS/runtime primitives are telemetry until a causal malicious intent is proven.

        Important: the gate evaluates each finding's own provenance/evidence. It deliberately does not
        borrow unrelated page-wide signals, preventing normal large applications from manufacturing a
        source->sink chain by coincidence.
        """
        generic_js_terms=(
            "dynamic script loader", "dinamik harici script", "script oluşturuyor",
            "createelement('script')", 'createelement("script")', ".src =", ".src=",
            "eval_like", "decoder_like", "atob(", "fromcharcode", "decodeuricomponent",
            "storage access", "cookie access", "event listener", "input event"
        )
        malicious_sink_terms=(
            "cross-origin credential", "credential exfil", "cross-site credential",
            "external credential sink", "harici credential", "harici kimlik",
            "malware payload", "known malicious", "urlhaus", "threatfox", "openphish",
            "phishtank", "sha-256 ioc", "sha256 ioc", "malware hash", "command and control",
            " c2 ", "c2 endpoint"
        )
        explicit_flow_terms=(
            "source_to_sink", "source->sink", "source → sink", "source-to-sink",
            "credential_source", "sink_host", "destination_host", "external_sink"
        )
        kept=[]
        contextual=list(self.results.get("contextual_findings_v322") or [])
        demoted=[]
        for f0 in self.results.get("findings") or []:
            f=dict(f0)
            local=self._v322_blob({
                "title":f.get("title"), "description":f.get("description"),
                "evidence":f.get("evidence"), "category":f.get("category"),
                "source":f.get("source_expert") or f.get("source")
            })
            is_generic=any(t in local for t in generic_js_terms)
            has_hard=any(t in local for t in malicious_sink_terms)
            has_explicit_flow=any(t in local for t in explicit_flow_terms)
            # A generic primitive is not malicious intent. Only evidence local to this finding can promote it.
            if is_generic and not (has_hard or has_explicit_flow):
                f["original_severity_v3226"]=f.get("severity")
                f["severity"]="info"
                f["confidence"]=min(float(f.get("confidence") or .5), .20)
                f["score_eligible_v322"]=False
                f["behavioral_intent_v3226"]="generic_primitive_without_local_malicious_sink"
                contextual.append(f)
                demoted.append({"title":f.get("title"),"category":f.get("category")})
                continue
            kept.append(f)
        self.results["findings"]=kept
        self.results["contextual_findings_v322"]=contextual
        report={
            "policy":"generic_runtime_primitive_requires_finding_local_causal_malicious_sink",
            "score_eligible_findings":len(kept), "demoted_count":len(demoted), "demoted":demoted
        }
        self.results["behavioral_intent_gate_v3226"]=report
        return report

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


    def trace_javascript_dataflow(self):
        # Conservative non-executing lexical source-to-sink tracker.
        base=self.results.get("final_url") or self.results.get("analyzed_url") or ""
        page_root=get_canonical_root(urlparse(base).hostname or "")
        st=self.results.get("static_source_intelligence_v32317") or {}
        credential_context=bool(st.get("credential_source"))
        blobs=[]; source_bus=self.results.get("_javascript_sources") or {}
        for row in (source_bus.get("inline_and_external") or [])[:8]:
            if not isinstance(row,dict): continue
            code=str(row.get("body") or "")[:1800000]
            if code: blobs.append((str(row.get("origin") or "source"),str(row.get("url") or base),code))

        source_rx=re.compile(r"(?i)(?:[A-Za-z_$][\w$]*\s*\.\s*value\b|document\s*\.\s*cookie\b|(?:localStorage|sessionStorage)\s*\.\s*(?:getItem\s*\([^)]*\)|[A-Za-z_$][\w$]*)|new\s+FormData\s*\([^)]*\))")
        assign_rx=re.compile(r"(?m)\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,700})")
        alias_rx=re.compile(r"\b([A-Za-z_$][\w$]*)\b")
        sink_rx=re.compile(r"(?is)(?:fetch\s*\(\s*([^,\n\)]{1,700})(?:,\s*(\{.{0,1800}?\}))?|sendBeacon\s*\(\s*([^,\n\)]{1,700})\s*,\s*([^\)]{1,1200})|axios\s*\.\s*(?:post|put|patch)\s*\(\s*([^,\n\)]{1,700})\s*,\s*([^\)]{1,1200})|\$\s*\.\s*post\s*\(\s*([^,\n\)]{1,700})\s*,\s*([^\)]{1,1200}))")
        literal_url_rx=re.compile(r"['\"]((?:https?:)?//[^'\"]+|/[^'\"]*)['\"]",re.I)

        reports=[]; proven=[]
        for origin,script_url,code in blobs:
            tainted=set(); sources=[]
            for m in assign_rx.finditer(code):
                name,rhs=m.group(1),m.group(2)
                if source_rx.search(rhs):
                    tainted.add(name); sources.append({"var":name,"offset":m.start()})
            for _ in range(6):
                changed=False
                for m in assign_rx.finditer(code):
                    name,rhs=m.group(1),m.group(2)
                    if set(alias_rx.findall(rhs)) & tainted and name not in tainted:
                        tainted.add(name); changed=True
                if not changed: break

            sinks=[]
            for m in sink_rx.finditer(code):
                parts=[x for x in m.groups() if x]
                joined=" ".join(parts)
                refs=set(alias_rx.findall(joined))
                carries=bool(refs & tainted or source_rx.search(joined))
                dest=""
                for part in parts[:2]:
                    lm=literal_url_rx.search(part)
                    if lm:
                        dest=urljoin(script_url or base,lm.group(1)); break
                root=get_canonical_root(urlparse(dest).hostname or "") if dest else ""
                cross=bool(dest and root and page_root and root!=page_root)
                row={"offset":m.start(),"destination":dest[:700],"destination_root":root,
                     "cross_root":cross,"carries_sensitive":carries,
                     "tainted_variables":sorted(refs & tainted)[:20]}
                sinks.append(row)
                if carries and cross and credential_context:
                    proven.append({"origin":origin,"script_url":script_url[:700],**row})
            reports.append({"origin":origin,"script_url":script_url[:700],
                            "tainted_variables":sorted(tainted)[:80],
                            "sources":sources[:80],"sinks":sinks[:80]})

        rep={"mode":"bounded_nonexecuting_lexical_dataflow","scripts_analyzed":len(blobs),
             "credential_context":credential_context,"reports":reports[:50],"proven_sensitive_crossroot_paths":proven[:40],
             "proven_count":len(proven),"score_eligible":bool(proven),
             "limitations":["dynamic destination expressions","eval/new Function","deep interprocedural calls","computed object properties"],
             "policy":"No JavaScript is executed and no form is submitted. Only explicit sensitive-data propagation into an explicit unrelated network destination is score-eligible."}
        self.results["javascript_dataflow"]=rep
        self.results["js_dataflow_v3244"]=rep
        if proven:
            self.add_finding("JavaScript hassas veri akışı harici hedefe bağlandı","critical",
                "Statik JavaScript veri akışında hassas bir kaynaktan açıkça farklı kök domaine yazılan ağ hedefi doğrulandı.",
                "credential_theft",json.dumps({"paths":proven[:8]},ensure_ascii=False),.97)
            self.results["findings"][-1].update({
                "producer":"javascript_dataflow","source_expert":"static_submission_exfil",
                "independent_group":"static_source","evidence_lineage_id":"v3244-js-sensitive-crossroot",
                "causal_proof":True,"score_eligible":True})
        return rep

    def js_dataflow_engine_v3244(self):
        return self.trace_javascript_dataflow()

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

    def persist_temporal_observation(self):
        rep=self.persist_temporal_observation_v3241(); self.results["temporal_persist"]=rep; return rep

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

    def differential_observation_engine_v32331(self):
        """Compare bounded browser observation profiles without interacting with live controls.

        This is a sensor, not a verdict. A profile difference only becomes scoring evidence
        when the same target exposes a materially different application surface and at least
        one profile contains an authentication/credential surface.
        """
        b=self.results.get("browser") or {}
        d=b.get("differential_observation") or {}
        profiles=d.get("profiles") or []
        base=d.get("baseline") or {}
        report={
            "mode":"bounded_observation_no_interaction",
            "profiles":profiles,
            "baseline":base,
            "material_divergence":False,
            "credential_surface_in_variant":False,
            "conditional_delivery_signal":False,
            "score_eligible":False,
            "reason":"not_observed",
            "policy":"Viewport/locale/JavaScript differences are sensors only. No click, typing, form submission or challenge bypass is performed."
        }
        if not profiles:
            report["reason"]="no_differential_profiles"
            self.results["differential_observation_v32331"]=report
            return report

        def sig(x):
            return (str(x.get("title") or "").strip().lower(), int(x.get("inputs") or 0),
                    int(x.get("forms") or 0), int(x.get("iframes") or 0),
                    bool(x.get("auth_intent")), str(x.get("final_url") or ""))
        bs=sig(base)
        divergent=[]; credential=[]
        for x in profiles:
            xs=sig(x)
            # Material means application-surface change, not a few bytes of analytics noise.
            surface_delta=(xs[1:5] != bs[1:5]) or (xs[5] and bs[5] and xs[5] != bs[5])
            title_delta=bool(xs[0] and bs[0] and xs[0] != bs[0])
            html_ratio=0.0
            try:
                a=max(1,int(base.get("html_length") or 0)); c=int(x.get("html_length") or 0)
                html_ratio=abs(c-a)/a
            except Exception: pass
            material=surface_delta or (title_delta and html_ratio >= .20) or html_ratio >= .45
            if material: divergent.append(x)
            if int(x.get("inputs") or 0)>0 or int(x.get("forms") or 0)>0 or bool(x.get("auth_intent")):
                credential.append(x)
        conditional=bool(divergent and credential)
        report.update({
            "material_divergence":bool(divergent),
            "credential_surface_in_variant":bool(credential),
            "conditional_delivery_signal":conditional,
            "divergent_profiles":[x.get("profile") for x in divergent],
            "credential_profiles":[x.get("profile") for x in credential],
            "reason":"conditional_application_surface" if conditional else ("profile_divergence_context_only" if divergent else "profiles_consistent")
        })
        # Stronger than generic headless telemetry, but still cannot declare phishing alone.
        if conditional:
            self._v323_add(
                "Koşullu içerik / farklı uygulama yüzeyi",
                "medium",
                "Aynı hedef, sınırlı tarayıcı profilleri arasında maddi olarak farklı içerik gösterdi ve en az bir profilde kimlik doğrulama/girdi yüzeyi gözlendi. Bu bulgu tek başına phishing hükmü değildir.",
                "cloaking",
                {"profiles":report["divergent_profiles"],"credential_profiles":report["credential_profiles"],"context_only":True},
                .86,
                "differential_observation"
            )
            self.results["findings"][-1].update({"producer":"differential_observation_v32331","context_only":True,"score_eligible_v322":False})
        self.results["differential_observation_v32331"]=report
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

    def zero_day_status_v32(self, limit=50):
        with db_connect(DB_PATH,timeout=10) as con:
            rows=con.execute("""SELECT observation_id,created_at,registrable_domain,score,confidence,verdict,
              independent_groups,behavior_families,known_ioc FROM zero_day_observations_v32
              ORDER BY score DESC,created_at DESC LIMIT ?""",(max(1,min(200,int(limit))),)).fetchall()
        return {"observations":[{"observation_id":r[0],"created_at":r[1],"domain":r[2],"score":r[3],
          "confidence":r[4],"verdict":r[5],"independent_groups":r[6],
          "families":json.loads(r[7] or "[]"),"known_ioc":bool(r[8])} for r in rows]}

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

    def run_identity_semantic_v18(self):
        """Brand identity + semantic intent + shared-hosting context. Passive only."""
        url=self.results.get("final_url") or self.results.get("url") or ""
        host=(urlparse(url).hostname or "").lower()
        root=get_root_domain(host) if host else ""
        browser=self.results.get("browser",{}) or {}
        http=self.results.get("http",{}) or {}

        # Curated high-signal brands. Domain ownership is checked independently.
        brands={
          "airbnb":["airbnb.com"],"paypal":["paypal.com"],"microsoft":["microsoft.com","live.com","office.com","outlook.com"],
          "google":["google.com","gmail.com"],"apple":["apple.com","icloud.com"],"facebook":["facebook.com","meta.com"],
          "instagram":["instagram.com"],"amazon":["amazon.com","amazon.com.tr","amazon.co.uk","amazon.de","amazon.fr","amazon.it","amazon.es","amazon.co.jp","amazon.ca","amazon.com.au","amazon.in","amazon.com.br","amazon.com.mx"],"netflix":["netflix.com"],"github":["github.com"],
          "discord":["discord.com"],"telegram":["telegram.org"],"binance":["binance.com"],"coinbase":["coinbase.com"],
          "shopee":["shopee.com"],"trendyol":["trendyol.com"],"hepsiburada":["hepsiburada.com"]
        }
        shared_suffixes=("vercel.app","netlify.app","pages.dev","github.io","firebaseapp.com","web.app","workers.dev")

        # V32.3.2: only strong first-party surfaces can assert identity.
        static_sem=self.results.get("static_semantic_v3232") or {}
        semdom=browser.get("semantic_dom") or {}
        pieces=[]
        for source in (semdom, static_sem):
            for key in ("title","headings","buttons","labels","visible_text"):
                val=source.get(key)
                if val:
                    if isinstance(val,list): pieces.extend(str(x)[:1000] for x in val[:50])
                    else: pieces.append(str(val)[:120000])
        semantic=" ".join(pieces).lower()

        detected=[]
        ambiguous_identity_tokens={"live"}
        for brand,domains in brands.items():
            if brand in ambiguous_identity_tokens:
                continue
            if re.search(r"(?<![a-z0-9])"+re.escape(brand)+r"(?![a-z0-9])",semantic,re.I):
                official=any(root==d or root.endswith("."+d) for d in domains)
                detected.append({"brand":brand,"official_domain":official,"expected_domains":domains})

        sensitive_terms={
          "login":["login","log in","sign in","oturum aç","giriş yap"],
          "password":["password","parola","şifre"],
          "otp":["otp","one-time","verification code","doğrulama kod"],
          "payment":["payment","card number","credit card","cvv","cvc","ödeme","kart numarası"],
          "booking":["book now","reservation","booking","rezervasyon"],
          "identity":["verify identity","identity verification","kimlik doğrul"]
        }
        intents=[k for k,terms in sensitive_terms.items() if any(t in semantic for t in terms)]

        shared=next((x for x in shared_suffixes if host==x or host.endswith("."+x)),None)
        mismatches=[x for x in detected if not x["official_domain"]]
        score=0; evidence=[]
        if mismatches:
            score+=34
            evidence.append("Sayfa içeriğinde marka kimliği var ancak kök domain markanın resmi domaini değil")
        if mismatches and shared:
            score+=12
            evidence.append("Marka içeriği üçüncü taraf/shared-hosting subdomaininde")
        sensitive=set(intents)&{"login","password","otp","payment","identity"}
        if mismatches and sensitive:
            score+=24
            evidence.append("Marka-domain uyuşmazlığı hassas işlem niyetiyle birlikte gözlendi")
        if len(sensitive)>=2:
            score+=10
            evidence.append("Birden fazla hassas kullanıcı akışı sinyali")
        score=min(100,score)

        self.results["identity_semantic_v18"]={
          "host":host,"root_domain":root,"shared_hosting":shared,
          "detected_brands":detected,"brand_mismatches":mismatches,
          "semantic_intents":intents,"score":score,"evidence":evidence,
          "note":"Shared hosting tek başına tehdit kanıtı değildir."
        }

        # Feed explicit findings into existing UI/fusion.
        if mismatches:
            names=", ".join(x["brand"].title() for x in mismatches[:4])
            sev="high" if sensitive else "medium"
            self.add_finding("Marka kimliği / domain uyuşmazlığı", sev,
                f"Sayfa {names} marka göstergeleri taşıyor ancak kök domain resmi marka domaini değil."
                + (f" Shared hosting: {shared}." if shared else ""),
                "phishing", confidence=.88 if sensitive else .72)
        if mismatches and sensitive:
            self.add_finding("Marka taklidi + hassas işlem korelasyonu", "high",
                "Marka-domain uyuşmazlığı ile "+", ".join(sorted(sensitive))+" sinyalleri birlikte gözlendi.",
                "credential_theft", confidence=.92)

        # Coverage is decomposed; 100% module completion is not 100% behavioral certainty.
        browser_ok=bool(browser.get("success"))
        body_ok=bool(http.get("body_analyzed"))
        intel_checked=bool((self.results.get("threat_intelligence") or {}).get("checked"))
        self.results["coverage_v18"]={
          "technical_module_completion":100,
          "static_content_observation":100 if body_ok else 0,
          "browser_behavior_observation":100 if browser_ok else 0,
          "threat_intel_observation":100 if intel_checked else 0,
          "interpretation":"Modüllerin tamamlanması, tüm saldırı davranışlarının gözlemlendiği anlamına gelmez."
        }

    def run_behavioral_fusion_v17(self):
        """Passive multi-evidence correlation; missing observation is not clean evidence."""
        findings=self.results.get("findings",[]) or []
        browser=self.results.get("browser",{}) or {}
        http=self.results.get("http",{}) or {}
        scan=self.results.get("scan",{}) or {}
        blob=" ".join(str(x.get("title",""))+" "+str(x.get("description",""))+" "+str(x.get("evidence",""))+" "+str(x.get("category","")) for x in findings).lower()
        fam={k:{"score":0,"experts":set(),"evidence":[]} for k in
             ("phishing","credential_theft","malware","suspicious_script","redirect_abuse","data_exfiltration","cloaking")}
        def add(k,e,w,label):
            d=fam[k]; d["score"]+=w; d["experts"].add(e)
            if label not in d["evidence"]: d["evidence"].append(label)
        rules=[
          ("phishing","brand",34,("marka/domain","brand imperson","marka taklidi","marka kimliği / domain uyuşmazlığı")),
          ("phishing","url",12,("typosquat","punycode","homoglyph","şüpheli tld")),
          ("credential_theft","credential",32,("password","parola","şifre","otp","cvv","pin","hassas alan","marka taklidi + hassas işlem")),
          ("credential_theft","network",30,("harici runtime veri hedefi","cross-domain credential","external credential")),
          ("malware","download",40,("sha-256 ioc","urlhaus malware","malware payload","zararlı indirme")),
          ("suspicious_script","javascript",20,("obfuscat","eval","dynamic script","js-added password")),
          ("redirect_abuse","redirect",20,("redirect","yönlendirme","location")),
          ("data_exfiltration","network",30,("beacon","external runtime","harici runtime","veri hedefi"))]
        for k,e,w,keys in rules:
            if any(x in blob for x in keys): add(k,e,w," / ".join(keys[:2]))
        if browser.get("success"):
            hooks=browser.get("runtime_hooks") or {}; sem=browser.get("semantic_dom") or {}
            forms=sem.get("forms") or []
            sensitive=any(any(k in json.dumps(f,ensure_ascii=False).lower() for k in
                ("password","otp","one-time","cvv","cvc","cc-number","pin","iban")) for f in forms)
            if sensitive:
                add("credential_theft","dom",24,"Runtime DOM hassas alan")
                add("phishing","dom",12,"Runtime hassas form")
            if hooks.get("form_submits"): add("credential_theft","runtime",12,"Runtime form submit")
            if hooks.get("beacons"): add("data_exfiltration","runtime",16,"sendBeacon")
            if hooks.get("fetches") or hooks.get("xhr"): add("data_exfiltration","runtime",6,"fetch/XHR")
            if browser.get("downloads"): add("malware","download",14,"Browser download")
            hf=str(http.get("final_url") or scan.get("final_url") or ""); bf=str(browser.get("final_url") or "")
            if hf and bf:
                try:
                    if get_root_domain(urlparse(hf).hostname or "") != get_root_domain(urlparse(bf).hostname or ""):
                        add("cloaking","http_vs_browser",34,"HTTP/browser farklı kök domain")
                except Exception: pass
            if http.get("status") and browser.get("status") and http.get("status")!=browser.get("status"):
                add("cloaking","http_vs_browser",12,"HTTP/browser status farkı")
        redirects=http.get("redirects") or []; navs=browser.get("navigations") or []
        if redirects or len(navs)>1:
            add("redirect_abuse","navigation",min(20,8+3*(len(redirects)+max(0,len(navs)-1))),"Çok katmanlı navigasyon")
        blind=[]
        if browser.get("attempted") and not browser.get("success"): blind+=["runtime DOM","runtime network","client-side navigation"]
        if not http.get("body_analyzed"): blind.append("static response body")
        scan["v17_blind_spots"]=blind
        out=[]
        for k,d in fam.items():
            n=len(d["experts"]); score=d["score"]+(12 if n>=2 else 0)+(14 if n>=3 else 0)+(10 if n>=4 else 0)
            score=max(0,min(100,score))
            strength="none" if score==0 else "low" if score<30 else "medium" if score<60 else "high" if score<85 else "critical"
            out.append({"family":k,"evidence_strength":score,"strength":strength,"independent_experts":n,
                        "experts":sorted(d["experts"]),"evidence":d["evidence"][:12]})
        out.sort(key=lambda x:x["evidence_strength"],reverse=True)
        self.results["behavioral_fusion_v17"]={"engine":"Multi-Evidence Behavioral Fusion V17",
            "families":out,"primary":out[0] if out and out[0]["evidence_strength"] else None,
            "blind_spots":blind,"principle":"Independent evidence correlation; missing observation is not negative evidence."}

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

    @staticmethod
    def _leet_skeleton_v32313(value):
        """Conservative hostname skeleton for brand-typo comparison only."""
        trans = str.maketrans({"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t"})
        return re.sub(r"[^a-z0-9]", "", str(value or "").lower()).translate(trans)

    def domain_impersonation_guard_v32313(self, original_url):
        """Site-agnostic passive identity detector that survives missing content.

        It never needs DOM access and therefore must remain eligible when a WAF,
        bot challenge, timeout or other target access restriction hides content.
        """
        final = self.results.get("final_url") or original_url
        host = (urlparse(final).hostname or "").lower()
        root = get_root_domain(host)
        labels = [x for x in host.split('.') if x and x not in {"www","com","net","org","app","site","online","co","tr"}]
        hits=[]
        for brand in BRAND_KEYWORDS:
            if legitimate_brand_root(brand, root):
                continue
            bs = self._leet_skeleton_v32313(brand)
            if len(bs) < 4: continue
            for label in labels:
                ls = self._leet_skeleton_v32313(label)
                if not ls: continue
                ratio = difflib.SequenceMatcher(None, bs, ls).ratio()
                # Exact skeleton catches leetspeak (f4c3b00k -> facebook).
                # High similarity catches ordinary typo variants without making
                # a single short substring decisive.
                if ls == bs or (len(bs) >= 5 and ratio >= .86):
                    hits.append({"brand":brand,"label":label,"skeleton":ls,"similarity":round(ratio,3)})
                    break
        # V32.3.14: hosted/tenant subdomain identity claim.
        # A phishing page can live below an otherwise legitimate hosting root
        # (tenant.example-host.tld). The hosting root must never inherit safety
        # to the tenant name. This is site/provider agnostic and does not require DOM.
        tenant_labels=[]
        if host and root and host != root and host.endswith("." + root):
            prefix=host[:-(len(root)+1)]
            tenant_labels=[x for x in prefix.split('.') if x and x != "www"]
        hosted_claims=[]
        for brand in BRAND_KEYWORDS:
            if legitimate_brand_root(brand, root):
                continue
            bs=self._leet_skeleton_v32313(brand)
            if len(bs) < 4:
                continue
            for label in tenant_labels:
                ls=self._leet_skeleton_v32313(label)
                # Exact token, leetspeak token, or a brand embedded in a longer
                # tenant slug (e.g. brand-support-login). This is an identity
                # warning, not by itself a phishing conviction.
                if ls == bs or (len(bs) >= 5 and (bs in ls or difflib.SequenceMatcher(None, bs, ls).ratio() >= .86)):
                    hosted_claims.append({"brand":brand,"tenant_label":label,"skeleton":ls,"root":root})
                    break

        detected=bool(hits or hosted_claims)
        if hits:
            detail = f"host={host}; root={root}; matches={hits[:8]}"
            self.add_finding(
                "Pasif alan adı marka taklidi / typosquatting sinyali", "high",
                "Alan adı, bilinen bir marka adının yazım/leetspeak benzerini kullanıyor ancak registrable domain o markanın resmi domain ilişkisiyle eşleşmiyor. İçerik alınamasa da bu pasif kimlik kanıtı geçerlidir.",
                "phishing", detail, .94)
        # Do not add a second scoring finding for hosted_claims here. Existing URL
        # intelligence may already score the brand-like hostname. This signal is
        # primarily an identity/observation guard so access failure cannot hide it.
        self.results["domain_impersonation_v32313"]={
            "detected":detected,"host":host,"root":root,"matches":hits[:8],
            "hosted_tenant_claims":hosted_claims[:8],
            "identity_context":"hosted_tenant_brand_claim" if hosted_claims else ("typosquat" if hits else "none"),
            "content_independent":True,
            "rule":"A legitimate hosting/root domain never makes an unverified tenant/subdomain identity claim safe."
        }
        return self.results["domain_impersonation_v32313"]

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

    # ═══════════════════════════════════════════════════════════════════════
    # KAPSAM HESAPLAMA
    # ═══════════════════════════════════════════════════════════════════════

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



# ═══════════════════════════════════════════════════════════════════════════
# HTML TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════

HTML_TEMPLATE = r'''<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Web Defender {{ app_version }}</title>
<style>
:root{--bg:#07111f;--panel:#0d1b2e;--panel2:#11243b;--line:#203a59;--text:#eaf2ff;--muted:#94a8c3;--white:#fff;--ink:#142033;--blue:#4d8dff;--green:#18b67a;--amber:#f2b84b;--red:#ef5b64;--soft:#f5f8fc}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(180deg,#07111f,#091522 55%,#07111f);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--text)}
.shell{max-width:1220px;margin:auto;padding:28px 20px 60px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px}.brand{display:flex;gap:12px;align-items:center}.logo{width:44px;height:44px;border:1px solid #31577e;border-radius:13px;display:grid;place-items:center;background:#102844;font-size:22px}.brand h1{font-size:22px;margin:0}.brand small{color:var(--muted)}.version{font-size:12px;color:#a8c3e6;border:1px solid var(--line);padding:7px 10px;border-radius:999px}
.search{background:#fff;border-radius:16px;padding:10px;display:flex;gap:10px;box-shadow:0 18px 50px #0005}.search input{flex:1;border:0;outline:0;padding:14px 15px;font-size:15px;color:#111827}.search button{border:0;background:#2468ed;color:#fff;font-weight:800;padding:0 22px;border-radius:11px;cursor:pointer}.loading{margin:18px 0;padding:15px;border:1px solid #2d5278;background:#0d2036;border-radius:12px;color:#bdd4ef}.hidden{display:none}
.hero[data-band="danger"]{border-color:#7f2f38;background:linear-gradient(135deg,#35151b,#161827)}.hero[data-band="high"]{border-color:#8a5524;background:linear-gradient(135deg,#322214,#121c2b)}.hero[data-band="guarded"]{border-color:#806a28}.hero[data-band="low"]{border-color:#2d6650}.hero[data-band="unverified"]{border-color:#536273}.hero[data-band="guarded_unverified"]{border-color:#806a28;background:linear-gradient(135deg,#2b2716,#10243a)}.hero{margin-top:18px;background:linear-gradient(135deg,#102945,#0b1d31);border:1px solid #294d73;border-radius:18px;padding:24px;display:grid;grid-template-columns:1fr 310px;gap:24px}.eyebrow{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#8fb7ea;font-weight:800}.hero h2{font-size:30px;margin:8px 0}.hero p{color:#b7c9df;line-height:1.6;margin:0}.meters{display:grid;grid-template-columns:1fr 1fr;gap:10px}.meter{background:#071525;border:1px solid #294766;border-radius:13px;padding:14px}.meter span{font-size:11px;color:#9bb1ca;display:block}.meter b{font-size:24px;display:block;margin-top:5px}.meter small{color:#8298b2}.action{margin-top:15px;background:#0a1a2d;border-left:3px solid var(--blue);padding:12px 14px;border-radius:8px;color:#dce9f8}
.section{margin-top:18px}.section-title{display:flex;justify-content:space-between;align-items:end;margin-bottom:10px}.section-title h3{margin:0;font-size:17px}.section-title span{font-size:12px;color:var(--muted)}
.category-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.cat{background:#fff;color:var(--ink);border-radius:14px;padding:16px;min-height:142px;border:1px solid #dce6f2}.cat-head{display:flex;justify-content:space-between;gap:10px}.cat h4{margin:0;font-size:15px}.pill{font-size:11px;font-weight:800;padding:5px 8px;border-radius:999px;background:#edf2f7}.bar{height:7px;background:#e7edf5;border-radius:999px;margin:14px 0 10px;overflow:hidden}.bar i{display:block;height:100%;background:#5b8def;border-radius:999px}.cat strong{font-size:22px}.cat p{font-size:12px;color:#64748b;margin:7px 0 0;line-height:1.45}.cat.high .bar i,.cat.critical .bar i{background:var(--red)}.cat.medium .bar i{background:var(--amber)}.cat.low .bar i{background:var(--green)}
.evidence{background:#fff;color:var(--ink);border-radius:14px;padding:6px 18px}.ev{padding:14px 0;border-bottom:1px solid #e8eef5}.ev:last-child{border:0}.ev-top{display:flex;justify-content:space-between;gap:12px}.ev h4{margin:0;font-size:14px}.sev{font-size:10px;font-weight:900;text-transform:uppercase;padding:4px 7px;border-radius:999px;background:#edf2f7}.sev.critical,.sev.high{background:#fee2e2;color:#991b1b}.sev.medium{background:#fef3c7;color:#92400e}.sev.low{background:#dcfce7;color:#166534}.ev p{font-size:13px;color:#526176;margin:7px 0}.ev code{display:block;background:#0b1728;color:#cfe2ff;padding:9px;border-radius:7px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:11px}
details.tech{margin-top:18px;border:1px solid #294d73;border-radius:14px;overflow:hidden;background:#0b1b2e}details.tech>summary{cursor:pointer;padding:16px 18px;font-weight:800;list-style:none;display:flex;justify-content:space-between}details.tech>summary small{font-weight:400;color:var(--muted)}.techbody{padding:0 14px 14px}.group{background:#fff;color:#152238;border-radius:12px;margin:10px 0;padding:15px}.group h4{margin:0 0 12px}.kv{display:grid;grid-template-columns:220px 1fr;gap:0}.kv b,.kv span{padding:8px;border-bottom:1px solid #e9eef5;font-size:12px}.kv b{color:#526176}.ok{color:#087a4e;font-weight:800}.warn{color:#a46500;font-weight:800}.bad{color:#b4232d;font-weight:800}.chips span{display:inline-block;margin:2px;padding:4px 7px;border-radius:6px;background:#edf3fa;font-size:11px}.feedback button{margin:4px;border:1px solid #cdd8e5;background:#fff;padding:7px 10px;border-radius:7px;cursor:pointer}
@media(max-width:850px){.hero{grid-template-columns:1fr}.category-grid{grid-template-columns:1fr}.meters{grid-template-columns:1fr 1fr}.kv{grid-template-columns:1fr}.top{align-items:flex-start}.brand small{display:none}}@media(max-width:520px){.search{flex-direction:column}.search button{padding:14px}.meters{grid-template-columns:1fr}.hero h2{font-size:24px}}
</style></head><body><div class="shell">
<div class="top"><div class="brand"><div class="logo">🛡️</div><div><h1>Web Defender</h1><small>Davranışsal web tehdit analizi</small></div></div><div class="version">{{ app_version }} • Render</div></div>
<div class="search"><input id="url" placeholder="Analiz edilecek URL'yi yapıştırın"><label style="display:flex;align-items:center;gap:7px;color:#172033;font-size:12px;font-weight:800;white-space:nowrap;padding:0 8px"><input id="feedOff" type="checkbox" checked style="width:16px;flex:0">Feed OFF test</label><button id="btn" onclick="analyze()">Derin Analiz</button></div>
<div id="loading" class="loading hidden">URL, ağ, tarayıcı, DOM, JavaScript, formlar ve davranış zincirleri inceleniyor…</div>
<div id="out" class="hidden">
<section class="hero"><div><div class="eyebrow">Analiz sonucu</div><h2 id="verdict">Sonuç hazırlanıyor</h2><p id="plain"></p><div class="action"><b>Ne yapmalıyım?</b><br><span id="action"></span></div></div><div class="meters"><div class="meter"><span>Tehdit kanıtı</span><b id="threat">-</b><small>0 düşük • 100 kritik</small></div><div class="meter"><span>Analiz kalitesi</span><b id="coverage">-</b><small>gözlemlenen yüzey</small></div><div class="meter"><span>Pasif risk</span><b id="passive">-</b><small>URL / domain</small></div><div class="meter"><span>Yapılandırma riski</span><b id="posture">-</b><small>site güvenlik ayarları</small></div><div class="meter"><span>Kimlik güveni</span><b id="identityTrust">-</b><small>tehdit skorunu düşürmez</small></div><div class="meter"><span>Kurumsal bağlam</span><b id="trustContext">-</b><small>RDAP • Tranco • DNS • ASN</small></div></div></section>
<section class="section"><div class="section-title"><h3>Karar kanalları</h3><span>Motor ve harici istihbarat birbirinden ayrıdır.</span></div><div class="category-grid" style="grid-template-columns:repeat(2,1fr)"><article class="cat"><div class="cat-head"><h4>Web Defender Motoru</h4><span class="pill" id="engineMode">-</span></div><strong id="engineScore">-</strong><p id="engineNote">Feed bağımsız motor sonucu.</p></article><article class="cat"><div class="cat-head"><h4>Harici İstihbarat</h4><span class="pill" id="intelMode">-</span></div><strong id="intelScore">-</strong><p id="intelNote">OpenPhish • PhishTank • URLhaus • ThreatFox</p></article></div></section>
<section class="section"><div class="section-title"><h3>Neyden şüphelendi?</h3><span>Yüzdeler olasılık değil, gözlenen kanıt gücüdür.</span></div><div id="cats" class="category-grid"></div></section>
<details class="tech" style="margin-top:18px"><summary>🧪 Motor Tanılama (V21) <small>HTTP → DOM → Identity → Trust Context → Fusion → Safety Gate</small></summary><div class="techbody"><div class="group"><pre id="diag" style="white-space:pre-wrap;word-break:break-word;font-size:11px;max-height:520px;overflow:auto">Tarama sonrası tanılama verisi burada görünür.</pre></div></div></details>
<details class="tech" id="credObsPanel"><summary>🔬 Credential Flow Observatory <small>V32.3.29 • ham sensör görünümü • skora katkı yapmaz</small></summary><div class="techbody"><div class="group"><div class="kv" id="credObsSummary"></div><h4 style="margin-top:16px">Ham gözlem</h4><pre id="credObs" style="white-space:pre-wrap;word-break:break-word;font-size:11px;max-height:720px;overflow:auto">Tarama sonrası credential-flow gözlemleri burada görünür.</pre></div></div></details>
<section class="section"><div class="section-title"><h3>Kanıtlar ve gerekçeler</h3><span>Motorun karar verirken gerçekten gördüğü şeyler</span></div><div id="evidence" class="evidence"></div></section>
<details class="tech"><summary>Teknik analiz raporunu aç <small>HTTP • Browser • DNS/TLS • DOM/JS • formlar • bulgular</small></summary><div class="techbody">
<div class="group"><h4>HTTP & Ağ</h4><div id="http" class="kv"></div></div>
<div class="group"><h4>Domain & TLS</h4><div id="domain" class="kv"></div></div>
<div class="group"><h4>Browser & Runtime</h4><div id="browser" class="kv"></div></div>
<div class="group"><h4>İçerik Edinme Motoru (V32.3.23)</h4><div id="acquisition" class="kv"></div></div>
<div class="group"><h4>Web İçeriği & Formlar</h4><div id="content" class="kv"></div></div>
<div class="group"><h4>Threat Intelligence</h4><div id="intel" class="kv"></div></div>
<div class="group"><h4>CVE / Teknoloji Eşleştirmesi</h4><div id="cves"></div></div>
<div class="group"><h4>Tüm teknik bulgular</h4><div id="allfindings"></div></div>
<div class="group feedback"><h4>Yerel öğrenme geri bildirimi</h4><div id="feedback"></div></div>
<div class="group"><h4>Fusion Trace / Karar DNA’sı (V32.3.10)</h4><pre id="fusiontrace" style="white-space:pre-wrap;word-break:break-word;font-size:11px;max-height:620px;overflow:auto"></pre></div>
<div class="group"><h4>Hatalar / eksik analiz yüzeyleri</h4><div id="errors"></div></div>
</div></details>
</div></div>
<script>
const esc=x=>String(x??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const row=(a,b)=>`<b>${esc(a)}</b><span>${b}</span>`; const yes=x=>x?'<span class="ok">Evet</span>':'<span class="warn">Hayır</span>';
function catClass(s){return s>=75?'critical':s>=50?'high':s>=25?'medium':'low'}
function fmtEvidence(v){if(v===null||v===undefined||v==='')return '';if(Array.isArray(v))return v.map(fmtEvidence).filter(Boolean).join(' • ');if(typeof v==='object'){let keys=['evidence_id','canonical_event_id','expert_family','expert','modality','producer','source','group','family','title','description','detail','observation','reason','signal','value','target','destination','url'];let p=keys.filter(k=>v[k]!==undefined&&v[k]!==null&&v[k]!=='').map(k=>k+': '+fmtEvidence(v[k]));if(p.length)return p.join(' • ');try{return JSON.stringify(v)}catch(_e){return ''}}let t=String(v);return t.includes('[object Object]')?'Kanıt ayrıntısı yapılandırılmış veri olarak alındı; teknik EV kayıtlarına bakın.':t}
async function analyze(){let u=document.getElementById('url').value.trim();if(!u)return;document.getElementById('loading').classList.remove('hidden');document.getElementById('out').classList.add('hidden');document.getElementById('btn').disabled=true;try{let r=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u,feed_off:document.getElementById('feedOff')?.checked===true})});let raw=await r.text();let d={};try{d=raw?JSON.parse(raw):{}}catch(_e){d={error:`Sunucu geçerli JSON döndürmedi (HTTP ${r.status}).`}}if(!r.ok||d.error)throw new Error(d.error||`Analiz başarısız (HTTP ${r.status})`);if(!raw)throw new Error('Sunucudan boş analiz yanıtı geldi.');render(d)}catch(e){alert(e.message)}finally{document.getElementById('loading').classList.add('hidden');document.getElementById('btn').disabled=false}}
function render(d){document.getElementById('out').classList.remove('hidden');let a=d.defender?.assessment||{},p=a.primary||{},uv=d.ui_verdict_v32361||{};let hero=document.querySelector('.hero');if(hero)hero.dataset.band=uv.band||'';document.getElementById('verdict').textContent=uv.label||d.risk_level||'Sonuç';document.getElementById('plain').textContent=a.plain_summary||'Analiz tamamlandı.';document.getElementById('action').textContent=a.action||'-';let t=d.scores?.threat;document.getElementById('threat').textContent=t==null?'N/A':t+'/100';let cv=d.coverage_v19||{};document.getElementById('coverage').textContent=cv.quality||'Sınırlı';document.querySelector('#coverage + small').textContent=(cv.observed_percent??0)+'% yüzey gözlemlendi';document.getElementById('passive').textContent=(d.scores?.passive_risk??0)+'/100';let sp=d.scores?.security_posture;document.getElementById('posture').textContent=sp==null?'N/A':sp+'/100';let it=d.identity_trust_v21||{};document.getElementById('identityTrust').textContent=(it.score??0)+'/100';let tc=d.trust_context_v21||{};document.getElementById('trustContext').textContent=(tc.score??0)+'/100';
let dc=d.decision_channels_v32320||{},eng=dc.web_defender_engine||{},ext=dc.external_intelligence||{};document.getElementById('engineScore').textContent=eng.score==null?'N/A':eng.score+'/100';document.getElementById('engineMode').textContent=dc.mode==='FEED_OFF_TEST'?'FEED OFF • karar yetkili':'Birleşik mod';document.getElementById('engineNote').textContent=dc.mode==='FEED_OFF_TEST'?'Harici feed puanları bu skora ve karara sıfır katkı verir.':'Motor kanıtları ve savunma katmanları birlikte çalışır.';document.getElementById('intelScore').textContent=(ext.score??0)+'/100';document.getElementById('intelMode').textContent=ext.match?'Eşleşme var':'Eşleşme yok';document.getElementById('intelNote').textContent=(ext.sources||[]).length?('Kaynaklar: '+ext.sources.join(', ')):'Harici kaynaklarda eşleşme gözlenmedi.';
let cats=(a.categories||[]);document.getElementById('cats').innerHTML=cats.map(c=>`<article class="cat ${catClass(c.score)}"><div class="cat-head"><h4>${esc(c.name)}</h4><span class="pill">${esc(c.level)}</span></div><div class="bar"><i style="width:${Math.min(100,c.score)}%"></i></div><strong>${c.score}/100</strong><p>${c.evidence?.length?esc(c.evidence[0].title):(c.score>0?'Kategori skoru var ancak açıklayıcı kanıt zinciri yayımlanamadı.':'Bu kategoride belirgin kanıt bulunmadı.')}</p></article>`).join('');
let ev=a.evidence||[];document.getElementById('evidence').innerHTML=ev.length?ev.map(x=>`<article class="ev"><div class="ev-top"><h4>${esc(x.type)} • ${esc(x.title)}</h4><span class="sev ${esc(x.severity)}">${esc(x.severity)}</span></div><p>${esc(x.description)}</p>${x.evidence?`<code>${esc(fmtEvidence(x.evidence))}</code>`:''}</article>`).join(''):'<article class="ev"><h4>Belirgin tehdit kanıtı bulunmadı</h4><p>Motor analiz ettiği yüzeylerde karar değiştirecek bir davranış zinciri görmedi.</p></article>';
let co=d.credential_deep_observatory_v32328||{};let cos=document.getElementById('credObsSummary');if(cos){let st=co.static||{},rr=co.rendered||{},cmp=co.comparison||{},ph=co.pipeline_handoff||{};cos.innerHTML=row('Miss stage',esc(co.miss_stage||'-'))+row('Static input',esc(st.inputs??0)+' (identity '+esc(st.identity??0)+', secret '+esc(st.secret??0)+')')+row('Rendered input',esc(rr.inputs??0)+' (identity '+esc(rr.identity??0)+', secret '+esc(rr.secret??0)+')')+row('Frame input',esc((rr.frame_identity??0)+(rr.frame_secret??0)))+row('Handler görüldü',yes(cmp.handler_seen))+row('Sink görüldü',yes(cmp.sink_seen))+row('Static credential source',yes(ph.static_credential_source))+row('External sensitive form',esc(ph.static_external_sensitive_forms??0))+row('Proven source→sink edge',esc(ph.static_proven_edges??0))+row('Independent phishing',esc(ph.independent_phishing_score??0)+'/100')+row('Canonical credential',esc(ph.canonical_credential_score??0)+'/100')+row('Canonical phishing',esc(ph.canonical_phishing_score??0)+'/100')+row('State snapshots',esc((co.stateful_surface?.snapshots||[]).length))+row('App surface verified',yes(co.stateful_surface?.application_surface_verified))+row('Interaction gate',yes(co.stateful_surface?.interaction_gate_suspected))+row('Surface reason',esc(co.stateful_surface?.reason||'-'));}let cop=document.getElementById('credObs');if(cop)cop.textContent=JSON.stringify(co,null,2);
let h=d.http||{};document.getElementById('http').innerHTML=row('İstenen URL',esc(d.analyzed_url))+row('Final URL',esc(d.final_url))+row('HTTP',esc(h.status_code??'-')+' '+esc(h.reason||''))+row('Yönlendirme',esc(h.redirect_count??0)+' adet')+row('HTTPS ulaşıldı',yes(h.https_reached))+row('Analiz modu',esc(h.network_mode||'-'))+row('Karar',esc(h.decision||'-'));
let di=d.domain_info||{},ss=d.ssl_info||{};document.getElementById('domain').innerHTML=row('Hostname',esc(di.hostname||'-'))+row('Root domain',esc(di.root_domain||'-'))+row('IP adresleri',esc((di.ips||[]).join(', ')||'-'))+row('TLS geçerli',yes(ss.valid))+row('TLS sürümü',esc(ss.version||'-'))+row('Sertifika bitişi',esc(ss.not_after||'-'));
let b=d.browser||{};document.getElementById('browser').innerHTML=row('Browser denendi',yes(b.attempted))+row('Browser başarılı',yes(b.success))+row('Final URL',esc(b.final_url||'-'))+row('Başlık',esc(b.title||'-'))+row('DOM boyutu',esc(b.dom_length??0)+' karakter')+row('Ağ istekleri',esc((b.requests||[]).length))+row('Engellenen istek',esc((b.blocked_requests||[]).length))+row('Runtime kararı',esc(b.decision||'-'));
let ac=d.content_acquisition_v32316||{};document.getElementById('acquisition').innerHTML=row('Durum',esc(ac.display_name||ac.state||'-'))+row('HTTP gerçek gövde',yes(ac.http_body_observed))+row('Browser gerçek DOM',yes(ac.browser_body_observed))+row('Gözlenen byte',esc((ac.bytes_observed||0)+(ac.dom_bytes_observed||0)))+row('Kör noktalar',esc((ac.blind_spots||[]).join(', ')||'Yok'))+row('Recovery',esc(ac.recovery?.attempted?(ac.recovery?.adopted?'Başarılı':'Denenmiş / başarısız'):'Gerekmedi'));
let sem=b.semantic_dom||{},forms=b.forms||d.forms||[],frames=b.frames||d.iframes||[];document.getElementById('content').innerHTML=row('Form sayısı',esc(forms.length))+row('Iframe sayısı',esc(frames.length))+row('Input sayısı',esc((sem.inputs||[]).length))+row('Runtime hooks',esc(Object.values(b.runtime_hooks||{}).reduce((n,x)=>n+(Array.isArray(x)?x.length:0),0)))+row('Şüpheli JS pattern',esc((d.suspicious_patterns||[]).length))+row('İndirme bağlantısı',esc((d.downloads||[]).length));
let ti=d.threat_intelligence||{};document.getElementById('intel').innerHTML=row('Kontrol edildi',yes(ti.checked))+row('Kaynaklar',esc((ti.sources||[]).map(x=>x.name+': '+x.status).join(', ')||'-'))+row('IOC eşleşmeleri',esc((ti.matches||[]).map(x=>x.source+' / '+x.type).join(', ')||'Yok'))+row('Kaynak hataları',esc((ti.errors||[]).length));let ci=d.cve_intelligence||{};document.getElementById('cves').innerHTML=(ci.candidates||[]).length?(ci.candidates||[]).map(x=>`<div class="ev"><h4>${esc(x.cve)} • ${esc(x.product)} ${esc(x.version)}</h4><p>${esc(x.description)}</p><code>Aday eşleşme; sürüm/parmak izi doğrulanmadan açık kesinleşmiş sayılmaz.</code></div>`).join(''):'<div class="ev"><p>Doğrulanabilir ürün+sürüm parmak izi yoksa CVE ataması yapılmaz.</p></div>';
let fs=d.findings||[];document.getElementById('allfindings').innerHTML=fs.length?fs.map(x=>`<div class="ev"><div class="ev-top"><h4>${esc(x.title)}</h4><span class="sev ${esc(x.severity)}">${esc(x.severity)}</span></div><p>${esc(x.description)}</p>${x.evidence?`<code>${esc(fmtEvidence(x.evidence))}</code>`:''}</div>`).join(''):'Bulgu yok.';
let sid=d.scan?.scan_id||'';document.getElementById('feedback').innerHTML=`Bu sonucu doğrulayarak yerel modele eğitim örneği ekleyebilirsiniz.<br><button onclick="fb('${esc(sid)}','safe')">Güvenli</button><button onclick="fb('${esc(sid)}','phishing')">Phishing</button><button onclick="fb('${esc(sid)}','malware')">Malware</button><button onclick="fb('${esc(sid)}','suspicious')">Şüpheli</button>`;let dg=document.getElementById('diag');if(dg)dg.textContent=JSON.stringify(d.diagnostics_v19_1||{},null,2);let ft=document.getElementById('fusiontrace');if(ft)ft.textContent=JSON.stringify(d.fusion_trace_v32310||{},null,2);let er=d.errors||[];document.getElementById('errors').innerHTML=er.length?er.map(x=>`<div class="ev"><h4>${esc(x.module)}</h4><code>${esc(x.error)}</code></div>`).join(''):'Analiz modülleri hatasız tamamlandı.'}
async function fb(id,v){let r=await fetch('/api/feedback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:id,verdict:v})});let d=await r.json();alert(d.ok?'Geri bildirim kaydedildi.':(d.error||'Kaydedilemedi.'))}
</script></body></html>'''


def _admin_ok_v30():
    token=os.getenv("THREAT_INTEL_ADMIN_TOKEN","").strip()
    return bool(token and request.headers.get("X-Web-Defender-Token","")==token)

def _admin_error_v30():
    token=os.getenv("THREAT_INTEL_ADMIN_TOKEN","").strip()
    if not token: return jsonify({"ok":False,"error":"THREAT_INTEL_ADMIN_TOKEN ayarlanmamış; admin endpoint devre dışı."}),503
    return jsonify({"ok":False,"error":"Yetkisiz: X-Web-Defender-Token geçersiz."}),401

@app.post("/api/v31/source/register")
def v31_source_register():
    if not _admin_ok_v30(): return _admin_error_v30()
    d=request.get_json(silent=True) or {}; a=SecurityAnalyzer()
    return jsonify(a.register_discovery_source_v31(str(d.get("name") or ""),str(d.get("source_type") or ""),
        str(d.get("trust_level") or "contextual"),d.get("config") or {}))

@app.post("/api/v31/feed/sync")
def v312_feed_sync():
    if not _admin_ok_v30(): return _admin_error_v30()
    d=request.get_json(silent=True) or {}; a=SecurityAnalyzer()
    sid=str(d.get("source_id") or "")
    if sid: return jsonify(a.sync_discovery_source_v312(sid))
    return jsonify({"ok":True,"results":a.sync_due_feeds_v312(int(d.get("limit") or 8))})

@app.get("/api/v31/feed/status")
def v312_feed_status():
    if not _admin_ok_v30(): return _admin_error_v30()
    return jsonify({"ok":True,**SecurityAnalyzer().feed_sync_status_v312()})

@app.post("/api/v31/source/ingest")
def v31_source_ingest():
    if not _admin_ok_v30(): return _admin_error_v30()
    d=request.get_json(silent=True) or {}; a=SecurityAnalyzer()
    return jsonify(a.ingest_discovery_urls_v31(str(d.get("source_id") or ""),d.get("urls") or []))

@app.get("/api/v32/zero-day/status")
def v32_zero_day_status():
    if not _admin_ok_v30(): return _admin_error_v30()
    return jsonify({"ok":True,**SecurityAnalyzer().zero_day_status_v32(int(request.args.get("limit","50")))})

@app.post("/api/v31/campaign/detect")
def v313_campaign_detect():
    if not _admin_ok_v30(): return _admin_error_v30()
    d=request.get_json(silent=True) or {}; a=SecurityAnalyzer()
    return jsonify(a.detect_campaign_v313(str(d.get("seed_type") or "domain"),
        str(d.get("seed_value") or ""),int(d.get("max_nodes") or 180)))

@app.post("/api/v31/campaign/from-observation")
def v313_campaign_observation():
    if not _admin_ok_v30(): return _admin_error_v30()
    d=request.get_json(silent=True) or {}
    return jsonify(SecurityAnalyzer().auto_campaign_from_observation_v313(str(d.get("observation_id") or "")))

@app.get("/api/v31/campaign/status")
def v313_campaign_status():
    if not _admin_ok_v30(): return _admin_error_v30()
    return jsonify({"ok":True,**SecurityAnalyzer().campaign_status_v313(int(request.args.get("limit","50")))})

@app.post("/api/v31/hunt/expand")
def v31_hunt_expand():
    if not _admin_ok_v30(): return _admin_error_v30()
    d=request.get_json(silent=True) or {}; a=SecurityAnalyzer()
    return jsonify(a.expand_threat_hunt_v31(str(d.get("observation_id") or ""),int(d.get("max_depth") or 1)))

@app.get("/api/v31/status")
def v31_status():
    if not _admin_ok_v30(): return _admin_error_v30()
    a=SecurityAnalyzer()
    return jsonify({"ok":True,"persistence":a.persistence_status_v31(),"discovery":a.discovery_status_v301()})

@app.post("/api/discovery/enqueue")
def discovery_enqueue_v301():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}; a=SecurityAnalyzer()
    return jsonify(a.enqueue_discovery_v301(data.get("url"),str(data.get("source") or "manual"),
        data.get("source_ref"),int(data.get("priority") or 50)))

@app.get("/api/discovery/status")
def discovery_status_api_v301():
    if not _admin_ok_v30(): return _admin_error_v30()
    return jsonify({"ok":True,**SecurityAnalyzer().discovery_status_v301()})

@app.post("/api/discovery/verify")
def discovery_verify_v301():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}; a=SecurityAnalyzer()
    return jsonify(a.verify_observation_v301(str(data.get("observation_id") or ""),
        str(data.get("label") or ""),str(data.get("family") or "general"),
        str(data.get("verifier") or "analyst"),str(data.get("source") or "analyst"),
        float(data.get("confidence") or 0),str(data.get("notes") or "")))

@app.post("/api/discovery/regression")
def discovery_regression_v301():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}; a=SecurityAnalyzer()
    return jsonify({"ok":True,**a.continuous_regression_v301(int(data.get("limit") or 2000),
        str(data.get("window_name") or "verified-live"))})


@app.post("/api/evolution/snapshot")
def evolution_snapshot_v30():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}
    a=SecurityAnalyzer()
    snap=a.create_model_snapshot_v30(data.get("weights") or {},data.get("global_metrics") or {},
        data.get("family_metrics") or {},data.get("parent_model_id"),"shadow",
        str(data.get("dataset_fingerprint") or "")[:128],str(data.get("reason") or "candidate"))
    return jsonify({"ok":True,**snap})

@app.post("/api/evolution/family-guard")
def evolution_family_guard_v30():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}; a=SecurityAnalyzer()
    return jsonify({"ok":True,"guard":a.evaluate_family_guard_v30(
        data.get("baseline_rows") or [],data.get("candidate_rows") or [],int(data.get("min_family_cases") or 20))})

@app.post("/api/evolution/drift")
def evolution_drift_v30():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}; a=SecurityAnalyzer()
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
    a=SecurityAnalyzer()
    return jsonify(a.promote_model_v30(str(data.get("model_id") or ""),str(data.get("reason") or "verified promotion")))

@app.post("/api/evolution/rollback")
def evolution_rollback_v30():
    if not _admin_ok_v30(): return _admin_error_v30()
    data=request.get_json(silent=True) or {}; a=SecurityAnalyzer()
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
    a=SecurityAnalyzer()
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
    a=SecurityAnalyzer()
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


def browser_worker_main(target_url, checkpoint_path=""):
    out = {
        "available": False, "success": False, "status_code": None,
        "final_url": "", "title": "", "dom_length": 0, "html": "",
        "requests": [], "responses": [], "downloads": [], "popups": [], "dialogs": [],
        "forms": [], "frames": [], "dom_mutations": {}, "runtime_hooks": {}, "script_signals": {}, "navigations": [], "semantic_dom": {}, "websockets": [], "screenshot_sha256": None, "screenshot_dhash": None,
        "blocked_requests": [], "console_errors": [], "error": "", "decision": "not_run", "failure_kind": "", "proxy_mode": "", "proxy_server": "",
        "stateful_surface": {"snapshots": [], "application_surface_verified": False, "interaction_gate_suspected": False, "reason": "not_observed"},
        "differential_observation": {"baseline": {}, "profiles": [], "policy": "bounded_no_interaction"}
    }
    def _checkpoint(stage):
        out["checkpoint_stage"] = stage
        out["checkpoint_at"] = time.time()
        if not checkpoint_path:
            return
        try:
            tmp = checkpoint_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(out, fh, ensure_ascii=False)
            os.replace(tmp, checkpoint_path)
        except Exception:
            pass

    _checkpoint("worker_started")
    try:
        from playwright.sync_api import sync_playwright
        out["available"] = True
    except Exception as exc:
        out["error"] = (
            "Playwright kurulu değil. Kurulum: pip install playwright && "
            "python -m playwright install chromium | " + str(exc)
        )
        print(json.dumps(out, ensure_ascii=False))
        return

    try:
        p = urlparse(normalize_url(target_url))
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("Geçersiz browser hedefi.")
        resolve_public_ips(p.hostname)

        with sync_playwright() as pw:
            launch_kwargs = {
                "headless": True,
                "args": [
                    "--disable-dev-shm-usage",
                    "--disable-background-networking",
                    "--disable-sync",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-component-extensions-with-background-pages",
                    "--disable-features=Translate,BackForwardCache,MediaRouter,OptimizationHints",
                    "--renderer-process-limit=2",
                    "--no-sandbox",
                    "--headless",
                ]
            }
            if RUNNING_ON_PYTHONANYWHERE and os.path.exists("/usr/bin/chromium"):
                launch_kwargs["executable_path"] = "/usr/bin/chromium"

            # Chromium does not reliably consume PythonAnywhere's proxy environment
            # in the same way requests does. Pass the proxy explicitly to Playwright.
            proxy_url = (
                os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
                or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or ""
            ).strip()
            if proxy_url:
                pp = urlparse(proxy_url)
                if pp.scheme and pp.hostname:
                    proxy_server = f"{pp.scheme}://{pp.hostname}"
                    if pp.port:
                        proxy_server += f":{pp.port}"
                    proxy_cfg = {"server": proxy_server}
                    if pp.username:
                        proxy_cfg["username"] = unquote(pp.username)
                    if pp.password:
                        proxy_cfg["password"] = unquote(pp.password)
                    launch_kwargs["proxy"] = proxy_cfg
                    out["proxy_mode"] = "explicit-playwright-proxy"
                    out["proxy_server"] = proxy_server
                else:
                    out["proxy_mode"] = "invalid-env-proxy"
            else:
                out["proxy_mode"] = "direct-browser"

            _t_launch=time.perf_counter()
            _checkpoint("before_chromium_launch")
            browser = pw.chromium.launch(**launch_kwargs)
            _checkpoint("chromium_launched")
            out.setdefault("timings_ms", {})["chromium_launch"] = round((time.perf_counter()-_t_launch)*1000,2)
            context = browser.new_context(
                accept_downloads=True,
                ignore_https_errors=True,
                java_script_enabled=True,
                service_workers="block",
                user_agent=USER_AGENT,
                locale=os.getenv("WEB_DEFENDER_BROWSER_LOCALE", "en-US"),
                extra_http_headers={"Accept-Language": os.getenv("WEB_DEFENDER_BROWSER_ACCEPT_LANGUAGE", "en-US,en;q=0.9")},
            )
            page = context.new_page()
            page.set_default_timeout(5000)
            page.set_default_navigation_timeout(8500)
            _checkpoint("page_created")

            # V32.3.3: cache host safety decisions. A modern page can request hundreds
            # of resources from the same hosts; repeating DNS validation for every
            # request can exhaust the browser-worker deadline.
            _route_host_cache = {}
            _target_host=(p.hostname or "").lower().rstrip(".")
            _route_host_cache[_target_host]=(True,"")  # already validated before Chromium launch
            def _resolve_bounded(key, seconds=1.25):
                box={}
                def work():
                    try: box["ips"]=resolve_public_ips(key)
                    except Exception as exc: box["error"]=str(exc)
                t=threading.Thread(target=work, daemon=True); t.start(); t.join(seconds)
                if t.is_alive(): raise TimeoutError("bounded_dns_timeout")
                if box.get("error"): raise ValueError(box["error"])
                return box.get("ips") or []
            def _public_host_once(host):
                key=(host or "").strip().lower().rstrip(".")
                if key in _route_host_cache:
                    ok,err=_route_host_cache[key]
                    if not ok: raise ValueError(err)
                    return True
                try:
                    _resolve_bounded(key)
                    _route_host_cache[key]=(True,"")
                    return True
                except Exception as exc:
                    _route_host_cache[key]=(False,str(exc)[:180])
                    raise

            def route_guard(route):
                u = route.request.url
                try:
                    if route.request.resource_type in ("font", "media"):
                        out["blocked_requests"].append({"url": u[:300], "reason": "resource_budget"})
                        return route.abort()
                    q = urlparse(u)
                    if q.scheme not in ("http", "https") or not q.hostname:
                        out["blocked_requests"].append({"url": u[:300], "reason": "scheme"})
                        return route.abort()
                    _public_host_once(q.hostname)
                    return route.continue_()
                except Exception as exc:
                    out["blocked_requests"].append({"url": u[:300], "reason": str(exc)[:180]})
                    return route.abort()

            page.route("**/*", route_guard)
            page.on("request", lambda req: out["requests"].append({
                "url": req.url[:500], "method": req.method, "resource_type": req.resource_type,
                "has_post_data": bool(req.post_data)
            }) if len(out["requests"]) < 300 else None)
            page.on("websocket", lambda ws: out["websockets"].append({"url":ws.url[:700]}) if len(out["websockets"]) < 80 else None)
            page.on("response", lambda rr: out["responses"].append({
                "url": rr.url[:500], "status": rr.status,
                "content_type": rr.headers.get("content-type", "")[:200],
                "content_disposition": rr.headers.get("content-disposition", "")[:300]
            }) if len(out["responses"]) < 300 else None)
            page.on("framenavigated", lambda fr: out["navigations"].append({"url": fr.url[:500], "main": fr == page.main_frame}) if len(out["navigations"]) < 80 else None)
            page.on("popup", lambda pg: out["popups"].append({"url": pg.url[:500]}) if len(out["popups"]) < 30 else None)
            page.on("dialog", lambda d: (out["dialogs"].append({"type": d.type, "message": d.message[:300]}) if len(out["dialogs"]) < 30 else None, d.dismiss()))
            page.on("console", lambda msg: out["console_errors"].append(msg.text[:500])
                    if msg.type == "error" and len(out["console_errors"]) < 50 else None)
            def inspect_download(dl):
                item={"url":dl.url[:500],"suggested_filename":dl.suggested_filename[:250],"sha256":None,"size":None,"hash_status":"metadata_only"}
                try:
                    fp=dl.path()
                    if fp and os.path.isfile(fp):
                        item["size"]=os.path.getsize(fp)
                        if item["size"] <= int(os.getenv("MAX_DOWNLOAD_HASH_BYTES",str(25*1024*1024))):
                            hh=hashlib.sha256()
                            with open(fp,"rb") as fh:
                                for ch in iter(lambda:fh.read(1024*1024),b""): hh.update(ch)
                            item["sha256"]=hh.hexdigest(); item["hash_status"]="hashed"
                        else: item["hash_status"]="too_large"
                except Exception as e:
                    item["hash_status"]="error"; item["hash_error"]=str(e)[:180]
                if len(out["downloads"])<30: out["downloads"].append(item)
            page.on("download",inspect_download)

            page.add_init_script("""() => {
              window.__wdMut = {forms_added:0,password_fields_added:0,nodes_added:0};
              window.__wdRuntime = {fetches:[], xhr:[], beacons:[], nav:[], form_submits:[], sensitive_events:0};
              window.__wdListeners = [];
              const oadd=EventTarget.prototype.addEventListener;
              EventTarget.prototype.addEventListener=function(type,listener,opts){ try{ if(['submit','click','change','input'].includes(String(type).toLowerCase())){ let src=''; try{src=String(listener).slice(0,5000)}catch(e){} window.__wdListeners.push({type:String(type).toLowerCase(),target:(this?.tagName||this?.constructor?.name||'').toString().slice(0,80),handler_source:src}); if(window.__wdListeners.length>200) window.__wdListeners.shift(); }}catch(e){} return oadd.call(this,type,listener,opts); };
              const clip=(x,n=700)=>String(x||'').slice(0,n);
              const ofetch=window.fetch; if(ofetch) window.fetch=function(input,init){ try{window.__wdRuntime.fetches.push({url:clip(input?.url||input),method:clip(init?.method||'GET',20),has_body:!!init?.body});}catch(e){} return ofetch.apply(this,arguments); };
              const oopen=XMLHttpRequest.prototype.open, osend=XMLHttpRequest.prototype.send;
              XMLHttpRequest.prototype.open=function(m,u){this.__wd={method:clip(m,20),url:clip(u)}; return oopen.apply(this,arguments)};
              XMLHttpRequest.prototype.send=function(body){try{window.__wdRuntime.xhr.push({...this.__wd,has_body:!!body})}catch(e){} return osend.apply(this,arguments)};
              const obeacon=navigator.sendBeacon?.bind(navigator); if(obeacon) navigator.sendBeacon=function(u,d){try{window.__wdRuntime.beacons.push({url:clip(u),has_body:!!d})}catch(e){} return obeacon(u,d)};
              document.addEventListener('submit',e=>{try{const f=e.target;window.__wdRuntime.form_submits.push({action:clip(f.action||location.href),method:clip(f.method||'GET',20)})}catch(x){}},true);
              document.addEventListener('input',e=>{try{if(e.target?.matches?.('input[type=password],input[autocomplete*=one-time],input[autocomplete*=cc-]'))window.__wdRuntime.sensitive_events++}catch(x){}},true);
              new MutationObserver(ms => { for (const m of ms) for (const n of m.addedNodes || []) {
                if (!n || n.nodeType !== 1) continue; window.__wdMut.nodes_added++;
                if (n.matches?.('form')) window.__wdMut.forms_added++;
                if (n.matches?.('input[type=password]')) window.__wdMut.password_fields_added++;
                window.__wdMut.forms_added += n.querySelectorAll?.('form').length || 0;
                window.__wdMut.password_fields_added += n.querySelectorAll?.('input[type=password]').length || 0;
              }}).observe(document, {subtree:true, childList:true});
            }""")
            _t_nav=time.perf_counter()
            out["tls_observation_mode"] = "browser_ignore_https_errors_for_observation_only"
            _checkpoint("before_navigation")
            resp = None
            try:
                resp = page.goto(target_url, wait_until="domcontentloaded", timeout=8500)
                out["navigation_state"]="domcontentloaded"
            except Exception as nav_exc:
                out["navigation_error"]=str(nav_exc)[:700]
                # A navigation timeout must not discard an already committed/rendered document.
                try:
                    if page.url and page.url not in ("about:blank", ""):
                        out["navigation_state"]="partial_committed"
                    else:
                        raise nav_exc
                except Exception:
                    raise nav_exc
            out.setdefault("timings_ms", {})["domcontentloaded"] = round((time.perf_counter()-_t_nav)*1000,2)
            _checkpoint("navigation_returned")
            # V32.3.23: bounded staged observation. We do not click, type or submit.
            # A short second window catches delayed phishing UI without turning the worker into a crawler.
            # V32.3.30 Stateful Surface Discovery. Observation only: no click, type or submit.
            # Multiple bounded snapshots catch delayed/SPAs/JS-created credential surfaces.
            def _surface_snapshot(label):
                try:
                    z=page.evaluate("""() => {
                      const vis=e=>{try{const s=getComputedStyle(e),r=e.getBoundingClientRect();return s.display!=='none'&&s.visibility!=='hidden'&&r.width>0&&r.height>0}catch(x){return false}};
                      const inputs=[...document.querySelectorAll('input,textarea')];
                      const forms=[...document.forms];
                      const controls=[...document.querySelectorAll('button,a,[role=button],input[type=submit]')].filter(vis).slice(0,100).map(x=>(x.innerText||x.value||x.getAttribute('aria-label')||x.getAttribute('title')||'').trim()).filter(Boolean);
                      const blob=(document.body?.innerText||'').slice(0,160000);
                      const low=(controls.join(' ')+' '+blob.slice(0,40000)).toLowerCase();
                      const auth=/log[ -]?in|sign[ -]?in|verify|verification|account|password|passcode|otp|one[ -]?time|email|e-mail|username|continue|next|giriş|oturum|doğrula|şifre|parola|hesap|kullanıcı/.test(low);
                      const meta=(document.querySelector('meta[http-equiv="refresh" i]')||{}).content||'';
                      return {url:location.href,title:document.title||'',html_length:document.documentElement?.outerHTML?.length||0,text_length:blob.length,inputs:inputs.length,forms:forms.length,iframes:document.querySelectorAll('iframe').length,buttons:document.querySelectorAll('button,input[type=submit],[role=button]').length,links:document.links.length,visible_controls:controls.slice(0,40),auth_intent:auth,meta_refresh:meta,ready_state:document.readyState};
                    }""")
                    z["label"]=label; z["at_ms"]=round((time.perf_counter()-_t_nav)*1000,2)
                    out["stateful_surface"]["snapshots"].append(z)
                except Exception as se:
                    out["stateful_surface"]["snapshots"].append({"label":label,"error":str(se)[:300]})
            page.wait_for_timeout(700); _surface_snapshot("t+0.7s")
            page.wait_for_timeout(1400); _surface_snapshot("t+2.1s")
            # Extra bounded quiet window for delayed UI. Still no interaction.
            page.wait_for_timeout(2400); _surface_snapshot("t+4.5s")
            snaps=[x for x in out["stateful_surface"]["snapshots"] if isinstance(x,dict) and not x.get("error")]
            if snaps:
                first,last=snaps[0],snaps[-1]
                changed=any((x.get("inputs"),x.get("forms"),x.get("iframes"),x.get("url"),x.get("html_length")) != (first.get("inputs"),first.get("forms"),first.get("iframes"),first.get("url"),first.get("html_length")) for x in snaps[1:])
                has_surface=any((x.get("inputs",0)>0 or x.get("forms",0)>0) for x in snaps)
                auth_gate=any(bool(x.get("auth_intent")) and not (x.get("inputs",0)>0 or x.get("forms",0)>0) for x in snaps)
                out["stateful_surface"].update({"application_surface_verified":bool(has_surface),"interaction_gate_suspected":bool(auth_gate),"changed_across_snapshots":bool(changed),"reason":"interactive_surface_observed" if has_surface else ("auth_or_continue_language_without_form" if auth_gate else "no_form_or_input_observed")})

            # Runtime DOM snapshot: forms, iframes, sensitive inputs and script-obfuscation indicators.
            try:
                snap = page.evaluate("""() => {
                  const txt = (document.body?.innerText || '').slice(0, 120000);
                  const inputs = [...document.querySelectorAll('input,textarea')].slice(0,120).map(i => ({
                    type:(i.type||'').toLowerCase(), name:i.name||'', id:i.id||'', placeholder:i.placeholder||'',
                    autocomplete:i.autocomplete||'', label:(i.labels && i.labels[0] ? i.labels[0].innerText : ''),
                    hidden: !!(i.hidden || i.type==='hidden' || getComputedStyle(i).display==='none' || getComputedStyle(i).visibility==='hidden')
                  }));
                  const forms = [...document.forms].slice(0,60).map(f => {
                    const ins=[...f.querySelectorAll('input,textarea')];
                    const blob=ins.map(i => `${i.type} ${i.name} ${i.id} ${i.placeholder} ${i.autocomplete}`).join(' ').toLowerCase();
                    return {action:f.action||location.href, method:(f.method||'get').toUpperCase(),
                      has_password:ins.some(i=>i.type==='password'), has_otp:/otp|one-time|verification|sms.?code|doğrulama.?kod/.test(blob),
                      has_card:/card|cc-number|cvv|cvc|iban|kart/.test(blob), input_count:ins.length};
                  });
                  const scripts=[...document.scripts].map(s=>s.textContent||'').join('\n').slice(0,500000);
                  const count = r => (scripts.match(r)||[]).length;
                  const shadowInputs=[]; const shadowForms=[];
                  const walkShadow=(root,depth=0)=>{ if(!root || depth>5) return;
                    for(const el of [...(root.querySelectorAll?.('*')||[])].slice(0,2500)){
                      if(el.shadowRoot){
                        for(const i of [...el.shadowRoot.querySelectorAll('input,textarea')].slice(0,80)) shadowInputs.push({type:(i.type||'').toLowerCase(),name:i.name||'',id:i.id||'',placeholder:i.placeholder||'',autocomplete:i.autocomplete||'',hidden:false,source:'shadow_dom'});
                        for(const f of [...el.shadowRoot.querySelectorAll('form')].slice(0,30)){ const ins=[...f.querySelectorAll('input,textarea')]; shadowForms.push({action:f.action||location.href,method:(f.method||'get').toUpperCase(),has_password:ins.some(i=>i.type==='password'),has_otp:ins.some(i=>/otp|one-time|verification|code/i.test(`${i.name} ${i.id} ${i.placeholder} ${i.autocomplete}`)),has_card:ins.some(i=>/card|cc-number|cvv|cvc|iban/i.test(`${i.name} ${i.id} ${i.placeholder} ${i.autocomplete}`)),input_count:ins.length,source:'shadow_dom'}); }
                        walkShadow(el.shadowRoot,depth+1);
                      }
                    }
                  };
                  try{walkShadow(document)}catch(e){}
                  return {
                    semantic_dom:{title:document.title||'', headings:[...document.querySelectorAll('h1,h2,h3')].slice(0,40).map(x=>x.innerText.trim()),
                      buttons:[...document.querySelectorAll('button,input[type=submit]')].slice(0,60).map(x=>(x.innerText||x.value||'').trim()), visible_text:txt, inputs:[...inputs,...shadowInputs].slice(0,200), shadow_input_count:shadowInputs.length,
                      identity_surfaces:{
                        og_title:(document.querySelector('meta[property="og:title"]')||{}).content||'',
                        app_name:(document.querySelector('meta[name="application-name"]')||{}).content||'',
                        header_text:[...document.querySelectorAll('header,[role=banner],nav')].slice(0,12).map(x=>(x.innerText||'').trim()).join(' ').slice(0,5000),
                        logo_text:[...document.querySelectorAll('header img,[role=banner] img,img[alt*="logo" i],svg[aria-label],a[aria-label]')].slice(0,40).map(x=>[x.alt||'',x.getAttribute('aria-label')||'',x.getAttribute('title')||''].join(' ')).join(' ').slice(0,5000)
                      }},
                    forms:[...forms,...shadowForms].slice(0,100), shadow_form_count:shadowForms.length,
                    frames:[...document.querySelectorAll('iframe')].slice(0,60).map(x=>({src:x.src||'', title:x.title||''})),
                    script_signals:{eval_like:count(/\\beval\\s*\\(/gi), decoder_like:count(/\\batob\\s*\\(|decodeURIComponent\\s*\\(|unescape\\s*\\(/gi),
                      from_char_code:count(/String[.]fromCharCode/gi), long_encoded_blobs:count(/[A-Za-z0-9+/]{180,}={0,2}/g),
                      hex_escape_blobs:count(/(?:\\x[0-9a-fA-F]{2}){8,}/g), unicode_escape_blobs:count(/(?:\\u[0-9a-fA-F]{4}){6,}/g)}
                  };
                }""")
                out["semantic_dom"] = snap.get("semantic_dom", {})
                out["forms"] = snap.get("forms", [])
                out["frames"] = snap.get("frames", [])
                out["script_signals"] = snap.get("script_signals", {})
                # V32.3.22: inspect frame DOMs without interacting with them. Playwright can
                # observe attached frames; failures are isolated per frame.
                frame_surfaces=[]
                for fr in page.frames[:20]:
                    if fr == page.main_frame:
                        continue
                    try:
                        fs=fr.evaluate("""() => ({url:location.href,title:document.title||'',visible:(document.body?.innerText||'').slice(0,12000),inputs:[...document.querySelectorAll('input,textarea')].slice(0,60).map(i=>({type:(i.type||'').toLowerCase(),name:i.name||'',id:i.id||'',placeholder:i.placeholder||'',autocomplete:i.autocomplete||''})),forms:[...document.forms].slice(0,30).map(f=>({action:f.action||location.href,method:(f.method||'get').toUpperCase(),has_password:!!f.querySelector('input[type=password]')}))})""")
                        frame_surfaces.append(fs)
                    except Exception as fe:
                        frame_surfaces.append({"url":fr.url[:500],"error":str(fe)[:180]})
                out["frame_surfaces"]=frame_surfaces
                try:
                    out["runtime_hooks"] = page.evaluate("() => window.__wdRuntime || {}") or {}
                    out["registered_listeners"] = page.evaluate("() => window.__wdListeners || []") or []
                except Exception:
                    out["runtime_hooks"] = {}
                    out["registered_listeners"] = []
                try:
                    out["dom_mutations"] = page.evaluate("() => window.__wdMut || {}") or {}
                except Exception:
                    out["dom_mutations"] = {}
            except Exception as exc:
                out["console_errors"].append(("DOM snapshot: " + str(exc))[:500])

            out["route_host_cache_size"] = len(_route_host_cache)
            out["status_code"] = resp.status if resp else None
            out["final_url"] = page.url
            out["title"] = page.title()[:500]
            try:
                shot=page.screenshot(full_page=False,type="png")
                out["screenshot_sha256"]=hashlib.sha256(shot).hexdigest()
                try:
                    from PIL import Image
                    im=Image.open(io.BytesIO(shot)).convert("L").resize((9,8))
                    px=list(im.getdata()); bits=[]
                    for yy in range(8):
                        row=px[yy*9:(yy+1)*9]
                        bits.extend(1 if row[x]>row[x+1] else 0 for x in range(8))
                    out["screenshot_dhash"]=f"{sum(bit << (63-i) for i,bit in enumerate(bits)):016x}"
                except Exception:
                    out["screenshot_dhash"]=None
            except Exception:
                out["screenshot_sha256"]=None; out["screenshot_dhash"]=None
            html = page.content()
            if len(html) > MAX_CONTENT_SIZE:
                html = html[:MAX_CONTENT_SIZE]
            out["dom_length"] = len(html)
            _checkpoint("dom_snapshot_complete")
            bs = out["status_code"]
            browser_2xx = bs is not None and 200 <= int(bs) < 300
            committed_observable = bool(html and len(html) > 200 and page.url not in ("", "about:blank"))
            out["committed_observable"] = committed_observable
            out["access_restricted"] = bs in (401, 403, 429)
            out["decision"] = ("content_analyzable" if browser_2xx else
                               "access_restricted" if out["access_restricted"] else
                               "target_content_unavailable" if bs is not None and 400 <= int(bs) < 500 else
                               "upstream_error" if bs is not None and 500 <= int(bs) < 600 else
                               "http_non_success")
            out["html"] = html if browser_2xx else ""
            out["success"] = bool(html) and browser_2xx
            if not browser_2xx:
                out["error"] = (f"Browser HTTP {bs}: hedef uygulamanın gerçek içeriği doğrulanamadı."
                                if bs is not None else
                                "Browser geçerli hedef yanıtı alamadı.")
            # V32.3.31 Differential Observation Engine.
            # Bounded passive reloads only. No click, type, submit, CAPTCHA/challenge bypass or payload execution.
            try:
                base_snap=(out.get("stateful_surface") or {}).get("snapshots") or []
                last_base=next((x for x in reversed(base_snap) if isinstance(x,dict) and not x.get("error")), {})
                out["differential_observation"]["baseline"]={
                    "profile":"baseline_en_desktop","status":out.get("status_code"),"final_url":out.get("final_url"),
                    "title":out.get("title"),"html_length":out.get("dom_length"),"inputs":last_base.get("inputs",0),
                    "forms":last_base.get("forms",0),"iframes":last_base.get("iframes",0),"auth_intent":last_base.get("auth_intent",False)
                }
                profs=[
                    {"profile":"tr_desktop","locale":"tr-TR","accept":"tr-TR,tr;q=0.9,en;q=0.6","viewport":{"width":1365,"height":768},"js":True},
                    {"profile":"mobile_en","locale":"en-US","accept":"en-US,en;q=0.9","viewport":{"width":390,"height":844},"js":True},
                    {"profile":"nojs_en","locale":"en-US","accept":"en-US,en;q=0.9","viewport":{"width":1365,"height":768},"js":False},
                ]
                for cfg in profs:
                    item={"profile":cfg["profile"],"success":False}
                    c2=None
                    try:
                        c2=browser.new_context(ignore_https_errors=True,java_script_enabled=cfg["js"],service_workers="block",user_agent=USER_AGENT,locale=cfg["locale"],viewport=cfg["viewport"],extra_http_headers={"Accept-Language":cfg["accept"]})
                        p2=c2.new_page(); p2.set_default_timeout(3500); p2.set_default_navigation_timeout(5500)
                        # Same SSRF/private-network guard as the primary context.
                        p2.route("**/*", route_guard)
                        r2=None
                        try: r2=p2.goto(target_url,wait_until="domcontentloaded",timeout=5500)
                        except Exception: pass
                        p2.wait_for_timeout(700 if cfg["js"] else 150)
                        z=p2.evaluate("""() => { const t=(document.body?.innerText||'').slice(0,50000); const low=t.toLowerCase(); return {title:document.title||'',html_length:document.documentElement?.outerHTML?.length||0,inputs:document.querySelectorAll('input,textarea').length,forms:document.forms.length,iframes:document.querySelectorAll('iframe').length,auth_intent:/log[ -]?in|sign[ -]?in|verify|verification|password|passcode|otp|email|username|continue|next|giriş|oturum|doğrula|şifre|parola|hesap|kullanıcı/.test(low)} }""")
                        item.update(z or {}); item.update({"status":r2.status if r2 else None,"final_url":p2.url,"success":bool(p2.url and p2.url!='about:blank'),"java_script":cfg["js"],"locale":cfg["locale"],"viewport":cfg["viewport"]})
                    except Exception as de:
                        item["error"]=str(de)[:300]
                    finally:
                        try:
                            if c2: c2.close()
                        except Exception: pass
                    out["differential_observation"]["profiles"].append(item)
            except Exception as de:
                out["differential_observation"]["error"]=str(de)[:500]
            context.close()
            browser.close()
    except Exception as exc:
        msg = str(exc)[:1200]
        out["error"] = msg
        low = msg.lower()
        if "err_tunnel_connection_failed" in low:
            out["decision"] = "hosting_access_restricted"
            out["failure_kind"] = "pythonanywhere_proxy_tunnel"
        elif "timeout" in low:
            out["decision"] = "browser_timeout"
            out["failure_kind"] = "browser_timeout"
        elif any(x in low for x in (
            "err_proxy_connection_failed", "err_connection_refused",
            "err_connection_reset", "err_name_not_resolved",
            "err_internet_disconnected"
        )):
            out["decision"] = "browser_network_error"
            out["failure_kind"] = "browser_network"
        else:
            out["decision"] = "browser_error"
            out["failure_kind"] = "browser_error"

    print(json.dumps(out, ensure_ascii=False))


# ═══════════════════════════════════════════════════════════════════════════
# FLASK ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Web-Defender-Version", APP_VERSION)
    return response

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

        analyzer = SecurityAnalyzer()
        # V32.3.1.1: feed_off may arrive in JSON (UI/API) or query/form values.
        feed_raw = data.get("feed_off", request.values.get("feed_off", "0"))
        analyzer.feed_off_v3231 = str(feed_raw).lower() in ("1", "true", "yes", "on")
        result = analyzer.analyze_url(url)

        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": f"Sunucu hatası: {exc}"}), 500



def legacy_feedback_helper():
    try:
        data=request.get_json(silent=True) or {}
        scan_id=(data.get("scan_id") or "").strip()
        verdict=(data.get("verdict") or "").strip().lower()
        if not scan_id: return jsonify({"error":"scan_id gerekli."}),400
        LEARNING_ENGINE.label_scan(scan_id, verdict)
        return jsonify({"ok":True,"stats":LEARNING_ENGINE.stats()})
    except ValueError as exc:
        return jsonify({"error":str(exc)}),400
    except Exception as exc:
        return jsonify({"error":f"Geri bildirim kaydedilemedi: {exc}"}),500

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

# V32.3.28.1: import sırasında DB/feed işi başlatma. Render readiness önce /healthz'yi
# cevaplayabilsin. Otomatik sync istenirse ayrı worker/cron veya API endpoint'i kullanılabilir.
# WEB_DEFENDER_EAGER_TI_SYNC=1 yalnızca bilinçli dedicated-worker kurulumları içindir.
if (os.getenv("WEB_DEFENDER_WORKER","0")=="1" and
        os.getenv("WEB_DEFENDER_EAGER_TI_SYNC","0").lower() in ("1","true","yes","on")):
    try: threading.Thread(target=_ti_loop,name="threat-intel-sync",daemon=True).start()
    except Exception: pass

if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--browser-worker":
        browser_worker_main(sys.argv[2], sys.argv[3] if len(sys.argv) >= 4 else "")
        raise SystemExit(0)

    print("=" * 65)
    print(f"🛡️  WEB DEFENDER {APP_VERSION}")
    print("    http://127.0.0.1:5000")
    print("=" * 65)
    print("Harici reputation API kullanmaz. Yerel analiz + doğrulanmış geri bildirimle öğrenir.")
    print("=" * 65)
    app.run(host="127.0.0.1", port=5000, debug=os.getenv("FLASK_DEBUG","0").lower() in ("1","true","yes","on"))