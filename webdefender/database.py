"""Database compatibility layer.

Owns SQLite/PostgreSQL connection compatibility. No threat scoring lives here.
"""
import os, re, sqlite3

DATABASE_URL=os.getenv("DATABASE_URL","").strip()

def db_backend_name():
    return "postgresql" if DATABASE_URL else "sqlite"


def db_persistence_status():
    """Describe persistence semantics without treating availability as threat evidence."""
    backend=db_backend_name()
    return {
        "backend":backend,
        "durable_expected":backend=="postgresql",
        "configured":bool(DATABASE_URL) if backend=="postgresql" else True,
        "note":"PostgreSQL is the durable production backend; SQLite is local/fallback storage."
    }

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
