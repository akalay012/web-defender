"""Standalone Web Defender discovery service.

This process is intentionally separate from Gunicorn. PostgreSQL is the queue boundary.
It ingests bounded discovery feeds and processes a bounded Feed-OFF candidate batch.
Candidate/prediction output never becomes verified ground truth automatically.
"""
import os
import time

def _int_env(name, default, lo, hi):
    try: value=int(os.getenv(name,str(default)) or default)
    except Exception: value=default
    return max(lo,min(hi,value))

def main():
    interval=_int_env("WEB_DEFENDER_DISCOVERY_INTERVAL_SECONDS",1800,300,21600)
    feed_limit=_int_env("WEB_DEFENDER_DISCOVERY_FEED_LIMIT",4,1,8)
    scan_limit=_int_env("WEB_DEFENDER_DISCOVERY_SCAN_LIMIT",2,1,4)
    startup=_int_env("WEB_DEFENDER_DISCOVERY_START_DELAY_SECONDS",10,0,120)
    print(f"[DISCOVERY-SERVICE] started | pid={os.getpid()} | interval={interval}s | feed_limit={feed_limit} | scan_limit={scan_limit}",flush=True)
    if not os.getenv("DATABASE_URL","").strip():
        print("[DISCOVERY-SERVICE][ERROR] DATABASE_URL is required for a separate worker; refusing local SQLite split-brain.",flush=True)
        raise SystemExit(2)
    time.sleep(startup)
    while True:
        started=time.monotonic()
        try:
            from .intelligence.sync import _trust_db_init
            _trust_db_init()
            from .engine import WebDefenderAnalyzer
            analyzer=WebDefenderAnalyzer()
            print("[DISCOVERY-SERVICE] cycle started",flush=True)
            ingestion=analyzer.run_autonomous_discovery_ingestion_v347(feed_limit)
            print(f"[DISCOVERY-SERVICE] ingestion finished | sources={len((ingestion or {}).get('sources') or [])}",flush=True)
            result=analyzer.process_discovery_queue_v344(scan_limit)
            print(f"[DISCOVERY-SERVICE] scan batch finished | scanned={int((result or {}).get('scanned') or 0)} | failed={int((result or {}).get('failed') or 0)}",flush=True)
        except Exception as exc:
            print(f"[DISCOVERY-SERVICE][ERROR] cycle failed | {type(exc).__name__}: {exc}",flush=True)
        elapsed=int(time.monotonic()-started)
        sleep_for=max(5,interval-elapsed)
        print(f"[DISCOVERY-SERVICE] sleeping | next_cycle_in={sleep_for}s",flush=True)
        time.sleep(sleep_for)

if __name__=="__main__":
    main()
