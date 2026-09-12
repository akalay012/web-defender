"""Detached bounded discovery queue job.

The web worker launches this job and returns to its scheduler immediately. Each candidate
still has its own isolated process-tree timeout in AnalyzerOperationsMixin.
"""
import os
import sys

def main():
    limit=max(1,min(4,int(sys.argv[1] if len(sys.argv)>1 else "2")))
    os.environ["WEB_DEFENDER_DISCOVERY_JOB_CHILD"]="1"
    from .intelligence.sync import _trust_db_init
    _trust_db_init()
    from .engine import WebDefenderAnalyzer
    print(f"[DISCOVERY-JOB] Queue job started | limit={limit}",flush=True)
    try:
        result=WebDefenderAnalyzer().process_discovery_queue_v344(limit)
        print(f"[DISCOVERY-JOB] Queue job finished | scanned={int((result or {}).get('scanned') or 0)} | failed={int((result or {}).get('failed') or 0)}",flush=True)
    except Exception as exc:
        print(f"[DISCOVERY-JOB][ERROR] Queue job failed | {type(exc).__name__}: {exc}",flush=True)
        raise

if __name__=="__main__":
    main()
