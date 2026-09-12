"""Bounded autonomous discovery worker.

The worker is opt-in. It never verifies ground truth and never promotes learned weights.
"""
import os
import time
import threading

_LOCK=threading.Lock()
_STARTED=False

def _enabled():
    return os.getenv("WEB_DEFENDER_DISCOVERY_WORKER","0").lower() in ("1","true","yes","on")

def _loop():
    interval=max(300,min(21600,int(os.getenv("WEB_DEFENDER_DISCOVERY_INTERVAL_SECONDS","1800") or 1800)))
    feed_limit=max(1,min(8,int(os.getenv("WEB_DEFENDER_DISCOVERY_FEED_LIMIT","4") or 4)))
    scan_limit=max(1,min(4,int(os.getenv("WEB_DEFENDER_DISCOVERY_SCAN_LIMIT","2") or 2)))
    # Avoid doing network/browser work during Gunicorn import/boot.
    delay=max(20,min(300,int(os.getenv("WEB_DEFENDER_DISCOVERY_START_DELAY_SECONDS","45") or 45)))
    print(f"[DISCOVERY] Worker started | delay={delay}s | interval={interval}s | feed_limit={feed_limit} | scan_limit={scan_limit}", flush=True)
    time.sleep(delay)
    while True:
        try:
            print("[DISCOVERY] Autonomous cycle started", flush=True)
            from .engine import WebDefenderAnalyzer
            WebDefenderAnalyzer().run_autonomous_discovery_iteration_v346(feed_limit,scan_limit)
        except Exception as exc:
            # Never crash the web worker because an optional discovery iteration failed,
            # but never hide the failure from operators either.
            print(f"[DISCOVERY][ERROR] Autonomous cycle failed | {type(exc).__name__}: {exc}", flush=True)
        print(f"[DISCOVERY] Sleeping | next_cycle_in={interval}s", flush=True)
        time.sleep(interval)

def start_discovery_worker():
    global _STARTED
    if not _enabled(): return False
    with _LOCK:
        if _STARTED: return True
        threading.Thread(target=_loop,name="webdefender-discovery",daemon=True).start()
        _STARTED=True
    return True
