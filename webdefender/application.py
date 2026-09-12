"""Web Defender application assembly."""
from .metadata import APP_NAME, APP_VERSION
import os, threading
from flask import Flask

from .state import LEARNING_ENGINE, THREAT_INTEL_STORE
from .intelligence.sync import _ti_loop

app=Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options","nosniff")
    response.headers.setdefault("X-Frame-Options","DENY")
    response.headers.setdefault("Referrer-Policy","strict-origin-when-cross-origin")
    response.headers.setdefault("Cache-Control","no-store")
    response.headers.setdefault("X-Web-Defender-Version",APP_VERSION)
    return response

def start_optional_workers():
    if (os.getenv("WEB_DEFENDER_WORKER","0")=="1" and
        os.getenv("WEB_DEFENDER_EAGER_TI_SYNC","0").lower() in ("1","true","yes","on")):
        try:
            threading.Thread(target=_ti_loop,name="threat-intel-sync",daemon=True).start()
        except Exception:
            pass
    if os.getenv("WEB_DEFENDER_DISCOVERY_WORKER","0").lower() in ("1","true","yes","on"):
        try:
            from .discovery_worker import start_discovery_worker
            start_discovery_worker()
        except Exception:
            pass
