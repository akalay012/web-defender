"""Deprecated import-compatibility shell.

No detection, scoring, routing, worker or presentation logic lives here.
"""
from .application import app, APP_NAME, APP_VERSION
from .engine import SecurityAnalyzer, WebDefenderAnalyzer, analyze_target
from .browser_worker.runtime import browser_worker_main
from .routes.template import HTML_TEMPLATE

__all__=[
    "app","APP_NAME","APP_VERSION","SecurityAnalyzer","WebDefenderAnalyzer",
    "analyze_target","browser_worker_main","HTML_TEMPLATE",
]
