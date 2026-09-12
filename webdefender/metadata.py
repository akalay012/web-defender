"""Dependency-neutral application metadata."""
APP_NAME = "Web Defender"
APP_VERSION = "V34.3.0"

import os
RUNNING_ON_PYTHONANYWHERE = bool(os.getenv("PYTHONANYWHERE_SITE") or os.getenv("PYTHONANYWHERE_DOMAIN"))

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 WebDefender/34"
)
