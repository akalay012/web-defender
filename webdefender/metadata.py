"""Dependency-neutral application metadata."""
APP_NAME = "Web Defender"
APP_VERSION = "V34.0.5"

import os
RUNNING_ON_PYTHONANYWHERE = bool(os.getenv("PYTHONANYWHERE_SITE") or os.getenv("PYTHONANYWHERE_DOMAIN"))
