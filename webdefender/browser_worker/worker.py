"""Isolated browser-worker entrypoint during modular migration."""
import sys
from webdefender.engine import browser_worker_main
if __name__ == "__main__" and len(sys.argv) >= 2:
    browser_worker_main(sys.argv[1], sys.argv[2] if len(sys.argv) >= 3 else "")
