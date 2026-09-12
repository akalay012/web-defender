"""Isolated browser-worker process entrypoint.

Implementation is delegated during the controlled migration. The public
entrypoint is semantic and stable.
"""
import sys

def run_browser_observer(url: str, output_path: str = ""):
    from webdefender.engine import browser_worker_main
    return browser_worker_main(url, output_path)

if __name__ == "__main__" and len(sys.argv) >= 2:
    run_browser_observer(sys.argv[1], sys.argv[2] if len(sys.argv) >= 3 else "")
