"""Isolated runner for one autonomous discovery scan.

The parent discovery worker enforces the hard wall-clock deadline. This module
never submits forms or changes the analyzer's existing safety policy.
"""
import json
import sys

def main():
    if len(sys.argv) != 3:
        raise SystemExit(2)
    url=sys.argv[1]
    output_path=sys.argv[2]
    from .engine import WebDefenderAnalyzer
    analyzer=WebDefenderAnalyzer(url, feed_off=True)
    result=analyzer.analyze_url(url)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, default=str)

if __name__ == "__main__":
    main()
