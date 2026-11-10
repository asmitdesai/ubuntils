#!/usr/bin/env python3
"""Summarise scan timings and peak memory from repeated runs.

    timings.py OUT.json RUN_DIR... [--budget-s S] [--budget-rss-mb M]

Each RUN_DIR holds report.json (a `scan --json` report) and time.txt (the
output of GNU `/usr/bin/time -v`). Writes the median duration, the median of
every collector's duration, and the peak RSS. With a budget, exits 1 when the
median duration or the peak RSS exceeds it (E13-S6).
"""
import argparse
import json
import os
import re
import statistics
import sys

_RSS = re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)")


def summarise(run_dirs):
    durations, rss_kb, per_collector = [], [], {}
    for d in run_dirs:
        meta = json.load(open(os.path.join(d, "report.json")))["scan_metadata"]
        durations.append(float(meta["duration_s"]))
        for name, secs in (meta.get("collector_durations_s") or {}).items():
            per_collector.setdefault(name, []).append(float(secs))
        m = _RSS.search(open(os.path.join(d, "time.txt")).read())
        if m:
            rss_kb.append(int(m.group(1)))
    return {
        "runs": len(run_dirs),
        "median_duration_s": round(statistics.median(durations), 3),
        "collector_median_s": {k: round(statistics.median(v), 3)
                               for k, v in sorted(per_collector.items())},
        "peak_rss_mb": round(max(rss_kb) / 1024, 1) if rss_kb else None,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("out")
    ap.add_argument("run_dirs", nargs="+")
    ap.add_argument("--budget-s", type=float)
    ap.add_argument("--budget-rss-mb", type=float)
    args = ap.parse_args(argv)
    try:
        result = summarise(args.run_dirs)
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    with open(args.out, "w") as fh:
        json.dump(result, fh, indent=2)
    print(json.dumps(result, indent=2))
    over = []
    if args.budget_s is not None and result["median_duration_s"] > args.budget_s:
        over.append(f"median {result['median_duration_s']} s > budget {args.budget_s} s")
    if args.budget_rss_mb is not None and (result["peak_rss_mb"] or 0) > args.budget_rss_mb:
        over.append(f"peak RSS {result['peak_rss_mb']} MB > budget {args.budget_rss_mb} MB")
    for o in over:
        print(f"::error::{o}")
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
