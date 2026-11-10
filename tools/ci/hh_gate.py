#!/usr/bin/env python3
"""Fail CI unless every hostile-host trap run against ubuntils is PASS or SEEN.

    hh_gate.py RESULTS_DIR [--tool ubuntils] [--summary FILE]

RESULTS_DIR is the run directory the harness printed (it holds summary.json).
A broken baseline, a missing tool, or any other verdict (HANG, LEAK, MISSED,
BROKEN-RUN, …) fails. Exit 0 pass, 1 fail, 2 bad input.
"""
import argparse
import json
import os
import sys

GOOD = {"PASS", "SEEN"}


def judge(summary: dict, tool: str):
    problems = []
    base = summary.get("baselines", {}).get(tool)
    if base is None:
        problems.append(f"no baseline run for {tool}")
    elif str(base.get("outcome", "")).startswith("broken"):
        problems.append(f"baseline run broken: {base['outcome']}")
    rows = [r for r in summary.get("results", []) if r.get("tool") == tool]
    if not rows and not problems:
        problems.append(f"no trap results for {tool}")
    for r in rows:
        if r.get("verdict") not in GOOD:
            problems.append(f"{r.get('trap')} {r.get('title', '')}: {r.get('verdict')}")
    return rows, problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("results_dir")
    ap.add_argument("--tool", default="ubuntils")
    ap.add_argument("--summary")
    args = ap.parse_args(argv)
    try:
        summary = json.load(open(os.path.join(args.results_dir, "summary.json")))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rows, problems = judge(summary, args.tool)
    good = sum(r.get("verdict") in GOOD for r in rows)
    text = [f"Hostile-host: {good}/{len(rows)} traps PASS/SEEN for {args.tool}"]
    text += [f"- FAIL {p}" for p in problems]
    print("\n".join(text))
    if args.summary:
        with open(args.summary, "a") as fh:
            fh.write("\n".join(text) + "\n")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
