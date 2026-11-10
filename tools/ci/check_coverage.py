#!/usr/bin/env python3
"""Enforce line and branch coverage floors, overall and per module (E13-S9).

    check_coverage.py coverage.json [--floors tools/ci/coverage-floors.json]

coverage.json is pytest-cov's `--cov-report=json` (run with --cov-branch).
pytest's own --cov-fail-under only sees the combined number; this checks
line and branch separately, and holds security-critical modules to their
own floors. Exit 0 when every floor holds, 1 otherwise, 2 on bad input.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _pct(covered, total):
    return 100.0 if total == 0 else 100.0 * covered / total


def check(report: dict, floors: dict) -> list:
    problems = []
    t = report["totals"]
    got = {"line": _pct(t["covered_lines"], t["num_statements"]),
           "branch": _pct(t["covered_branches"], t["num_branches"])}
    for kind, floor in floors.get("overall", {}).items():
        if got[kind] + 1e-9 < floor:
            problems.append(f"overall {kind} {got[kind]:.2f}% < {floor}%")
    files = report["files"]
    for path, want in floors.get("modules", {}).items():
        if path not in files:
            problems.append(f"{path}: not in the coverage report")
            continue
        s = files[path]["summary"]
        mod = {"line": _pct(s["covered_lines"], s["num_statements"]),
               "branch": _pct(s["covered_branches"], s["num_branches"])}
        for kind, floor in want.items():
            if mod[kind] + 1e-9 < floor:
                problems.append(f"{path} {kind} {mod[kind]:.2f}% < {floor}%")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("report")
    ap.add_argument("--floors", default=os.path.join(HERE, "coverage-floors.json"))
    args = ap.parse_args(argv)
    try:
        report = json.load(open(args.report))
        floors = json.load(open(args.floors))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    problems = check(report, floors)
    for p in problems:
        print(f"FAIL {p}")
    if not problems:
        print("coverage floors hold")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
