#!/usr/bin/env python3
"""Check a clean-host scan report against the false-positive budget.

    check.py REPORT.json --baseline baseline/IMAGE.json [--write-baseline]

A clean reference host (a stock image with nothing planted) must show:
  - no HIGH finding, ever (fails);
  - no finding that isn't in the image's committed baseline (fails: a new
    false positive);
  - at most 3 findings in total (the 3.0 target; reported, and fails only
    with --enforce-target until the known noise is fixed).
Degraded collectors are listed: in a container some collectors can't run,
and the baseline records which, so a newly degraded one also fails.

The baseline is the reviewed list of known false positives, each with the
reason it is still there. --write-baseline records the current report (keep
the reasons you already wrote; new entries get "TODO").
"""
import argparse
import json
import sys

TARGET_MAX_TOTAL = 3


def _key(f):
    return (f["rule_id"], f["severity"], f["artifact_path"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("report")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--enforce-target", action="store_true",
                    help=f"also fail above {TARGET_MAX_TOTAL} findings in total")
    args = ap.parse_args(argv)

    report = json.load(open(args.report))
    findings = report["findings"]
    meta = report["scan_metadata"]
    degraded = sorted(meta.get("collectors_degraded") or {})

    if args.write_baseline:
        try:
            old = json.load(open(args.baseline))
        except FileNotFoundError:
            old = {"findings": []}
        reasons = {_key(e): e.get("reason", "TODO") for e in old.get("findings", [])}
        baseline = {
            "image": meta.get("ubuntu_version", ""),
            "tool_version": meta.get("tool_version", ""),
            "collectors_degraded": degraded,
            "findings": [dict(zip(("rule_id", "severity", "artifact_path"), k),
                              reason=reasons.get(k, "TODO"))
                         for k in sorted({_key(f) for f in findings})],
        }
        with open(args.baseline, "w") as fh:
            json.dump(baseline, fh, indent=2)
            fh.write("\n")
        print(f"wrote {args.baseline} ({len(baseline['findings'])} known findings)")
        return 0

    baseline = json.load(open(args.baseline))
    known = {_key(e) for e in baseline["findings"]}
    problems = []
    for f in findings:
        if f["severity"] == "HIGH":
            problems.append(f"HIGH on a clean host: {f['rule_id']} {f['artifact_path']}")
        elif _key(f) not in known:
            problems.append(f"new false positive: {f['rule_id']} {f['severity']} "
                            f"{f['artifact_path']}")
    for name in degraded:
        if name not in baseline.get("collectors_degraded", []):
            problems.append(f"collector newly degraded: {name}: "
                            f"{'; '.join(meta['collectors_degraded'][name])}")
    if meta.get("rules_failed"):
        problems.append(f"rules failed: {meta['rules_failed']}")

    total = len(findings)
    print(f"{meta.get('ubuntu_version', '?')}: {total} findings "
          f"({sum(f['severity'] == 'HIGH' for f in findings)} HIGH); "
          f"target <= {TARGET_MAX_TOTAL}: {'met' if total <= TARGET_MAX_TOTAL else 'NOT met'}")
    if args.enforce_target and total > TARGET_MAX_TOTAL:
        problems.append(f"{total} findings, target is <= {TARGET_MAX_TOTAL}")
    for p in problems:
        print(f"FAIL: {p}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
