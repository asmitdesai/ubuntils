#!/usr/bin/env python3
"""Judge one PANIX run: what did the scan after planting add?

    compare.py OUTDIR      (holds before.json, after.json, meta.json)

A technique is *caught* when the after-scan has a MEDIUM or HIGH finding the
before-scan did not; *low only* when the only new findings are LOW (or
inventory); *missed* when nothing new appears; *not planted* when PANIX exited
non-zero; *scan failed* when a report is missing or detection failed. Writes
OUTDIR/result.json following the schema in README.md.
"""
import json
import os
import sys

RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _key(f):
    return (f.get("rule_id"), f.get("artifact_path"), f.get("raw_value"))


def _load(path):
    try:
        return json.load(open(path))
    except (OSError, ValueError):
        return None


def judge(before, after, meta):
    result = {k: meta.get(k) for k in ("technique", "attack", "panix_commit")}
    result.update({"outcome": None, "best_severity": None, "rule_ids": [], "finding_ids": []})
    if meta.get("plant_rc") not in (0, None):
        result["outcome"] = "not planted"
        return result
    if before is None or after is None or after["scan_metadata"].get("detection_error"):
        result["outcome"] = "scan failed"
        return result
    seen = {_key(f) for f in before["findings"]}
    new = [f for f in after["findings"] if _key(f) not in seen]
    scored = [f for f in new if f.get("category") != "inventory"]
    best = max((RANK.get(f.get("severity"), 0) for f in scored), default=0)
    result["best_severity"] = next((k for k, v in RANK.items() if v == best), None)
    result["rule_ids"] = sorted({f["rule_id"] for f in new})
    result["finding_ids"] = sorted({f["finding_id"] for f in new if f.get("finding_id")})
    result["outcome"] = ("caught" if best >= RANK["MEDIUM"] else
                         "low only" if new else "missed")
    result["collectors_degraded"] = sorted(after["scan_metadata"].get("collectors_degraded") or {})
    return result


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    d = argv[0]
    meta = _load(os.path.join(d, "meta.json")) or {}
    result = judge(_load(os.path.join(d, "before.json")), _load(os.path.join(d, "after.json")), meta)
    with open(os.path.join(d, "result.json"), "w") as fh:
        json.dump(result, fh, indent=2)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
