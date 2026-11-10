#!/usr/bin/env python3
"""Combine per-technique result.json files into the PANIX matrix.

    aggregate.py OUT.md OUT.json RESULT.json...

The headline is caught / applicable, where applicable = planted and scanned.
"""
import json
import sys


def aggregate(results):
    results = sorted(results, key=lambda r: r.get("technique") or "")
    applicable = [r for r in results if r["outcome"] in ("caught", "low only", "missed")]
    caught = [r for r in applicable if r["outcome"] == "caught"]
    return {"caught": len(caught), "applicable": len(applicable),
            "not_run": len(results) - len(applicable), "results": results}


def render(summary) -> str:
    lines = [f"PANIX: caught {summary['caught']} of {summary['applicable']} applicable techniques "
             f"at MEDIUM or HIGH ({summary['not_run']} not planted or not scanned)", "",
             "| Technique | ATT&CK | Outcome | Best severity | Rules |", "|---|---|---|---|---|"]
    for r in summary["results"]:
        lines.append(f"| {r['technique']} | {r['attack']} | {r['outcome']} | "
                     f"{r.get('best_severity') or '–'} | {', '.join(r.get('rule_ids') or []) or '–'} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    summary = aggregate([json.load(open(p)) for p in argv[2:]])
    open(argv[0], "w").write(render(summary))
    json.dump(summary, open(argv[1], "w"), indent=2)
    print(render(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
