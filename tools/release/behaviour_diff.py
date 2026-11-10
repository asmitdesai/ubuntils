#!/usr/bin/env python3
"""Compare the JSON two ubuntils versions produce on the fixture hosts.

    behaviour_diff.py OLD_SRC NEW_SRC OUTDIR

OLD_SRC and NEW_SRC are source trees (e.g. a `git worktree` of the v2.3.0 tag
and this checkout). Each version scans tests/fixture_hosts.py hosts offline,
with a fixed clock and Wazuh off; volatile fields are dropped. Writes one
report per host and version, then a unified diff of each pair, and checks that
a bundle written by NEW_SRC still verifies under OLD_SRC.
"""
import difflib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.abspath(os.path.join(HERE, "..", "..", "tests"))
NEUTRAL_CWD = tempfile.mkdtemp(prefix="ubuntils-diff-")

SCAN = r'''
import json, sys, tempfile, time
sys.path.insert(0, sys.argv[3])
import fixture_hosts as fh
from ubuntils.pipeline import run_scan
from ubuntils.formatters.json_formatter import JSONFormatter
NOW = 1_800_000_000.0
time.time = lambda: NOW
with tempfile.TemporaryDirectory() as d:
    r = run_scan(fh.fixture_source(fh.build_host(sys.argv[1], d, now=NOW)), forward_wazuh=False)
    rep = json.loads(JSONFormatter().format(r.scan_metadata, r.artifact_counts, r.findings,
                                            r.timeline, r.remediation_results))
for k in ("generated_at", "duration_s", "collector_durations_s"):
    rep["scan_metadata"].pop(k, None)
rep.pop("report_sha256", None)
json.dump(rep, open(sys.argv[2], "w"), indent=1, sort_keys=True)
'''

BUNDLE = r'''
import os, sys, tempfile
sys.path.insert(0, sys.argv[1])
import fixture_hosts as fh
from ubuntils.bundle.writer import write_bundle
from ubuntils import cli
d = tempfile.mkdtemp()
out = os.path.join(d, "b.tar.gz")
write_bundle(source=fh.fixture_source(fh.build_host("lab", os.path.join(d, "h"))),
             files_to_capture=cli.COLLECT_FILES, commands_to_capture=[], out_path=out,
             metadata={"hostname": "fixture", "ubuntu_version": "24.04", "tool_version": "x"})
print(out)
'''

READ = ("import sys; from ubuntils.bundle import read_bundle; s, i = read_bundle(sys.argv[1]);"
        "print(i['bundle_integrity']); s.cleanup()")


def _py(src, *args):
    # cwd matters: `python -c` puts it first on sys.path, so running from a
    # checkout would import that checkout's ubuntils for both versions.
    r = subprocess.run([sys.executable, *args], env={**os.environ, "PYTHONPATH": src},
                       capture_output=True, text=True, cwd=NEUTRAL_CWD)
    if r.returncode:
        raise SystemExit(f"{src}: {r.stderr.strip()}")
    return r.stdout.strip()


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    old, new, outdir = (os.path.abspath(a) for a in argv)
    os.makedirs(outdir, exist_ok=True)
    for host in ("clean", "lab"):
        paths = []
        for label, src in (("old", old), ("new", new)):
            p = os.path.join(outdir, f"{host}-{label}.json")
            _py(src, "-c", SCAN, host, p, TESTS)
            paths.append(p)
        diff = list(difflib.unified_diff(open(paths[0]).readlines(), open(paths[1]).readlines(),
                                         paths[0], paths[1]))
        open(os.path.join(outdir, f"{host}.diff"), "w").writelines(diff)
        removed = [l for l in diff if l.startswith("-") and not l.startswith("---")]
        print(f"{host}: {len(diff)} diff lines, {len(removed)} removed or changed")
    bundle = _py(new, "-c", BUNDLE, TESTS)
    print(f"bundle from NEW, verified by OLD: {_py(old, '-c', READ, bundle)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
