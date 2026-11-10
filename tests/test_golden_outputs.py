"""E13-S4: frozen JSON reports for the fixture hosts.

An unexpected change to the report (a field renamed, a finding gained or lost,
a score moved) fails here. An intended change is re-blessed in the same
commit, with the reason in the commit message and the CHANGELOG:

    UBUNTILS_BLESS=1 pytest tests/test_golden_outputs.py
"""
import json
import os
import time

import pytest

from tests import fixture_hosts as fh
from ubuntils.formatters.json_formatter import JSONFormatter

GOLDEN = os.path.join(os.path.dirname(__file__), "golden")
NOW = 1_800_000_000.0  # fixed clock: recency rules give the same answer every run
VOLATILE_META = ("generated_at", "duration_s", "collector_durations_s", "tool_version")


def _report(host, tmp_path, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: NOW)
    root = fh.build_host(host, tmp_path / host, now=NOW)
    r = fh.scan(root)
    rep = json.loads(JSONFormatter().format(r.scan_metadata, r.artifact_counts, r.findings,
                                            r.timeline, r.remediation_results))
    for k in VOLATILE_META:
        rep["scan_metadata"].pop(k, None)
    rep.pop("report_sha256", None)
    return rep


@pytest.mark.parametrize("host", sorted(fh.HOSTS))
def test_report_matches_golden(host, tmp_path, monkeypatch):
    rep = _report(host, tmp_path, monkeypatch)
    path = os.path.join(GOLDEN, f"{host}.json")
    text = json.dumps(rep, indent=1, sort_keys=True) + "\n"
    if os.environ.get("UBUNTILS_BLESS") == "1":
        with open(path, "w") as fh_:
            fh_.write(text)
        pytest.skip(f"blessed {path}")
    with open(path) as fh_:
        expected = fh_.read()
    assert text == expected, (
        f"{host} report changed. If intended, re-bless (UBUNTILS_BLESS=1) and say why "
        "in the commit and the CHANGELOG.")
