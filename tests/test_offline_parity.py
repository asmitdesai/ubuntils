"""E5-S2 / R-02: `analyze BUNDLE` must find what `scan` finds.

For each fixture host: scan it directly, then collect a bundle from it (the
real writer and reader) and analyze that. The finding sets, keyed by
finding_id, must match, except rules that can only work live, which must be
labelled as such. Today `collect` captures a fixed list of 22 files and 10
commands, so most findings are missing offline (review R-02); this is strict
xfail until collect records the collectors' own read set (alpha.2, §2.3.2).
"""
import pytest

from tests import fixture_hosts as fh
from ubuntils import cli
from ubuntils.bundle import read_bundle
from ubuntils.bundle.writer import write_bundle
from ubuntils.pipeline import run_scan

# Rules that need a live kernel or running processes; their absence offline is
# expected, and must be reported as live-only (not silently missing).
LIVE_ONLY_RULES = {"PROCESS_MASQUERADE", "PROCESS_SUSPICIOUS_CONNECTION",
                   "PROCESS_SUSPICIOUS_EXE"}


def _ids(findings):
    return {f.finding_id for f in findings if f.rule_id not in LIVE_ONLY_RULES}


@pytest.mark.xfail(strict=True, reason="R-02 → E5-S1 collect derived from read sets (alpha.2)")
@pytest.mark.parametrize("host", sorted(fh.HOSTS))
def test_scan_and_analyze_bundle_find_the_same_things(host, tmp_path):
    root = fh.build_host(host, tmp_path / "h")
    live = fh.scan(root).findings
    out = write_bundle(source=fh.fixture_source(root), files_to_capture=cli.COLLECT_FILES,
                       commands_to_capture=cli.COLLECT_COMMANDS,
                       out_path=str(tmp_path / "b.tar.gz"), metadata={"hostname": host})
    source, info = read_bundle(out)
    try:
        offline = run_scan(source, bundle_info=info, forward_wazuh=False).findings
    finally:
        source.cleanup()
    missing = sorted(f"{f.rule_id} {f.artifact_path}" for f in live
                     if f.finding_id in _ids(live) - _ids(offline))
    assert not missing, f"found live, missed offline: {missing}"
