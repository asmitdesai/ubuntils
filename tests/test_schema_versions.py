"""Version fields on every output format (ARCH-SV, docs/plans/v3.0.0-plan.md §2.2.9)."""
import io
import json
import os
import tarfile
from unittest.mock import patch

import pytest

from ubuntils.bundle import BundleError, read_bundle, write_bundle
from ubuntils.bundle.manifest import BUNDLE_FORMAT_VERSION, Manifest, CommandEntry, FileEntry
from ubuntils.collectors.source import LiveSource
from ubuntils.detectors.finding import Finding, Severity
from ubuntils.formatters.json_formatter import REPORT_SCHEMA_VERSION, JSONFormatter
from ubuntils.integrations.wazuh import (
    MAX_LINE_BYTES, WAZUH_SCHEMA_VERSION, degraded_line, finding_line,
)
from ubuntils.pipeline import run_scan


def _finding():
    return Finding(rule_id="CRON_TMP_PATH", severity=Severity.HIGH, title="t",
                   description="d", artifact_path="/etc/cron.d/x",
                   raw_value="* * * * * root /tmp/x", remediation_available=True)


def test_report_carries_schema_version_and_still_verifies():
    report = json.loads(JSONFormatter().format({}, {}, [_finding()], [], []))
    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    claimed = report.pop("report_sha256")
    assert JSONFormatter.digest(report) == claimed


def test_wazuh_lines_carry_schema_version_within_the_cap():
    for line in (finding_line(_finding(), "h"), degraded_line({"X": ["why"]}, "h")):
        assert json.loads(line)["schema_version"] == WAZUH_SCHEMA_VERSION
        assert len(line.encode()) <= MAX_LINE_BYTES


def _bundle(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    out = tmp_path / "b.tar.gz"
    write_bundle(source=LiveSource(root=str(root)), files_to_capture=["/etc/passwd"],
                 commands_to_capture=[], out_path=str(out),
                 metadata={"hostname": "h", "ubuntu_version": "U", "tool_version": "t"})
    return out


def _rewrite_manifest(bundle, out, change):
    """Rewrite manifest.json the way a given writer would have, digest included."""
    with tarfile.open(bundle) as src, tarfile.open(out, "w:gz") as dst:
        for member in src.getmembers():
            data = src.extractfile(member).read() if member.isfile() else None
            if member.name == "bundle/manifest.json":
                stored = json.loads(data)
                stored.pop("bundle_sha256")
                change(stored)
                m = Manifest(**{k: v for k, v in stored.items()
                                if k not in ("files", "commands")},
                             files=[FileEntry(**f) for f in stored["files"]],
                             commands=[CommandEntry(**c) for c in stored["commands"]])
                stored["bundle_sha256"] = m.manifest_sha256()
                data = json.dumps(stored).encode()
                member.size = len(data)
            dst.addfile(member, io.BytesIO(data) if data is not None else None)


def test_new_bundles_record_their_format_and_verify(tmp_path):
    source, info = read_bundle(str(_bundle(tmp_path)))
    source.cleanup()
    assert info["manifest"]["format_version"] == BUNDLE_FORMAT_VERSION
    assert info["bundle_integrity"] == "ok"


def test_2x_bundles_without_a_format_version_still_verify(tmp_path):
    old = tmp_path / "old.tar.gz"
    _rewrite_manifest(_bundle(tmp_path), old, lambda m: m.pop("format_version"))
    source, info = read_bundle(str(old))
    source.cleanup()
    assert "format_version" not in info["manifest"]
    assert info["bundle_integrity"] == "ok"


def test_unknown_bundle_format_is_refused(tmp_path):
    future = tmp_path / "future.tar.gz"
    _rewrite_manifest(_bundle(tmp_path), future, lambda m: m.update(format_version=99))
    with pytest.raises(BundleError, match="newer than this ubuntils"):
        read_bundle(str(future))


def test_scan_metadata_records_collector_durations():
    class _Quick:
        def __init__(self, source):
            self.degraded = []

        def collect(self):
            return {}

    with patch("ubuntils.pipeline.ALL_COLLECTORS", [_Quick]), \
            patch("ubuntils.pipeline.TimelineBuilder") as tl:
        tl.return_value.build.return_value = []
        r = run_scan(LiveSource(), forward_wazuh=False)
    durations = r.scan_metadata["collector_durations_s"]
    assert set(durations) == {"_Quick"}
    assert durations["_Quick"] >= 0
