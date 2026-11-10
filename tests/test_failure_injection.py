"""E13-S7: every collector fails closed. "Could not look" never reads as "clean".

Each collector is run against a source whose every read, list, stat and
command raises. A collector may raise (the pipeline records it as degraded)
or record a degraded reason itself; returning nothing and saying nothing is
the failure this test exists to catch (it caught PamCollector doing that).
"""
import pytest

from tests import fixture_hosts as fh
from ubuntils.collectors import ALL_COLLECTORS
from ubuntils.pipeline import run_scan

ERRORS = [
    OSError(5, "Input/output error"),
    PermissionError(13, "Permission denied"),
    UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
    TimeoutError("timed out"),
    RuntimeError("unexpected"),
]


def _broken_source(root, err):
    base = fh.fixture_source(root)

    class Broken(type(base)):
        def _fail(self, *a, **k):
            raise err
        read_text = read_bytes = read_user_file = lstat = glob = readlink = exists = _fail
        sha256_file = run = _fail

    return Broken(root=str(root), offline=True)


@pytest.fixture(scope="module")
def lab_root(tmp_path_factory):
    return fh.build_host("lab", tmp_path_factory.mktemp("lab"))


@pytest.mark.parametrize("err", ERRORS, ids=lambda e: type(e).__name__)
@pytest.mark.parametrize("collector", ALL_COLLECTORS, ids=lambda c: c.__name__)
def test_each_collector_fails_closed(collector, err, lab_root):
    c = collector(source=_broken_source(lab_root, err))
    try:
        result = c.collect()
    except Exception:
        return  # the pipeline records a raising collector as degraded (tested below)
    produced = any(v for v in (result or {}).values() if not isinstance(v, bool))
    assert c.degraded or produced, (
        f"{collector.__name__} returned nothing and recorded no reason under {err!r}: "
        "a failed look would read as a clean host")


@pytest.mark.parametrize("err", ERRORS, ids=lambda e: type(e).__name__)
def test_a_scan_where_nothing_can_be_read_completes_and_says_so(err, lab_root, capsys):
    r = run_scan(_broken_source(lab_root, err), forward_wazuh=False)
    degraded = r.scan_metadata["collectors_degraded"]
    skipped = set(r.scan_metadata["command_collectors_skipped"])
    expected = {c.__name__ for c in ALL_COLLECTORS} - skipped
    assert expected <= set(degraded), f"not reported as degraded: {expected - set(degraded)}"
    assert r.scan_metadata["detection_error"] is None   # detection itself still ran
    assert "Traceback" not in capsys.readouterr().err
