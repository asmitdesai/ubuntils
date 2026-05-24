import pytest
from ubuntils.detectors.finding import Finding, RemediationResult, Severity, RemediationStatus
from ubuntils.collectors.base import BaseCollector
from ubuntils.remediators.base import BaseRemediator


# --- Task 8: Finding, RemediationResult, enums ---

def test_finding_creation():
    f = Finding(
        rule_id="CRON_TMP_PATH",
        severity=Severity.HIGH,
        title="Cron job in tmp",
        description="A cron job references /tmp",
        artifact_path="/etc/crontab",
        raw_value="* * * * * root /tmp/evil.sh",
        remediation_available=True,
        remediation_description="Remove the offending cron entry",
    )
    assert f.rule_id == "CRON_TMP_PATH"
    assert f.severity == Severity.HIGH
    assert f.title == "Cron job in tmp"
    assert f.artifact_path == "/etc/crontab"
    assert f.remediation_available is True
    assert f.remediation_description == "Remove the offending cron entry"


def test_finding_remediation_description_defaults_to_none():
    f = Finding(
        rule_id="SHELL_RC_MODIFICATION",
        severity=Severity.LOW,
        title="Shell RC modified",
        description="desc",
        artifact_path="/home/user/.bashrc",
        raw_value="export PATH=/tmp:$PATH",
        remediation_available=False,
    )
    assert f.remediation_description is None


def test_severity_enum_values():
    assert Severity.HIGH.value == "HIGH"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.LOW.value == "LOW"


def test_remediation_status_enum_values():
    assert RemediationStatus.SUCCESS.value == "SUCCESS"
    assert RemediationStatus.FAILED.value == "FAILED"
    assert RemediationStatus.SKIPPED.value == "SKIPPED"


def test_remediation_result_creation():
    r = RemediationResult(
        finding_rule_id="CRON_TMP_PATH",
        status=RemediationStatus.SUCCESS,
        message="Entry removed",
        backup_path="/var/backups/ubuntils/20240101_120000/crontab",
        rollback_command="cp /var/backups/ubuntils/20240101_120000/crontab /etc/crontab",
    )
    assert r.finding_rule_id == "CRON_TMP_PATH"
    assert r.status == RemediationStatus.SUCCESS
    assert r.backup_path is not None
    assert r.rollback_command is not None


def test_remediation_result_optional_fields_default_to_none():
    r = RemediationResult(
        finding_rule_id="CRON_TMP_PATH",
        status=RemediationStatus.SKIPPED,
        message="Dry run",
    )
    assert r.backup_path is None
    assert r.rollback_command is None


# --- Task 6: BaseCollector ---

def test_base_collector_cannot_instantiate():
    with pytest.raises(TypeError):
        BaseCollector()


def test_base_collector_subclass_without_collect_cannot_instantiate():
    class IncompleteCollector(BaseCollector):
        pass

    with pytest.raises(TypeError):
        IncompleteCollector()


def test_base_collector_subclass_valid():
    class GoodCollector(BaseCollector):
        def collect(self) -> dict:
            return {"key": "value"}

    c = GoodCollector()
    assert callable(c.collect)
    assert c.collect() == {"key": "value"}


# --- Task 7: BaseRemediator ---

def _make_finding():
    return Finding(
        rule_id="CRON_TMP_PATH",
        severity=Severity.HIGH,
        title="Cron in tmp",
        description="desc",
        artifact_path="/etc/crontab",
        raw_value="* * * * * root /tmp/evil.sh",
        remediation_available=True,
    )


def test_base_remediator_cannot_instantiate():
    with pytest.raises(TypeError):
        BaseRemediator()


def test_base_remediator_subclass_without_all_methods_cannot_instantiate():
    class IncompleteRemediator(BaseRemediator):
        def backup(self, finding): return "/backup"
        def validate(self, finding): pass
        def apply(self, finding, dry_run): return "applied"
        # missing verify

    with pytest.raises(TypeError):
        IncompleteRemediator()


def test_remediate_returns_failed_on_validate_error():
    class FailingRemediator(BaseRemediator):
        def backup(self, finding): return "/backup/path"
        def validate(self, finding): raise ValueError("unsafe to apply")
        def apply(self, finding, dry_run): return "applied"
        def verify(self, finding): pass

    r = FailingRemediator().remediate(_make_finding(), dry_run=False)
    assert r.status == RemediationStatus.FAILED
    assert "unsafe to apply" in r.message


def test_remediate_returns_failed_on_backup_error():
    class BackupFailRemediator(BaseRemediator):
        def backup(self, finding): raise OSError("disk full")
        def validate(self, finding): pass
        def apply(self, finding, dry_run): return "applied"
        def verify(self, finding): pass

    r = BackupFailRemediator().remediate(_make_finding(), dry_run=False)
    assert r.status == RemediationStatus.FAILED
    assert "disk full" in r.message


def test_remediate_returns_success_on_happy_path():
    class GoodRemediator(BaseRemediator):
        def backup(self, finding): return "/backup/path"
        def validate(self, finding): pass
        def apply(self, finding, dry_run): return "entry removed"
        def verify(self, finding): pass

    r = GoodRemediator().remediate(_make_finding(), dry_run=False)
    assert r.status == RemediationStatus.SUCCESS
    assert r.backup_path == "/backup/path"
    assert "entry removed" in r.message


def test_remediate_passes_dry_run_to_apply():
    received = {}

    class SpyRemediator(BaseRemediator):
        def backup(self, finding): return "/backup/path"
        def validate(self, finding): pass
        def apply(self, finding, dry_run):
            received["dry_run"] = dry_run
            return "ok"
        def verify(self, finding): pass

    SpyRemediator().remediate(_make_finding(), dry_run=True)
    assert received["dry_run"] is True
