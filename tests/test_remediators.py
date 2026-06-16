"""
Tests for Phase 7 remediators.

All tests operate on tmp file fixtures — no real /etc or /var paths touched.
dry_run=True tests verify the system state is unchanged.
dry_run=False tests verify the targeted entry is removed/commented out.
"""
import os
import stat
import textwrap
from unittest.mock import patch

import pytest

from ubuntils.detectors.finding import Finding, RemediationStatus, Severity
from ubuntils.remediators.cron import CronRemediator
from ubuntils.remediators.environment import EnvironmentRemediator
from ubuntils.remediators.ssh import SSHRemediator
from ubuntils.remediators.sudoers import SudoersRemediator
from ubuntils.remediators import REMEDIATOR_REGISTRY


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(rule_id, artifact_path, raw_value="bad line"):
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="Test finding",
        description="Test description",
        artifact_path=artifact_path,
        raw_value=raw_value,
        remediation_available=True,
    )


# ---------------------------------------------------------------------------
# CronRemediator
# ---------------------------------------------------------------------------

class TestCronRemediator:
    def test_dry_run_does_not_modify_file(self, tmp_path):
        cron_file = tmp_path / "malicious_cron"
        cron_file.write_text("* * * * * root /tmp/evil.sh\n* * * * * root /usr/bin/legit\n")
        finding = _finding("CRON_TMP_PATH", str(cron_file), "* * * * * root /tmp/evil.sh")

        remediator = CronRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=True)

        assert result.status == RemediationStatus.SUCCESS
        assert "dry" in result.message.lower()
        assert cron_file.read_text() == "* * * * * root /tmp/evil.sh\n* * * * * root /usr/bin/legit\n"

    def test_apply_removes_matching_line(self, tmp_path):
        cron_file = tmp_path / "malicious_cron"
        cron_file.write_text("* * * * * root /tmp/evil.sh\n* * * * * root /usr/bin/legit\n")
        finding = _finding("CRON_TMP_PATH", str(cron_file), "* * * * * root /tmp/evil.sh")

        remediator = CronRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)

        assert result.status == RemediationStatus.SUCCESS
        content = cron_file.read_text()
        assert "/tmp/evil.sh" not in content
        assert "/usr/bin/legit" in content

    def test_backup_created_before_change(self, tmp_path):
        cron_file = tmp_path / "cron_job"
        original = "* * * * * root /tmp/evil.sh\n"
        cron_file.write_text(original)
        finding = _finding("CRON_TMP_PATH", str(cron_file), "* * * * * root /tmp/evil.sh")

        remediator = CronRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)

        assert result.backup_path is not None
        assert os.path.exists(result.backup_path)
        assert open(result.backup_path).read() == original

    def test_missing_artifact_returns_failed(self, tmp_path):
        finding = _finding("CRON_TMP_PATH", str(tmp_path / "nonexistent"), "bad line")
        remediator = CronRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)
        assert result.status == RemediationStatus.FAILED

    def test_line_not_present_returns_failed(self, tmp_path):
        cron_file = tmp_path / "cron_clean"
        cron_file.write_text("* * * * * root /usr/bin/legit\n")
        finding = _finding("CRON_TMP_PATH", str(cron_file), "* * * * * root /tmp/evil.sh")

        remediator = CronRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)
        assert result.status == RemediationStatus.FAILED


# ---------------------------------------------------------------------------
# EnvironmentRemediator
# ---------------------------------------------------------------------------

class TestEnvironmentRemediator:
    def test_dry_run_does_not_modify_file(self, tmp_path):
        env_file = tmp_path / "environment"
        env_file.write_text("PATH=/usr/bin\nLD_PRELOAD=/tmp/evil.so\n")
        finding = _finding("LD_PRELOAD_INJECT", str(env_file), "LD_PRELOAD=/tmp/evil.so")

        remediator = EnvironmentRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=True)

        assert result.status == RemediationStatus.SUCCESS
        assert "dry" in result.message.lower()
        assert env_file.read_text() == "PATH=/usr/bin\nLD_PRELOAD=/tmp/evil.so\n"

    def test_apply_comments_out_ld_preload_line(self, tmp_path):
        env_file = tmp_path / "environment"
        env_file.write_text("PATH=/usr/bin\nLD_PRELOAD=/tmp/evil.so\n")
        finding = _finding("LD_PRELOAD_INJECT", str(env_file), "LD_PRELOAD=/tmp/evil.so")

        remediator = EnvironmentRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)

        assert result.status == RemediationStatus.SUCCESS
        content = env_file.read_text()
        assert "PATH=/usr/bin" in content
        assert "LD_PRELOAD=/tmp/evil.so" not in content or content.count("#") >= 1
        # The line must be commented out, not removed entirely
        assert "LD_PRELOAD" in content
        for line in content.splitlines():
            if "LD_PRELOAD" in line:
                assert line.strip().startswith("#")

    def test_backup_created(self, tmp_path):
        env_file = tmp_path / "environment"
        original = "LD_PRELOAD=/tmp/evil.so\n"
        env_file.write_text(original)
        finding = _finding("LD_PRELOAD_INJECT", str(env_file), "LD_PRELOAD=/tmp/evil.so")

        remediator = EnvironmentRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)

        assert result.backup_path is not None
        assert os.path.exists(result.backup_path)
        assert open(result.backup_path).read() == original

    def test_missing_file_returns_failed(self, tmp_path):
        finding = _finding("LD_PRELOAD_INJECT", str(tmp_path / "nonexistent"), "LD_PRELOAD=/tmp/evil.so")
        remediator = EnvironmentRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)
        assert result.status == RemediationStatus.FAILED

    def test_line_not_present_returns_failed(self, tmp_path):
        env_file = tmp_path / "environment"
        env_file.write_text("PATH=/usr/bin\n")
        finding = _finding("LD_PRELOAD_INJECT", str(env_file), "LD_PRELOAD=/tmp/evil.so")

        remediator = EnvironmentRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)
        assert result.status == RemediationStatus.FAILED


# ---------------------------------------------------------------------------
# SSHRemediator
# ---------------------------------------------------------------------------

class TestSSHRemediator:
    def test_dry_run_does_not_modify_file(self, tmp_path):
        auth_keys = tmp_path / "authorized_keys"
        auth_keys.write_text(
            "ssh-rsa AAAAB3N legit_key user@host\n"
            "ssh-rsa AAAAXXX evil_key attacker@evil\n"
        )
        finding = _finding(
            "SSH_UNAUTHORIZED_KEY",
            str(auth_keys),
            "ssh-rsa AAAAXXX evil_key attacker@evil",
        )

        remediator = SSHRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=True)

        assert result.status == RemediationStatus.SUCCESS
        assert "dry" in result.message.lower()
        assert "evil_key" in auth_keys.read_text()

    def test_apply_removes_matching_key_line(self, tmp_path):
        auth_keys = tmp_path / "authorized_keys"
        auth_keys.write_text(
            "ssh-rsa AAAAB3N legit_key user@host\n"
            "ssh-rsa AAAAXXX evil_key attacker@evil\n"
        )
        finding = _finding(
            "SSH_UNAUTHORIZED_KEY",
            str(auth_keys),
            "ssh-rsa AAAAXXX evil_key attacker@evil",
        )

        remediator = SSHRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)

        assert result.status == RemediationStatus.SUCCESS
        content = auth_keys.read_text()
        assert "evil_key" not in content
        assert "legit_key" in content

    def test_backup_created(self, tmp_path):
        auth_keys = tmp_path / "authorized_keys"
        original = "ssh-rsa AAAAXXX evil_key attacker@evil\n"
        auth_keys.write_text(original)
        finding = _finding(
            "SSH_UNAUTHORIZED_KEY",
            str(auth_keys),
            "ssh-rsa AAAAXXX evil_key attacker@evil",
        )

        remediator = SSHRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)

        assert result.backup_path is not None
        assert os.path.exists(result.backup_path)
        assert open(result.backup_path).read() == original

    def test_missing_file_returns_failed(self, tmp_path):
        finding = _finding("SSH_UNAUTHORIZED_KEY", str(tmp_path / "nonexistent"), "ssh-rsa bad")
        remediator = SSHRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)
        assert result.status == RemediationStatus.FAILED

    def test_key_not_present_returns_failed(self, tmp_path):
        auth_keys = tmp_path / "authorized_keys"
        auth_keys.write_text("ssh-rsa AAAAB3N legit_key user@host\n")
        finding = _finding(
            "SSH_UNAUTHORIZED_KEY",
            str(auth_keys),
            "ssh-rsa AAAAXXX evil_key attacker@evil",
        )
        remediator = SSHRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)
        assert result.status == RemediationStatus.FAILED


# ---------------------------------------------------------------------------
# SudoersRemediator
# ---------------------------------------------------------------------------

class TestSudoersRemediator:
    def test_dry_run_does_not_modify_file(self, tmp_path):
        sudoers_file = tmp_path / "sudoers"
        sudoers_file.write_text("root ALL=(ALL:ALL) ALL\nalice ALL=(ALL) NOPASSWD: ALL\n")
        finding = _finding(
            "SUDOERS_NOPASSWD",
            str(sudoers_file),
            "alice ALL=(ALL) NOPASSWD: ALL",
        )

        remediator = SudoersRemediator(backup_base=str(tmp_path / "backups"))
        with patch("ubuntils.remediators.sudoers.SudoersRemediator._run_visudo_check"):
            result = remediator.remediate(finding, dry_run=True)

        assert result.status == RemediationStatus.SUCCESS
        assert "dry" in result.message.lower()
        assert "NOPASSWD" in sudoers_file.read_text()

    def test_apply_removes_nopasswd_line(self, tmp_path):
        sudoers_file = tmp_path / "sudoers"
        sudoers_file.write_text("root ALL=(ALL:ALL) ALL\nalice ALL=(ALL) NOPASSWD: ALL\n")
        finding = _finding(
            "SUDOERS_NOPASSWD",
            str(sudoers_file),
            "alice ALL=(ALL) NOPASSWD: ALL",
        )

        remediator = SudoersRemediator(backup_base=str(tmp_path / "backups"))
        with patch("ubuntils.remediators.sudoers.SudoersRemediator._run_visudo_check"):
            result = remediator.remediate(finding, dry_run=False)

        assert result.status == RemediationStatus.SUCCESS
        content = sudoers_file.read_text()
        assert "NOPASSWD" not in content
        assert "root ALL=(ALL:ALL) ALL" in content

    def test_backup_created(self, tmp_path):
        sudoers_file = tmp_path / "sudoers"
        original = "root ALL=(ALL:ALL) ALL\nalice ALL=(ALL) NOPASSWD: ALL\n"
        sudoers_file.write_text(original)
        finding = _finding(
            "SUDOERS_NOPASSWD",
            str(sudoers_file),
            "alice ALL=(ALL) NOPASSWD: ALL",
        )

        remediator = SudoersRemediator(backup_base=str(tmp_path / "backups"))
        with patch("ubuntils.remediators.sudoers.SudoersRemediator._run_visudo_check"):
            result = remediator.remediate(finding, dry_run=False)

        assert result.backup_path is not None
        assert os.path.exists(result.backup_path)
        assert open(result.backup_path).read() == original

    def test_visudo_check_called_after_apply(self, tmp_path):
        sudoers_file = tmp_path / "sudoers"
        sudoers_file.write_text("root ALL=(ALL:ALL) ALL\nalice ALL=(ALL) NOPASSWD: ALL\n")
        finding = _finding(
            "SUDOERS_NOPASSWD",
            str(sudoers_file),
            "alice ALL=(ALL) NOPASSWD: ALL",
        )

        remediator = SudoersRemediator(backup_base=str(tmp_path / "backups"))
        with patch(
            "ubuntils.remediators.sudoers.SudoersRemediator._run_visudo_check"
        ) as mock_check:
            remediator.remediate(finding, dry_run=False)
            mock_check.assert_called_once()

    def test_missing_file_returns_failed(self, tmp_path):
        finding = _finding(
            "SUDOERS_NOPASSWD", str(tmp_path / "nonexistent"), "alice ALL=(ALL) NOPASSWD: ALL"
        )
        remediator = SudoersRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)
        assert result.status == RemediationStatus.FAILED

    def test_line_not_present_returns_failed(self, tmp_path):
        sudoers_file = tmp_path / "sudoers"
        sudoers_file.write_text("root ALL=(ALL:ALL) ALL\n")
        finding = _finding(
            "SUDOERS_NOPASSWD",
            str(sudoers_file),
            "alice ALL=(ALL) NOPASSWD: ALL",
        )
        remediator = SudoersRemediator(backup_base=str(tmp_path / "backups"))
        with patch("ubuntils.remediators.sudoers.SudoersRemediator._run_visudo_check"):
            result = remediator.remediate(finding, dry_run=False)
        assert result.status == RemediationStatus.FAILED

    def test_visudo_failure_returns_failed(self, tmp_path):
        sudoers_file = tmp_path / "sudoers"
        sudoers_file.write_text("root ALL=(ALL:ALL) ALL\nalice ALL=(ALL) NOPASSWD: ALL\n")
        finding = _finding(
            "SUDOERS_NOPASSWD",
            str(sudoers_file),
            "alice ALL=(ALL) NOPASSWD: ALL",
        )

        remediator = SudoersRemediator(backup_base=str(tmp_path / "backups"))
        with patch(
            "ubuntils.remediators.sudoers.SudoersRemediator._run_visudo_check",
            side_effect=ValueError("visudo check failed"),
        ):
            result = remediator.remediate(finding, dry_run=False)

        assert result.status == RemediationStatus.FAILED


# ---------------------------------------------------------------------------
# Security: symlink rejection and backup collision prevention
# ---------------------------------------------------------------------------

class TestSecurityHardenings:
    def test_symlink_rejected_before_remediation(self, tmp_path):
        """BaseRemediator.remediate() must refuse to act on a symlink artifact."""
        real_file = tmp_path / "real_authorized_keys"
        real_file.write_text("ssh-rsa AAAA...\n")
        link = tmp_path / "authorized_keys"
        link.symlink_to(real_file)

        finding = _finding("SSH_UNAUTHORIZED_KEY", str(link), "ssh-rsa AAAA...")
        remediator = SSHRemediator(backup_base=str(tmp_path / "backups"))
        result = remediator.remediate(finding, dry_run=False)

        assert result.status == RemediationStatus.FAILED
        assert "symlink" in result.message.lower()
        # Real file must be untouched
        assert real_file.read_text() == "ssh-rsa AAAA...\n"

    def test_symlink_swap_in_validate_apply_window_does_not_write_through(self, tmp_path):
        """TOCTOU: if the artifact is swapped to a symlink after validate() has
        already read the genuine file, apply() must NOT follow the link and
        truncate the (root-owned) target. Models an active attacker winning the
        race between the validate read and the apply write."""
        sensitive = tmp_path / "shadow"
        sensitive_content = "root:$6$realhash:19000:0:99999:7:::\n"
        sensitive.write_text(sensitive_content)

        artifact = tmp_path / "authorized_keys"
        artifact.write_text("ssh-rsa AAAA evil attacker@evil\n")

        finding = _finding(
            "SSH_UNAUTHORIZED_KEY", str(artifact), "ssh-rsa AAAA evil attacker@evil"
        )
        remediator = SSHRemediator(backup_base=str(tmp_path / "backups"))

        # Attacker wins the race precisely in the validate->apply window.
        orig_validate = remediator.validate

        def swap_then_validate(f):
            orig_validate(f)  # reads the genuine file and passes
            artifact.unlink()
            artifact.symlink_to(sensitive)  # redirect at the final component

        remediator.validate = swap_then_validate

        result = remediator.remediate(finding, dry_run=False)

        assert result.status == RemediationStatus.FAILED
        # The sensitive target must be byte-for-byte untouched.
        assert sensitive.read_text() == sensitive_content

    def test_backup_uses_flattened_full_path(self, tmp_path):
        """Backup filename must encode the full artifact path, not just the basename."""
        alice_keys = tmp_path / "alice" / "authorized_keys"
        alice_keys.parent.mkdir()
        alice_keys.write_text("ssh-rsa AAAA...\n")
        bob_keys = tmp_path / "bob" / "authorized_keys"
        bob_keys.parent.mkdir()
        bob_keys.write_text("ssh-rsa BBBB...\n")

        backup_base = tmp_path / "backups"
        remediator_a = SSHRemediator(backup_base=str(backup_base))
        remediator_b = SSHRemediator(backup_base=str(backup_base))

        finding_a = _finding("SSH_UNAUTHORIZED_KEY", str(alice_keys), "ssh-rsa AAAA...")
        finding_b = _finding("SSH_UNAUTHORIZED_KEY", str(bob_keys), "ssh-rsa BBBB...")

        backup_a = remediator_a.backup(finding_a)
        backup_b = remediator_b.backup(finding_b)

        assert backup_a != backup_b
        assert os.path.exists(backup_a)
        assert os.path.exists(backup_b)

    def test_backup_dir_created_with_restricted_permissions(self, tmp_path):
        """Backup directory must be created with mode 0o700."""
        artifact = tmp_path / "crontab"
        artifact.write_text("* * * * * root /tmp/evil.sh\n")

        backup_base = tmp_path / "backups"
        remediator = CronRemediator(backup_base=str(backup_base))
        finding = _finding("CRON_TMP_PATH", str(artifact), "* * * * * root /tmp/evil.sh")
        backup_path = remediator.backup(finding)

        backup_dir = os.path.dirname(backup_path)
        mode = stat.S_IMODE(os.stat(backup_dir).st_mode)
        assert mode == 0o700

    def test_backup_collision_raises_if_dest_exists(self, tmp_path):
        """backup() must raise FileExistsError rather than silently overwrite."""
        artifact = tmp_path / "authorized_keys"
        artifact.write_text("ssh-rsa AAAA...\n")

        backup_base = tmp_path / "backups"
        remediator = SSHRemediator(backup_base=str(backup_base))
        finding = _finding("SSH_UNAUTHORIZED_KEY", str(artifact), "ssh-rsa AAAA...")

        remediator.backup(finding)

        # Pre-create the destination that a second backup would target
        import glob
        backup_dirs = list((backup_base).iterdir())
        dest_dir = backup_dirs[0]
        safe_name = str(artifact).lstrip("/").replace("/", "_")
        dest = dest_dir / safe_name
        assert dest.exists()

        # Second backup to the same dest_dir should fail
        dest.unlink()
        dest.write_text("already here")
        remediator2 = SSHRemediator(backup_base=str(backup_base))
        with pytest.raises(FileExistsError):
            remediator2.backup(finding)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestRemediatorRegistry:
    def test_registry_contains_all_four_rule_ids(self):
        assert "CRON_TMP_PATH" in REMEDIATOR_REGISTRY
        assert "CRON_ROOT_EXEC" in REMEDIATOR_REGISTRY
        assert "LD_PRELOAD_INJECT" in REMEDIATOR_REGISTRY
        assert "SSH_UNAUTHORIZED_KEY" in REMEDIATOR_REGISTRY
        assert "SUDOERS_NOPASSWD" in REMEDIATOR_REGISTRY

    def test_registry_values_are_remediator_instances(self):
        from ubuntils.remediators.base import BaseRemediator
        for key, val in REMEDIATOR_REGISTRY.items():
            assert isinstance(val, BaseRemediator), f"{key} is not a BaseRemediator"
