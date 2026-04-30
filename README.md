# ubuntils - Ubuntu Incident Response Forensics Tool

Fast, native Linux forensics for rapid Ubuntu system triage, persistence detection, and automated remediation.

![Build Status](https://img.shields.io/badge/status-development-yellow)
![Python](https://img.shields.io/badge/python-3.9+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What ubuntils Does

**ubuntils** automates incident response on compromised Ubuntu systems by:

1. **Collecting artifacts** — Running processes, network connections, logs, cron jobs, SSH keys, sudoers config
2. **Detecting persistence** — Identifies 8 types of persistence mechanisms (cron abuse, LD_PRELOAD injection, systemd timers, etc.)
3. **Building timelines** — Correlates events across logs into chronological incident narrative
4. **Remediating automatically** — Removes malicious artifacts with timestamped backups and rollback support

**Use case:** Post-breach triage on Ubuntu systems. Run ubuntils, get findings + auto-remediation options.

---

## Quick Start

### Installation

```bash
# Clone repo
git clone https://github.com/asmitdesai/ubuntils.git
cd ubuntils

# Install
pip install -e .
# OR from PyPI (once released)
pip install ubuntils
```

### Usage

```bash
# Scan system for findings
sudo ubuntils scan

# Show as JSON (for integration)
sudo ubuntils scan --output json

# Save report to file
sudo ubuntils scan --output /tmp/report.txt

# Preview what would be fixed
sudo ubuntils scan --remediate --dry-run

# Apply fixes (creates timestamped backups)
sudo ubuntils scan --remediate --confirm

# Rollback if something breaks
sudo ubuntils rollback /var/backups/ubuntils_20240615_142345/
```

---

## What It Detects

| Finding | Severity | Example | Auto-Fix |
|---------|----------|---------|----------|
| **Cron Root Execution** | HIGH | Non-root user cron running root commands | ✅ Remove |
| **Cron /tmp Paths** | HIGH | Cron points to /tmp or /var/tmp | ✅ Remove |
| **LD_PRELOAD Injection** | HIGH | LD_PRELOAD set in env or /etc/ld.so.preload | ✅ Unset |
| **Sudoers NOPASSWD** | MEDIUM | Unprivileged user has passwordless sudo | ✅ Remove |
| **Shell Init Hijacking** | MEDIUM | Suspicious commands in .bashrc/.zshrc | ✅ Clean |
| **SSH Key Injection** | HIGH | Unexpected authorized_keys entries | ✅ Remove |
| **Non-Standard Services** | MEDIUM | Systemd service from /tmp or /home | ⚠️ Flag only |
| **System File Mods** | MEDIUM | /etc/passwd modified recently | ⚠️ Flag only |

---

## Example Output

### Human-Readable Format
```
===== UBUNTU FORENSICS TRIAGE REPORT =====
Generated: 2024-06-15 14:23:45 UTC
Hostname: web-server-01
Kernel: 5.15.0-101-generic

----- SUSPICIOUS FINDINGS -----

[HIGH] Cron Job: root cron execution by ubuntu user
  Location: /var/spool/cron/crontabs/ubuntu
  Command: /tmp/check_disk.sh
  Interval: */5 * * * *
  Auto-Remediation: AVAILABLE
  Recommendation: Investigate /tmp/check_disk.sh immediately

[MEDIUM] Shell Initialization Hijacking
  File: /home/ubuntu/.bashrc
  Modified: 2024-06-10 09:15:22
  Contains: LD_PRELOAD=/tmp/libx.so
  Auto-Remediation: AVAILABLE
  Recommendation: Remove LD_PRELOAD line

[LOW] Sudoers NOPASSWD
  User: ubuntu
  Commands: /usr/bin/apt-get
  Auto-Remediation: AVAILABLE

----- TIMELINE (Last 48 Hours) -----
2024-06-15 14:00:00 | SSH Login: ubuntu from 203.0.113.45
2024-06-15 14:05:00 | Sudo: ubuntu ran /usr/bin/apt-get
2024-06-15 14:10:00 | File Modified: /home/ubuntu/.bashrc
2024-06-15 14:15:00 | Cron Job Added: /tmp/check_disk.sh

----- ARTIFACTS COLLECTED -----
Processes: 142
Network Connections: 24
Cron Jobs: 8
Systemd Timers: 5
Auth Events: 342
SSH Keys: 3
Sudoers Entries: 12
```

### JSON Format
```json
{
  "metadata": {
    "timestamp": "2024-06-15T14:23:45Z",
    "hostname": "web-server-01",
    "kernel": "5.15.0-101-generic"
  },
  "findings": [
    {
      "severity": "HIGH",
      "category": "cron_job",
      "description": "root cron execution by ubuntu user",
      "path": "/var/spool/cron/crontabs/ubuntu",
      "command": "/tmp/check_disk.sh",
      "remediation_available": true,
      "recommendation": "Investigate /tmp/check_disk.sh"
    }
  ],
  "timeline": [
    {
      "timestamp": "2024-06-15T14:00:00Z",
      "type": "ssh_login",
      "user": "ubuntu",
      "source": "203.0.113.45"
    }
  ]
}
```

---

## Remediation

ubuntils can automatically fix detected issues with **safety-first** approach:

### Dry-Run (Recommended First)
```bash
sudo ubuntils scan --remediate --dry-run
```
Shows what WOULD be fixed without making any changes.

### Apply Fixes
```bash
sudo ubuntils scan --remediate --confirm
```
- Creates timestamped backups before modifying files
- Applies fixes
- Logs all changes
- Shows rollback command if needed

### Rollback if Needed
```bash
sudo ubuntils rollback /var/backups/ubuntils_20240615_142345/
```
Restores original files from backup.

### Safeguards
- Always creates backups before modifying
- Validates sudoers with `visudo` before applying
- Never removes all sudo access (leaves at least one admin)
- Never force-deletes files (only disables/comments)

---

## Requirements

**OS:** Ubuntu 20.04 LTS, 22.04 LTS, 24.04 LTS (amd64)
**Python:** 3.9+
**Root/Sudo:** Required for full artifact collection and remediation

```
click>=8.1.0            # CLI framework
pyyaml>=6.0             # Config files
python-dateutil>=2.8    # Date/time parsing
tabulate>=0.9.0         # Pretty tables
loguru>=0.7.0           # Logging
```

---

## Getting Started

### 1. Installation
```bash
git clone https://github.com/asmitdesai/ubuntils.git
cd ubuntils
pip install -e .
```

### 2. First Scan (Detection Only)
```bash
sudo ubuntils scan
```

### 3. Review Findings
Look for HIGH severity findings first. Verify each before remediating.

### 4. Preview Remediation
```bash
sudo ubuntils scan --remediate --dry-run
```

### 5. Apply Fixes (If Confident)
```bash
sudo ubuntils scan --remediate --confirm
```

---

## Documentation

- **[Installation Guide](INSTALL.md)** — Ubuntu version-specific setup
- **[Development Guide](claude.md)** — Architecture and development context
- **[Contributing](CONTRIBUTING.md)** — How to contribute

---

## Testing

ubuntils is tested on:
- Ubuntu 20.04 LTS
- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS

Run tests locally:
```bash
pip install pytest pytest-cov
pytest tests/
pytest --cov=ubuntils tests/  # Coverage report
```

---

## Security Notes

**ubuntils requires sudo/root access because:**
- Reading /var/log/* files
- Reading /etc/cron.d/* and /etc/sudoers
- Reading process memory and file descriptors
- Modifying system files (during remediation)

**Safe to run on:**
- Production systems (detection-only mode, no remediation)
- Test/lab systems (with remediation)
- Your own systems (always)

**Not recommended on:**
- Shared multi-tenant systems
- Systems where you can't restart if something breaks

---

## Performance

Typical execution time on Ubuntu 20.04 system:

| Operation | Time |
|-----------|------|
| Artifact collection | ~2 seconds |
| Detection | ~1 second |
| Remediation (with backups) | ~2 seconds |
| **Total** | **~5 seconds** |

---

## Known Limitations

- **Detection only:** Set `--remediate --dry-run` first to verify findings
- **Backup cleanup:** Old backups in /var/backups/ubuntils/ are not auto-deleted
- **Multi-user systems:** May flag legitimate cron jobs from other admins
- **Custom logging:** Non-standard logging configs may not be detected

---

## Example Workflow

```bash
# Day 1: Incident detected on web-server-01
ssh ubuntu@web-server-01

# Scan for persistence
sudo ubuntils scan

# Findings show suspicious cron + SSH key
# Preview fixes
sudo ubuntils scan --remediate --dry-run

# Review output, confirm it's safe
# Apply fixes
sudo ubuntils scan --remediate --confirm

# Export findings to MISP/SIEM
sudo ubuntils scan --output json > /tmp/findings.json

# Send to security team for review
scp /tmp/findings.json security-team:/incidents/
```

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Bug reporting
- Feature requests
- Pull request process
- Development setup

---

## License

MIT License. See [LICENSE](LICENSE) file.

---

## Author

Built by Asmit - BTech CS, PES University

---

## Acknowledgments

- Inspiration: Incident response workflows in real-world SOC environments
- Detection rules: MITRE ATT&CK framework
- Testing: Ubuntu security best practices

---

## Support

Found a bug? File an [issue](https://github.com/asmitdesai/ubuntils/issues).
Have a question? Open a [discussion](https://github.com/asmitdesai/ubuntils/discussions).

---

## Roadmap

- [x] Phase 1: Artifact collection + detection
- [x] Phase 2: Remediation with backups
- [ ] Phase 3: macOS support
- [ ] Phase 4: Web dashboard
- [ ] Phase 5: MISP/Wazuh integration

---

**ubuntils: Automate Ubuntu incident response. Ship faster. Remediate smarter.**

---

*Latest Release:* v0.1.0-beta
*Status:* Active Development
