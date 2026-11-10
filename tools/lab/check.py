#!/usr/bin/env python3
"""Check a lab scan against what seed-lab.sh says it planted.

    check.py PLANT_LOG REPORT.json [--summary FILE]

PLANT_LOG is the stdout of `seed-lab.sh plant`. Every line it prints under
"Planting" names the rule an artifact should trip; lines listed under "Not
planted on this host" are skipped artifacts, not misses. Each planted artifact
counts as flagged only if a finding with that rule *and* the artifact's own
marker exists, so one finding can't satisfy two artifacts of the same rule.

Exit status: 0 when every planted artifact is flagged, 1 otherwise, 2 on bad input.
"""
import argparse
import json
import re
import sys

# rule, a regex over the plant line, and a regex a matching finding must
# contain (in artifact_path, raw_value or description).
ARTIFACTS = [
    ("USER_UID_ZERO", r"UID-0 alias", r"ubuntils-lab-root"),
    ("USER_EMPTY_PASSWORD", r"NO PASSWORD", r"ubuntils-lab-nopw"),
    ("CRON_TMP_PATH", r"/etc/cron\.d/", r"/etc/cron\.d/ubuntils-lab"),
    ("CRON_SUSPICIOUS_COMMAND", r"revshell", r"/etc/cron\.d/ubuntils-lab-revshell"),
    ("CRON_ROOT_EXEC", r"crontab for", r"ubuntils-lab"),
    ("SUDOERS_NOPASSWD", r"/etc/sudoers\.d/", r"/etc/sudoers\.d/ubuntils-lab"),
    ("SSH_UNAUTHORIZED_KEY", r"command= option", r"/\.ssh/authorized_keys(?!2)"),
    ("SSH_UNAUTHORIZED_KEY", r"authorized_keys2", r"authorized_keys2"),
    ("SHELL_RC_MODIFICATION", r"download-and-execute", r"\.bashrc"),
    ("LD_PRELOAD_INJECT", r"LD_PRELOAD", r"\.bashrc"),
    ("SUSPICIOUS_SYSTEMD_TIMER", r"updater\.service runs from /tmp", r"ubuntils-lab-updater\.service(?!\.d)"),
    ("SUSPICIOUS_SYSTEMD_TIMER", r"drop-in override", r"\.service\.d/"),
    ("PAM_BACKDOOR", r"/etc/pam\.d/", r"/etc/pam\.d/ubuntils-lab"),
    ("PROCESS_MASQUERADE", r"'kworker'", r"kworker"),
    ("PROCESS_MASQUERADE", r"'sshd'", r"'sshd'"),
    ("PROCESS_SUSPICIOUS_EXE", r"'cache-sync'", r"/var/tmp/cache-sync"),
    ("SETUID_INVENTORY", r"setuid-bit script", r"/opt/ubuntils-lab/beacon"),
    ("IMMUTABLE_FLAG_SET", r"append-only flag", r"/var/log/btmp"),
    ("PACKAGE_TAMPERED", r"appended to", r"base-files"),
    ("KERNEL_MODULE_SUSPICIOUS", r"'dummy'", r"'dummy'"),
]

# The old rule ID and its 2.4 alias are the same rule (QW-13).
ALIASES = {"SUSPICIOUS_SYSTEMD_TIMER": {"SUSPICIOUS_SYSTEMD_TIMER", "SUSPICIOUS_SYSTEMD_UNIT"}}

_LINE = re.compile(r"^  ([A-Z_]+)\s+(.*)$")


def parse_plant_log(text: str):
    """(planted, skipped): lists of (rule, detail) lines from `plant` output."""
    planted, skipped, section = [], [], None
    for line in text.splitlines():
        if line.startswith("Planting"):
            section = "planted"
            continue
        if line.startswith("Not planted on this host"):
            section = "skipped"
            continue
        if line.startswith("Done."):
            section = None
            continue
        m = _LINE.match(line)
        if m and section:
            (planted if section == "planted" else skipped).append((m.group(1), m.group(2)))
    return planted, skipped


def _artifact_for(rule: str, detail: str):
    for a_rule, pattern, marker in ARTIFACTS:
        if a_rule == rule and re.search(pattern, detail):
            return marker
    return None


def evaluate(planted, skipped, findings):
    skipped_rules = {rule for rule, _ in skipped}
    rows, used = [], set()
    for rule, detail in planted:
        if rule in skipped_rules:
            continue
        marker = _artifact_for(rule, detail)
        ids = ALIASES.get(rule, {rule})
        hit = None
        if marker is not None:
            for i, f in enumerate(findings):
                if i in used or f.get("rule_id") not in ids:
                    continue
                if any(re.search(marker, str(f.get(k, "")))
                       for k in ("artifact_path", "raw_value", "description")):
                    hit = f
                    used.add(i)
                    break
        rows.append({"rule": rule, "artifact": detail, "known_artifact": marker is not None,
                     "flagged": hit is not None,
                     "severity": hit.get("severity") if hit else None})
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("plant_log")
    ap.add_argument("report")
    ap.add_argument("--summary", help="also write a Markdown table here")
    args = ap.parse_args(argv)
    try:
        planted, skipped = parse_plant_log(open(args.plant_log).read())
        findings = json.load(open(args.report))["findings"]
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not planted:
        print("error: no planted artifacts found in the plant log", file=sys.stderr)
        return 2
    rows = evaluate(planted, skipped, findings)
    flagged = sum(r["flagged"] for r in rows)
    lines = [f"Lab: {flagged}/{len(rows)} planted artifacts flagged"
             + (f" ({len(skipped)} not planted on this host)" if skipped else ""), "",
             "| Rule | Artifact | Result |", "|---|---|---|"]
    for r in rows:
        result = (f"flagged ({r['severity']})" if r["flagged"] else
                  "MISSED" if r["known_artifact"] else "MISSED (no checker entry)")
        lines.append(f"| {r['rule']} | {r['artifact']} | {result} |")
    for rule, detail in skipped:
        lines.append(f"| {rule} | {detail} | not planted |")
    text = "\n".join(lines)
    print(text)
    if args.summary:
        with open(args.summary, "a") as fh:
            fh.write(text + "\n")
    return 0 if flagged == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
