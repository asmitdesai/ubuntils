# Versioning, compatibility and deprecation

ubuntils follows [Semantic Versioning](https://semver.org). This page defines what
counts as its public interface (E13-S3).

## Public interface

A **major** release may change these; a **minor** release may only add to them;
a **patch** release changes none of them.

| Interface | Compatible (minor) | Breaking (major only) |
|---|---|---|
| CLI commands and flags | new commands, new flags, new values | removing or renaming a flag; changing a default |
| Exit statuses ([README](../README.md#exit-codes)) | new statuses for new opt-in behaviour | changing what an existing status means |
| JSON report (`schema_version`) | new fields, new enum values | removing or renaming a field; changing a field's type |
| Wazuh line (`schema_version`) | as the report | as the report |
| Bundle format (`format_version`) | new optional manifest fields readers may ignore | a layout older readers can't verify |
| Rule IDs | new rules | renaming or removing a rule (an alias is kept through the major) |
| Custom-rule YAML (`--rules`) | new sources, new match types | changing an existing key's meaning |
| Allowlist and baseline YAML | new optional keys | dropping a format version |

Not public: Python module paths and functions (`ubuntils.detectors.rules`…),
confidence scores and signal weights (they are tuned), finding wording, the TUI's
layout. Finding *titles* and *descriptions* are for people, not parsers.

## Schema versions are independent of the tool version

`schema_version` (report, Wazuh line) and `format_version` (bundle) are versioned
on their own (decision D-12). A minor schema bump only adds fields or enum values;
only a major may remove or rename anything. The report schema is `"3.0"` from
2.4 on: the 3.0 schema is additive over the unversioned 2.x reports, and it is
frozen at 3.0.0-beta.2, after which only additions are allowed until 4.0.
2.x reports have no `schema_version`.

## Deprecation

1. Anything that will break is announced at least **one minor release** before it
   changes: in the CHANGELOG's "Deprecated" section, in `--help` where it fits, and
   as a `deprecation:` line on stderr when the deprecated thing is actually used.
2. A renamed rule keeps answering to its old name (allowlists, baselines,
   `rule_aliases` in output) for the whole next major series.
3. Removal happens only in a major release, listed in the migration guide.

## Support window

- The latest minor of the current major gets fixes.
- After **3.0.0** ships, the last **2.x** release gets security fixes for **six
  months** (announced in 2.3.0).
- Python: 2.x supports 3.9+; 3.0 requires 3.10+ (announced in 2.3.0).
