# PANIX benchmark (E11-S1)

Measures how many [PANIX](https://github.com/Aegrah/PANIX) persistence techniques
ubuntils flags at MEDIUM or HIGH. PANIX is independent of ubuntils' own rules,
which the lab and the hostile-host harness are not.

**Runs only on disposable GitHub Actions runners** (`.github/workflows/panix.yml`,
`workflow_dispatch` and weekly). Never on a real host.

- Each technique gets its own fresh runner VM: scan, plant with PANIX, scan again
  (`run_one.sh`). Nothing is reverted, because the VM is thrown away.
- Callbacks use TEST-NET-1 (`192.0.2.1`), which is never routed; listeners bind
  on the runner. PANIX itself is pinned (`PANIX_COMMIT`) and fetched by CI.
- Techniques that download from the internet or touch the bootloader are not
  planted (`EXCLUDED.md`).

## Result schema (`result.json`, one per technique)

| Field | Meaning |
|---|---|
| `technique`, `attack`, `panix_commit` | what was planted |
| `outcome` | `caught` (new MEDIUM/HIGH finding), `low only`, `missed`, `not planted`, `scan failed` |
| `best_severity` | highest severity among new non-inventory findings |
| `rule_ids`, `finding_ids` | the new findings |
| `collectors_degraded` | collectors that couldn't look during the after-scan |

`aggregate.py` writes `panix.md` and `panix.json`. The headline is
caught / applicable, where applicable excludes `not planted` and `scan failed`.
