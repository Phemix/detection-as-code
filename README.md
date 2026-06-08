# Detection-as-Code

SSC-style detection rule library with raw SPL queries, automated validation,
compilation, and CI/CD via GitHub Actions.

## Rule Schema

```yaml
title: Suspicious PowerShell Download
id: DET-00001                        # DET-NNNNN or UUID v4
type: detection                      # detection | hunting | correlation | baseline
status: experimental                 # experimental | test | stable | deprecated
description: >
  What this detects and why it matters.
author: Detection Engineering Team
date: 2024-01-15
modified: 2024-01-15
mitre:
  - T1059.001
data_source:
  - Sysmon EventID 1 (Process Creation)
analytic_story:
  - Malicious PowerShell
how_to_implement: >
  Required data sources and configuration steps.
schedule:
  cron: "*/5 * * * *"
  earliest_time: "-10m"
  latest_time: "now"
search: |
  index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
  your SPL here
  | table _time, Computer, User, Image, CommandLine
  | sort -_time
falsepositives:
  - Known FP scenario with remediation guidance
level: high                          # critical | high | medium | low | informational
```

## Quickstart

```bash
git clone <your-repo>
cd detection-as-code
python3 -m venv .venv
source .venv/bin/activate
make install
make install-hooks
make validate
make compile
```

## Commands

```
make install          Install dependencies (pyyaml, yamllint)
make install-hooks    Install git pre-commit hook
make validate         Validate all rules
make validate-strict  Validate — fail on warnings too
make validate-changed Validate unstaged changed rules only
make validate-staged  Validate staged rules only
make compile          Compile rules to Splunk SPL
make inventory        Generate RULES.md + rules_manifest.json
make lint             YAML lint all rule files
make new-rule         Interactive rule scaffolder (auto-increments DET-ID)
make clean            Remove compiled output
```

## Structure

```
rules/
  credential_access/
  execution/
  lateral_movement/
  persistence/
  defense_evasion/
  exfiltration/
  discovery/
  command_and_control/
scripts/
  validate.py     Schema + MITRE + search field enforcement
  compile.py      Wraps search block into deployable SPL
  inventory.py    Generates RULES.md + rules_manifest.json
  new_rule.py     Interactive scaffolder with auto-ID
  pre-commit      Git hook — run make install-hooks to activate
compiled/splunk/  Auto-generated (gitignored)
.github/workflows/
  validate.yml    CI: validate -> compile -> PR comment -> inventory
```

## CI Pipeline

Every PR touching `rules/**` triggers:
1. Validate — changed rules only
2. Compile — changed rules only
3. PR comment — table of changed rules with ID, title, type, level, MITRE
4. Inventory — on merge to main, regenerates RULES.md and rules_manifest.json
5. Full validate + compile — on merge to main as integrity check
