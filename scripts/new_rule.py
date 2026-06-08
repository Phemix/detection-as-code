#!/usr/bin/env python3
"""
new_rule.py — Interactive detection rule scaffolder (SSC-style schema)
Run via: make new-rule  OR  python scripts/new_rule.py
"""

import datetime
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent

TACTICS = [
    "credential_access", "execution", "lateral_movement",
    "persistence", "defense_evasion", "exfiltration",
    "discovery", "command_and_control"
]

LEVELS = ["critical", "high", "medium", "low"]
TYPES = ["detection", "hunting", "correlation", "baseline"]


def prompt(label, default=None):
    suffix = f" [{default}]" if default else ""
    val = input(f"  {label}{suffix}: ").strip()
    return val if val else default


def next_id() -> str:
    """Find the highest existing DET-NNNNN ID and increment."""
    existing = []
    for yml in ROOT.glob("rules/**/*.yml"):
        try:
            import yaml
            with open(yml) as f:
                rule = yaml.safe_load(f)
            rule_id = str(rule.get("id", ""))
            import re
            m = re.match(r'^DET-(\d+)$', rule_id)
            if m:
                existing.append(int(m.group(1)))
        except Exception:
            pass
    next_num = max(existing, default=0) + 1
    return f"DET-{next_num:05d}"


def main():
    print("\n  New Detection Rule Scaffolder")
    print("  " + "─" * 38)

    title = prompt("Rule title")
    if not title:
        print("  Aborted.")
        sys.exit(0)

    print(f"\n  Tactics: {', '.join(TACTICS)}")
    tactic = prompt("Tactic", "execution").lower().replace(" ", "_")
    if tactic not in TACTICS:
        print(f"  Unknown tactic — defaulting to 'execution'.")
        tactic = "execution"

    print(f"  Types: {', '.join(TYPES)}")
    rule_type = prompt("Type", "detection").lower()
    if rule_type not in TYPES:
        rule_type = "detection"

    level = prompt("Level (critical/high/medium/low)", "high").lower()
    if level not in LEVELS:
        level = "high"

    mitre = prompt("MITRE technique (e.g. T1059.001)", "TXXXX.XXX")
    author = prompt("Author", "Detection Engineering Team")

    rule_id = next_id()
    today = datetime.date.today().isoformat()
    slug = (
        title.lower()
        .replace(" ", "_")
        .replace("/", "_")
        .replace("(", "")
        .replace(")", "")
        [:60]
    )
    out_path = ROOT / "rules" / tactic / f"{slug}.yml"

    template = f"""title: {title}
id: {rule_id}
type: {rule_type}
status: experimental
description: >
  TODO: Describe what this rule detects and why it indicates malicious activity.
  Include context about the attacker technique, impacted systems, and signal fidelity.
author: {author}
date: {today}
modified: {today}
mitre:
  - {mitre}
data_source:
  - Sysmon EventID 1 (Process Creation)
analytic_story:
  - TODO: Add analytic story name
how_to_implement: >
  TODO: Describe required data sources, configurations, and index setup.
schedule:
  cron: "*/5 * * * *"
  earliest_time: "-10m"
  latest_time: "now"
search: |
  index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
  TODO: Add your SPL query here
  NOT (TODO: Add exclusions)
  | table _time, Computer, User, Image, CommandLine, ParentImage
  | sort -_time
falsepositives:
  - TODO: Document known false positive scenarios
level: {level}
"""

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(template)

    print(f"\n  Created: {out_path.relative_to(ROOT)}")
    print(f"  ID:      {rule_id}")
    print(f"\n  Next steps:")
    print(f"    1. Edit {out_path.relative_to(ROOT)}")
    print(f"    2. make validate")
    print(f"    3. git add {out_path.relative_to(ROOT)} && git commit -m 'feat: add {slug}'")
    print()


if __name__ == "__main__":
    main()
