#!/usr/bin/env python3
"""
new_rule_ai.py — AI-assisted detection rule scaffolder using Claude.

Generates a fully populated detection rule YAML and test fixture JSON
based on a plain-English description of the threat you want to detect.

Usage:
  make new-rule-ai
  python scripts/new_rule_ai.py
  python scripts/new_rule_ai.py --dry-run   # preview without writing files

Environment variables:
  ANTHROPIC_API_KEY  — required for API calls
"""

import argparse
import datetime
import json
import os
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent

TACTICS = [
    "credential_access", "execution", "lateral_movement",
    "persistence", "defense_evasion", "exfiltration",
    "discovery", "command_and_control"
]

LEVELS = ["critical", "high", "medium", "low"]
TYPES  = ["detection", "hunting", "correlation", "baseline"]
MODEL  = "claude-sonnet-4-6"

ANSI_GREEN  = "\033[32m"
ANSI_RED    = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_BLUE   = "\033[34m"
ANSI_RESET  = "\033[0m"
ANSI_BOLD   = "\033[1m"


# ── Prompt ────────────────────────────────────────────────────────────────

GENERATION_PROMPT = """You are a senior detection engineer building a Detection-as-Code pipeline.

Generate a complete detection rule based on the following threat description:

<threat>
{threat_description}
</threat>

<context>
Tactic:      {tactic}
Level:       {level}
Type:        {rule_type}
Data source: {data_source}
Author:      {author}
Rule ID:     {rule_id}
Date:        {date}
</context>

Generate the rule in the following JSON format. Return ONLY valid JSON, no markdown, no explanation:

{{
  "title": "Short descriptive title of what the rule detects",
  "description": "2-3 sentence description of the threat, why it is malicious, and what the rule detects",
  "mitre": ["T1234.001"],
  "data_source": ["Sysmon EventID 1 (Process Creation)"],
  "how_to_implement": "Brief description of required data sources and any configuration needed",
  "falsepositives": ["Known false positive scenario 1", "Known false positive scenario 2"],
  "search_spl": "Raw Splunk SPL query using field=value syntax with NOT filters for exclusions. Use Windows Sysmon field names (Image, CommandLine, ParentImage, User, Computer). Include | table and | sort at the end.",
  "search_kql": "Raw Microsoft Sentinel KQL query targeting DeviceProcessEvents table. Use MDE field names (FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName, DeviceName). Include | project at the end.",
  "test_cases": [
    {{
      "description": "True positive: describe the malicious scenario",
      "expected_match": true,
      "event": {{
        "Image": "C:\\\\Windows\\\\Temp\\\\malicious.exe",
        "CommandLine": "malicious.exe -flag target",
        "User": "CORP\\\\attacker",
        "ParentImage": "C:\\\\Windows\\\\System32\\\\cmd.exe",
        "Computer": "WORKSTATION-01"
      }}
    }},
    {{
      "description": "True negative: describe the benign scenario that should NOT fire",
      "expected_match": false,
      "event": {{
        "Image": "C:\\\\Windows\\\\System32\\\\legitimate.exe",
        "CommandLine": "legitimate.exe normal-args",
        "User": "NT AUTHORITY\\\\SYSTEM",
        "ParentImage": "C:\\\\Windows\\\\System32\\\\services.exe",
        "Computer": "WORKSTATION-02"
      }}
    }}
  ]
}}

Requirements:
- SPL must use raw field=value syntax (no Sigma modifiers like |contains or |startswith)
- SPL must include at least one NOT filter for a known false positive exclusion
- KQL must target DeviceProcessEvents or appropriate MDE table
- Include exactly 2 test cases minimum: 1 true positive and 1 true negative
- MITRE techniques must be in T####.### or T#### format
- Description must be at least 50 characters
- falsepositives must have at least 2 specific scenarios, not generic "None" or "Unknown"
"""


# ── Helpers ───────────────────────────────────────────────────────────────

def prompt(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"  {label}{suffix}: ").strip()
    return val if val else (default or "")


def next_id() -> str:
    """Find the highest existing DET-NNNNN ID and increment."""
    existing = []
    for yml in ROOT.glob("rules/**/*.yml"):
        try:
            with open(yml) as f:
                rule = yaml.safe_load(f)
            rule_id = str(rule.get("id", ""))
            m = re.match(r'^DET-(\d+)$', rule_id)
            if m:
                existing.append(int(m.group(1)))
        except Exception:
            pass
    return f"DET-{max(existing, default=0) + 1:05d}"


def call_claude(prompt_text: str, api_key: str) -> str:
    """Call the Anthropic API and return the response text."""
    payload = {
        "model": MODEL,
        "max_tokens": 4096,
        "messages": [{"role": "user", "content": prompt_text}]
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["content"][0]["text"]
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"API error {e.code}: {e.read().decode()}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection error: {e.reason}")


def parse_json_response(response: str) -> dict:
    """Extract and parse JSON from Claude's response."""
    response = response.strip()
    response = re.sub(r'^```json\s*', '', response)
    response = re.sub(r'^```\s*', '', response)
    response = re.sub(r'\s*```$', '', response)
    response = response.strip()
    
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        # Try to recover truncated JSON by finding the last complete field
        # and closing the object
        try:
            # Find the last complete key-value pair
            last_comma = response.rfind('",\n')
            if last_comma > 0:
                truncated = response[:last_comma + 1] + '\n  "test_cases": []}'
                return json.loads(truncated)
        except Exception:
            pass
        raise


def build_rule_yaml(
    generated: dict,
    rule_id: str,
    tactic: str,
    level: str,
    rule_type: str,
    author: str,
    date: str
) -> str:
    """Build the complete rule YAML from generated content."""

    # Build SPL search block
    spl = generated.get("search_spl", "TODO: Add SPL query here")
    kql = generated.get("search_kql", "")

    # Format falsepositives as YAML list
    fps = generated.get("falsepositives", ["Unknown"])
    fps_yaml = "\n".join(f"  - {fp}" for fp in fps)

    # Format MITRE techniques
    mitre = generated.get("mitre", ["TXXXX.XXX"])
    mitre_yaml = "\n".join(f"  - {t}" for t in mitre)

    # Format data sources
    data_sources = generated.get("data_source", ["Sysmon EventID 1"])
    ds_yaml = "\n".join(f"  - {ds}" for ds in data_sources)

    kql_block = ""
    if kql:
        kql_block = f"\nkql_search: |\n  {kql.strip().replace(chr(10), chr(10) + '  ')}\n"

    rule = f"""title: {generated.get('title', 'AI Generated Rule')}
id: {rule_id}
type: {rule_type}
status: experimental
description: >
  {generated.get('description', 'AI generated detection rule.')}
author: {author}
date: {date}
modified: {date}
mitre:
{mitre_yaml}
data_source:
{ds_yaml}
analytic_story:
  - AI Generated
how_to_implement: >
  {generated.get('how_to_implement', 'See data_source field for required telemetry.')}
schedule:
  cron: "*/5 * * * *"
  earliest_time: "-10m"
  latest_time: "now"
search: |
  {spl.strip().replace(chr(10), chr(10) + '  ')}
{kql_block}
falsepositives:
{fps_yaml}
level: {level}
"""
    return rule


def build_test_fixture(generated: dict) -> list[dict]:
    """Extract test cases from generated content."""
    return generated.get("test_cases", [])


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AI-assisted detection rule creation")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview generated content without writing files")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key and not args.dry_run:
        print(f"\n  {ANSI_RED}✗{ANSI_RESET}  ANTHROPIC_API_KEY not set.")
        print("  Export it: export ANTHROPIC_API_KEY=your_key_here")
        print("  Or use --dry-run to preview without an API key.\n")
        sys.exit(1)

    print(f"\n  {ANSI_BOLD}AI-Assisted Detection Rule Creator{ANSI_RESET}")
    print("  " + "─" * 42)
    print(f"  {ANSI_YELLOW}Powered by Claude ({MODEL}){ANSI_RESET}\n")

    # Gather inputs
    threat_desc = prompt("Describe the threat to detect (plain English)")
    if not threat_desc:
        print("  Aborted.")
        sys.exit(0)

    print(f"\n  Tactics: {', '.join(TACTICS)}")
    tactic = prompt("Tactic", "execution").lower().replace(" ", "_")
    if tactic not in TACTICS:
        tactic = "execution"

    level = prompt("Level (critical/high/medium/low)", "high").lower()
    if level not in LEVELS:
        level = "high"

    print(f"  Types: {', '.join(TYPES)}")
    rule_type = prompt("Type", "detection").lower()
    if rule_type not in TYPES:
        rule_type = "detection"

    data_source = prompt("Primary data source", "Sysmon EventID 1 (Process Creation)")
    author = prompt("Author", "Detection Engineering Team")

    rule_id = next_id()
    today = datetime.date.today().isoformat()

    # Call Claude
    print(f"\n  {ANSI_BLUE}Generating rule with Claude...{ANSI_RESET}", end=" ", flush=True)

    if args.dry_run:
        print(f"{ANSI_YELLOW}[dry-run]{ANSI_RESET}")
        generated = {
            "title": f"[DRY RUN] Detection for: {threat_desc[:50]}",
            "description": "This is a dry run — no API call was made.",
            "mitre": ["T1059.001"],
            "data_source": [data_source],
            "how_to_implement": "Dry run — no implementation details generated.",
            "falsepositives": ["Dry run scenario 1", "Dry run scenario 2"],
            "search_spl": 'index=* EventID=1\n  TODO: Add SPL query here\n  | table _time, Computer, User, Image, CommandLine\n  | sort -_time',
            "search_kql": "DeviceProcessEvents\n| where TODO\n| project TimeGenerated, DeviceName, AccountName, FolderPath, ProcessCommandLine",
            "test_cases": [
                {"description": "True positive (dry run)", "expected_match": True,
                 "event": {"Image": "C:\\\\malicious.exe", "CommandLine": "malicious.exe", "User": "CORP\\\\attacker", "Computer": "WS-01"}},
                {"description": "True negative (dry run)", "expected_match": False,
                 "event": {"Image": "C:\\\\legitimate.exe", "CommandLine": "legitimate.exe", "User": "NT AUTHORITY\\\\SYSTEM", "Computer": "WS-02"}}
            ]
        }
    else:
        try:
            prompt_text = GENERATION_PROMPT.format(
                threat_description=threat_desc,
                tactic=tactic,
                level=level,
                rule_type=rule_type,
                data_source=data_source,
                author=author,
                rule_id=rule_id,
                date=today
            )
            response = call_claude(prompt_text, api_key)
            generated = parse_json_response(response)
            print(f"{ANSI_GREEN}✓{ANSI_RESET}")
        except RuntimeError as e:
            print(f"{ANSI_RED}✗{ANSI_RESET}")
            print(f"\n  {ANSI_RED}API error:{ANSI_RESET} {e}\n")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"{ANSI_RED}✗{ANSI_RESET}")
            print(f"\n  {ANSI_RED}Failed to parse Claude response as JSON:{ANSI_RESET} {e}\n")
            sys.exit(1)

    # Build output files
    title = generated.get("title", f"AI Detection: {threat_desc[:40]}")
    slug = (
        title.lower()
        .replace(" ", "_")
        .replace("/", "_")
        .replace("(", "")
        .replace(")", "")
        .replace("[dry_run]_", "")
        [:60]
    )

    rule_path = ROOT / "rules" / tactic / f"{slug}.yml"
    test_path = ROOT / "tests" / "sample_logs" / f"{slug}.json"

    rule_content = build_rule_yaml(generated, rule_id, tactic, level, rule_type, author, today)
    test_cases = build_test_fixture(generated)

    # Preview
    print(f"\n  {ANSI_BOLD}Generated Rule Preview:{ANSI_RESET}")
    print(f"  Title:    {title}")
    print(f"  ID:       {rule_id}")
    print(f"  MITRE:    {', '.join(generated.get('mitre', []))}")
    print(f"  FPs:      {len(generated.get('falsepositives', []))} documented")
    print(f"  Tests:    {len(test_cases)} test cases")
    print(f"  SPL:      {'✓ generated' if generated.get('search_spl') else '✗ missing'}")
    print(f"  KQL:      {'✓ generated' if generated.get('search_kql') else '✗ missing'}")

    if args.dry_run:
        print(f"\n  {ANSI_YELLOW}[dry-run] Files would be written to:{ANSI_RESET}")
        print(f"  Rule:  {rule_path.relative_to(ROOT)}")
        print(f"  Tests: {test_path.relative_to(ROOT)}")
        print(f"\n  {ANSI_YELLOW}Rule content preview:{ANSI_RESET}\n")
        print(rule_content)
        sys.exit(0)

    # Write files
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.parent.mkdir(parents=True, exist_ok=True)

    rule_path.write_text(rule_content)
    test_path.write_text(json.dumps(test_cases, indent=2))

    print(f"\n  {ANSI_GREEN}✓{ANSI_RESET}  Rule:  {rule_path.relative_to(ROOT)}")
    print(f"  {ANSI_GREEN}✓{ANSI_RESET}  Tests: {test_path.relative_to(ROOT)}")

    print(f"\n  {ANSI_BOLD}Next steps:{ANSI_RESET}")
    print(f"    1. Review and refine: {rule_path.relative_to(ROOT)}")
    print(f"    2. make validate")
    print(f"    3. make test RULE={rule_id}")
    print(f"    4. git add rules/ tests/ && git commit -m 'feat: add {slug}'")
    print()


if __name__ == "__main__":
    main()