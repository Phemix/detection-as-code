#!/usr/bin/env python3
"""
mcp_server.py — MCP server for the Detection-as-Code pipeline.

Exposes detection rules, scores, coverage, and pipeline operations
as tools that Claude can call from VS Code.

Usage:
  python scripts/mcp_server.py          # start the server
  make mcp                              # same via Makefile

VS Code configuration (.mcp.json):
  {
    "mcpServers": {
      "dac-pipeline": {
        "command": "python3",
        "args": ["scripts/mcp_server.py"],
        "cwd": "/path/to/your/detection-as-code"
      }
    }
  }
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

ROOT = Path(__file__).parent.parent
CONFIG_FILE = ROOT / "sigma_config.yml"
TESTS_DIR = ROOT / "tests" / "sample_logs"

# ── Helpers ───────────────────────────────────────────────────────────────

def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def collect_rule_paths(config: dict) -> list[Path]:
    paths = []
    for d in config.get("rule_dirs", []):
        rule_dir = ROOT / d
        if rule_dir.exists():
            paths.extend(sorted(rule_dir.glob("*.yml")))
    return paths


def load_rule(path: Path) -> dict | None:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def extract_techniques(rule: dict) -> list[str]:
    techniques = []
    mitre = rule.get("mitre", [])
    if isinstance(mitre, list):
        for t in mitre:
            t_str = str(t).strip().upper()
            if t_str.startswith("T"):
                techniques.append(t_str)
    return techniques


def compute_score(rule: dict, path: Path) -> int:
    score = 0
    stem = path.stem

    # Test coverage (0-25)
    test_file = TESTS_DIR / f"{stem}.json"
    if test_file.exists():
        try:
            cases = json.loads(test_file.read_text())
            score += 10
            if any(c.get("expected_match", True) for c in cases):
                score += 8
            if any(not c.get("expected_match", True) for c in cases):
                score += 7
        except Exception:
            pass

    # Backend coverage (0-20)
    if (rule.get("search") or "").strip():
        score += 10
    if (rule.get("kql_search") or "").strip():
        score += 10

    # Documentation (0-20)
    for field in ["description", "falsepositives", "how_to_implement", "data_source"]:
        val = rule.get(field)
        if val and str(val).strip().lower() not in ("none", "unknown", "todo", "tbd", "n/a"):
            score += 5

    # MITRE mapping (0-15)
    techniques = extract_techniques(rule)
    if techniques:
        score += 8
        if any("." in t for t in techniques):
            score += 4
        if len(techniques) > 1:
            score += 3

    # Promotion status (0-20)
    status_scores = {"stable": 20, "test": 10, "experimental": 5}
    score += status_scores.get(str(rule.get("status", "")).lower(), 0)

    return min(score, 100)


# ── MCP Server ────────────────────────────────────────────────────────────

server = Server("dac-pipeline")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="list_rules",
            description="List all detection rules in the library. Returns ID, title, tactic, level, status and score for each rule. Use this when the user wants to browse or see an overview of all rules.",
            inputSchema={
                "type": "object",
                "properties": {
                    "tactic": {
                        "type": "string",
                        "description": "Optional filter by tactic (e.g. credential_access, execution, lateral_movement)"
                    },
                    "status": {
                        "type": "string",
                        "description": "Optional filter by status (stable, experimental, test)"
                    },
                    "level": {
                        "type": "string",
                        "description": "Optional filter by severity level (critical, high, medium, low)"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="get_rule",
            description="Get the full YAML content of a specific detection rule by its ID (e.g. DET-00001). Use this when the user asks about a specific rule or wants to see its detection logic, MITRE mapping, or false positives.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "The rule ID in DET-NNNNN format (e.g. DET-00001)"
                    }
                },
                "required": ["rule_id"]
            }
        ),
        Tool(
            name="get_score",
            description="Get the quality score for a specific rule or all rules. Returns a 0-100 score with breakdown across test coverage, backend coverage, documentation, MITRE mapping, and promotion status. Use this when the user asks about rule quality or what needs improvement.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "Optional rule ID. If not provided returns scores for all rules."
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="search_rules",
            description="Search for detection rules by tactic, MITRE technique, level, or keyword in the title. Use this when the user asks what rules exist for a specific technique, tactic, or threat scenario.",
            inputSchema={
                "type": "object",
                "properties": {
                    "tactic": {
                        "type": "string",
                        "description": "MITRE tactic to search for (e.g. credential_access)"
                    },
                    "technique": {
                        "type": "string",
                        "description": "MITRE technique ID to search for (e.g. T1003)"
                    },
                    "keyword": {
                        "type": "string",
                        "description": "Keyword to search for in rule titles"
                    },
                    "level": {
                        "type": "string",
                        "description": "Filter by severity level (critical, high, medium, low)"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="get_coverage",
            description="Get MITRE ATT&CK coverage summary showing which tactics and techniques are covered by the detection library, and which backends (Splunk/Sentinel) have coverage. Use this when the user asks about coverage gaps or what techniques are missing.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="validate_rule",
            description="Run schema validation against a specific rule file and return any errors or warnings. Use this when the user wants to check if a rule is valid before committing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "The rule ID to validate (e.g. DET-00001)"
                    }
                },
                "required": ["rule_id"]
            }
        ),
        Tool(
            name="compile_rule",
            description="Compile a specific rule to SPL (Splunk) or KQL (Sentinel) and return the compiled output. Use this when the user wants to see what the compiled query looks like.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "The rule ID to compile (e.g. DET-00001)"
                    },
                    "backend": {
                        "type": "string",
                        "description": "Backend to compile for: splunk or sentinel",
                        "enum": ["splunk", "sentinel"]
                    }
                },
                "required": ["rule_id", "backend"]
            }
        ),
        Tool(
            name="check_journal",
            description="Check whether rule changes since a base branch have matching journal/{rule_id}.md updates. Returns pass/fail and lists any rules missing a journal entry. Use this when the user asks if their rule changes are journaled or before opening a PR.",
            inputSchema={
                "type": "object",
                "properties": {
                    "base": {
                        "type": "string",
                        "description": "Base ref to diff against (default: main)"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="get_journal",
            description="Get the journal content for a specific rule by ID — its origin, tuning history, known false positives, and review status. Use this when the user asks why a rule was created or how it's evolved.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "The rule ID in DET-NNNNN format (e.g. DET-00001)"
                    }
                },
                "required": ["rule_id"]
            }
        ),
        Tool(
            name="create_rule",
            description="Create a new detection rule scaffold with the given parameters. Returns the path to the created rule file. Use this when the user wants to create a new detection rule.",
            inputSchema={
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Title of the detection rule"
                    },
                    "tactic": {
                        "type": "string",
                        "description": "MITRE tactic directory (e.g. credential_access, execution)"
                    },
                    "level": {
                        "type": "string",
                        "description": "Severity level: critical, high, medium, or low",
                        "enum": ["critical", "high", "medium", "low"]
                    },
                    "mitre": {
                        "type": "string",
                        "description": "MITRE technique ID (e.g. T1003.001)"
                    }
                },
                "required": ["title", "tactic", "level"]
            }
        ),
    ]


# ── Tool implementations ───────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    config = load_config()
    paths = collect_rule_paths(config)

    if name == "list_rules":
        return await _list_rules(paths, arguments)
    elif name == "get_rule":
        return await _get_rule(paths, arguments)
    elif name == "get_score":
        return await _get_score(paths, arguments)
    elif name == "search_rules":
        return await _search_rules(paths, arguments)
    elif name == "get_coverage":
        return await _get_coverage(paths)
    elif name == "validate_rule":
        return await _validate_rule(paths, arguments)
    elif name == "compile_rule":
        return await _compile_rule(paths, arguments)
    elif name == "check_journal":
        return await _check_journal(arguments)
    elif name == "get_journal":
        return await _get_journal(arguments)
    elif name == "create_rule":
        return await _create_rule(arguments)
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def _list_rules(paths: list[Path], args: dict) -> list[TextContent]:
    tactic_filter = args.get("tactic", "").lower()
    status_filter = args.get("status", "").lower()
    level_filter = args.get("level", "").lower()

    rows = []
    for path in paths:
        rule = load_rule(path)
        if not rule:
            continue

        tactic = path.parent.name
        if tactic_filter and tactic_filter not in tactic:
            continue

        status = str(rule.get("status", "")).lower()
        if status_filter and status != status_filter:
            continue

        level = str(rule.get("level") or rule.get("severity", "")).lower()
        if level_filter and level != level_filter:
            continue

        score = compute_score(rule, path)
        title = rule.get("title") or rule.get("name", path.stem)
        rule_id = str(rule.get("id", ""))
        techniques = ", ".join(extract_techniques(rule)) or "none"

        rows.append(
            f"[{rule_id}] {title}\n"
            f"  Tactic: {tactic} | Level: {level} | Status: {status} | Score: {score}/100\n"
            f"  MITRE: {techniques}"
        )

    if not rows:
        return [TextContent(type="text", text="No rules found matching the filters.")]

    result = f"Found {len(rows)} rule(s):\n\n" + "\n\n".join(rows)
    return [TextContent(type="text", text=result)]


async def _get_rule(paths: list[Path], args: dict) -> list[TextContent]:
    rule_id = args.get("rule_id", "").strip().upper()
    if not rule_id:
        return [TextContent(type="text", text="Please provide a rule_id (e.g. DET-00001)")]

    for path in paths:
        rule = load_rule(path)
        if rule and str(rule.get("id", "")).upper() == rule_id:
            content = path.read_text()
            score = compute_score(rule, path)
            return [TextContent(
                type="text",
                text=f"Rule: {rule_id} | Score: {score}/100 | File: {path.relative_to(ROOT)}\n\n{content}"
            )]

    return [TextContent(type="text", text=f"Rule {rule_id} not found.")]


async def _get_score(paths: list[Path], args: dict) -> list[TextContent]:
    rule_id = args.get("rule_id", "").strip().upper()
    results = []

    for path in paths:
        rule = load_rule(path)
        if not rule:
            continue

        if rule_id and str(rule.get("id", "")).upper() != rule_id:
            continue

        score = compute_score(rule, path)
        title = rule.get("title") or rule.get("name", path.stem)
        rid = str(rule.get("id", ""))

        # Dimension breakdown
        stem = path.stem
        test_file = TESTS_DIR / f"{stem}.json"
        tc = 0
        if test_file.exists():
            try:
                cases = json.loads(test_file.read_text())
                tc = 10
                if any(c.get("expected_match", True) for c in cases):
                    tc += 8
                if any(not c.get("expected_match", True) for c in cases):
                    tc += 7
            except Exception:
                pass

        bc = (10 if (rule.get("search") or "").strip() else 0) + \
             (10 if (rule.get("kql_search") or "").strip() else 0)

        doc = sum(5 for f in ["description", "falsepositives", "how_to_implement", "data_source"]
                  if rule.get(f) and str(rule.get(f)).strip().lower() not in
                  ("none", "unknown", "todo", "tbd", "n/a"))

        techniques = extract_techniques(rule)
        mitre = 0
        if techniques:
            mitre = 8
            if any("." in t for t in techniques):
                mitre += 4
            if len(techniques) > 1:
                mitre += 3

        promo = {"stable": 20, "test": 10, "experimental": 5}.get(
            str(rule.get("status", "")).lower(), 0)

        results.append(
            f"[{rid}] {title}\n"
            f"  Total: {score}/100\n"
            f"  Test coverage:    {tc}/25\n"
            f"  Backend coverage: {bc}/20\n"
            f"  Documentation:    {doc}/20\n"
            f"  MITRE mapping:    {mitre}/15\n"
            f"  Promotion status: {promo}/20"
        )

    if not results:
        msg = f"Rule {rule_id} not found." if rule_id else "No rules found."
        return [TextContent(type="text", text=msg)]

    avg = 0
    if not rule_id and len(results) > 1:
        all_scores = []
        for path in paths:
            rule = load_rule(path)
            if rule:
                all_scores.append(compute_score(rule, path))
        if all_scores:
            avg = int(sum(all_scores) / len(all_scores))
        header = f"Rule Quality Scores (Average: {avg}/100)\n\n"
    else:
        header = ""

    return [TextContent(type="text", text=header + "\n\n".join(results))]


async def _search_rules(paths: list[Path], args: dict) -> list[TextContent]:
    tactic = args.get("tactic", "").lower()
    technique = args.get("technique", "").upper()
    keyword = args.get("keyword", "").lower()
    level = args.get("level", "").lower()

    if not any([tactic, technique, keyword, level]):
        return [TextContent(type="text", text="Please provide at least one search parameter: tactic, technique, keyword, or level.")]

    matches = []
    for path in paths:
        rule = load_rule(path)
        if not rule:
            continue

        # Tactic filter
        if tactic and tactic not in path.parent.name.lower():
            continue

        # Technique filter
        if technique:
            techniques = extract_techniques(rule)
            if not any(technique in t for t in techniques):
                continue

        # Keyword filter
        if keyword:
            title = str(rule.get("title") or rule.get("name", "")).lower()
            if keyword not in title:
                continue

        # Level filter
        if level:
            rule_level = str(rule.get("level") or rule.get("severity", "")).lower()
            if rule_level != level:
                continue

        score = compute_score(rule, path)
        title = rule.get("title") or rule.get("name", path.stem)
        rule_id = str(rule.get("id", ""))
        techniques = ", ".join(extract_techniques(rule)) or "none"
        rule_level = str(rule.get("level") or rule.get("severity", "unknown"))

        matches.append(
            f"[{rule_id}] {title}\n"
            f"  Tactic: {path.parent.name} | Level: {rule_level} | Score: {score}/100\n"
            f"  MITRE: {techniques}"
        )

    if not matches:
        return [TextContent(type="text", text="No rules found matching your search.")]

    return [TextContent(type="text", text=f"Found {len(matches)} matching rule(s):\n\n" + "\n\n".join(matches))]


async def _get_coverage(paths: list[Path]) -> list[TextContent]:
    tactic_coverage: dict[str, dict] = {}
    technique_coverage: dict[str, list] = {}

    for path in paths:
        rule = load_rule(path)
        if not rule:
            continue

        tactic = path.parent.name
        techniques = extract_techniques(rule)
        has_splunk = bool((rule.get("search") or "").strip())
        has_sentinel = bool((rule.get("kql_search") or "").strip())
        title = rule.get("title") or path.stem
        rule_id = str(rule.get("id", ""))

        if tactic not in tactic_coverage:
            tactic_coverage[tactic] = {"rules": 0, "splunk": 0, "sentinel": 0, "both": 0}

        tactic_coverage[tactic]["rules"] += 1
        if has_splunk:
            tactic_coverage[tactic]["splunk"] += 1
        if has_sentinel:
            tactic_coverage[tactic]["sentinel"] += 1
        if has_splunk and has_sentinel:
            tactic_coverage[tactic]["both"] += 1

        for t in techniques:
            if t not in technique_coverage:
                technique_coverage[t] = []
            technique_coverage[t].append(f"{rule_id}: {title}")

    lines = ["MITRE ATT&CK Coverage Summary\n"]
    lines.append("Coverage by Tactic:")
    lines.append("─" * 50)

    for tactic, data in sorted(tactic_coverage.items()):
        lines.append(
            f"{tactic.replace('_', ' ').title()}\n"
            f"  Rules: {data['rules']} | Splunk: {data['splunk']} | "
            f"Sentinel: {data['sentinel']} | Both: {data['both']}"
        )

    lines.append(f"\nTechniques Covered: {len(technique_coverage)}")
    lines.append("─" * 50)

    for technique in sorted(technique_coverage.keys()):
        rules = technique_coverage[technique]
        lines.append(f"{technique}: {', '.join(rules)}")

    # Coverage gaps
    covered_tactics = set(tactic_coverage.keys())
    all_tactics = {
        "credential_access", "execution", "lateral_movement", "persistence",
        "defense_evasion", "exfiltration", "discovery", "command_and_control"
    }
    gaps = all_tactics - covered_tactics
    if gaps:
        lines.append(f"\nTactics with NO coverage: {', '.join(sorted(gaps))}")

    return [TextContent(type="text", text="\n".join(lines))]


async def _validate_rule(paths: list[Path], args: dict) -> list[TextContent]:
    rule_id = args.get("rule_id", "").strip().upper()

    for path in paths:
        rule = load_rule(path)
        if rule and str(rule.get("id", "")).upper() == rule_id:
            result = subprocess.run(
                ["python3", str(ROOT / "scripts" / "validate.py"), "--file", str(path)],
                capture_output=True,
                text=True,
                cwd=str(ROOT)
            )
            output = result.stdout + result.stderr
            status = "PASSED" if result.returncode == 0 else "FAILED"
            return [TextContent(type="text", text=f"Validation {status} for {rule_id}:\n\n{output}")]

    return [TextContent(type="text", text=f"Rule {rule_id} not found.")]


async def _compile_rule(paths: list[Path], args: dict) -> list[TextContent]:
    rule_id = args.get("rule_id", "").strip().upper()
    backend = args.get("backend", "splunk").lower()

    for path in paths:
        rule = load_rule(path)
        if rule and str(rule.get("id", "")).upper() == rule_id:
            result = subprocess.run(
                ["python3", str(ROOT / "scripts" / "compile.py"),
                 "--backend", backend,
                 "--file", str(path)],
                capture_output=True,
                text=True,
                cwd=str(ROOT)
            )
            output = result.stdout + result.stderr

            # Try to read compiled output file
            ext = ".spl" if backend == "splunk" else ".kql"
            compiled_dir = ROOT / "compiled" / backend
            compiled_file = compiled_dir / path.parent.name / path.with_suffix(ext).name

            if compiled_file.exists():
                compiled = compiled_file.read_text()
                return [TextContent(
                    type="text",
                    text=f"Compiled {rule_id} to {backend.upper()}:\n\n{compiled}"
                )]

            return [TextContent(type="text", text=f"Compile output:\n{output}")]

    return [TextContent(type="text", text=f"Rule {rule_id} not found.")]


async def _check_journal(args: dict) -> list[TextContent]:
    base = args.get("base", "main")
    result = subprocess.run(
        ["python3", str(ROOT / "scripts" / "check_journal_updated.py"), "--base", base],
        capture_output=True,
        text=True,
        cwd=str(ROOT)
    )
    output = result.stdout + result.stderr
    status = "PASSED" if result.returncode == 0 else "FAILED"
    return [TextContent(type="text", text=f"Journal check {status} (base: {base}):\n\n{output}")]


async def _get_journal(args: dict) -> list[TextContent]:
    rule_id = args.get("rule_id", "").strip().upper()
    if not rule_id:
        return [TextContent(type="text", text="Please provide a rule_id (e.g. DET-00001)")]

    journal_path = ROOT / "journal" / f"{rule_id}.md"
    if not journal_path.exists():
        return [TextContent(
            type="text",
            text=f"No journal found for {rule_id} at journal/{rule_id}.md.\n"
                 f"Copy journal/rule-journal-template.md to create one."
        )]

    return [TextContent(type="text", text=journal_path.read_text())]


async def _create_rule(args: dict) -> list[TextContent]:
    import datetime

    title = args.get("title", "")
    tactic = args.get("tactic", "execution").lower().replace(" ", "_")
    level = args.get("level", "high").lower()
    mitre = args.get("mitre", "TXXXX.XXX")

    if not title:
        return [TextContent(type="text", text="Please provide a rule title.")]

    # Get next ID
    config = load_config()
    paths = collect_rule_paths(config)
    existing = []
    for p in paths:
        r = load_rule(p)
        if r:
            m = re.match(r'^DET-(\d+)$', str(r.get("id", "")))
            if m:
                existing.append(int(m.group(1)))
    rule_id = f"DET-{max(existing, default=0) + 1:05d}"

    today = datetime.date.today().isoformat()
    slug = (title.lower().replace(" ", "_").replace("/", "_")
            .replace("(", "").replace(")", "")[:60])

    out_path = ROOT / "rules" / tactic / f"{slug}.yml"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    template = f"""title: {title}
id: {rule_id}
type: detection
status: experimental
description: >
  TODO: Describe what this rule detects and why it indicates malicious activity.
author: Detection Engineering Team
date: {today}
modified: {today}
mitre:
  - {mitre}
data_source:
  - Sysmon EventID 1 (Process Creation)
how_to_implement: >
  TODO: Describe required data sources and configuration.
schedule:
  cron: "*/5 * * * *"
  earliest_time: "-10m"
  latest_time: "now"
search: |
  index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
  TODO: Add your SPL query here
  | table _time, Computer, User, Image, CommandLine, ParentImage
  | sort -_time
falsepositives:
  - TODO: Document known false positive scenarios
level: {level}
"""

    out_path.write_text(template)

    return [TextContent(
        type="text",
        text=f"Created rule {rule_id}: {out_path.relative_to(ROOT)}\n\n"
             f"Title: {title}\n"
             f"Tactic: {tactic}\n"
             f"Level: {level}\n"
             f"MITRE: {mitre}\n\n"
             f"Next steps:\n"
             f"1. Edit the rule file to add your SPL query\n"
             f"2. Run validate_rule to check it\n"
             f"3. Add test cases to tests/sample_logs/{slug}.json"
    )]


# ── Entry point ───────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())