#!/usr/bin/env python3
"""
coverage.py — Generate MITRE ATT&CK coverage dashboard.

Scans all rules in the library and produces:
  1. An interactive HTML heatmap (coverage_report.html)
  2. A Markdown coverage summary (COVERAGE.md)

Coverage is tracked per backend:
  - Splunk: rules with a 'search' field
  - Sentinel: rules with a 'kql_search' field

Usage:
  python scripts/coverage.py                    # generate both outputs
  python scripts/coverage.py --html-only        # HTML heatmap only
  python scripts/coverage.py --markdown-only    # Markdown only
  python scripts/coverage.py --output-dir path  # custom output directory
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
CONFIG_FILE = ROOT / "sigma_config.yml"

ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"

# MITRE ATT&CK Tactics in kill chain order
TACTICS = [
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0010", "Exfiltration"),
    ("TA0011", "Command and Control"),
    ("TA0040", "Impact"),
]

# Tactic name to ID mapping
TACTIC_NAME_TO_ID = {name.lower(): tid for tid, name in TACTICS}

# Common techniques per tactic for reference (subset — expand as needed)
TACTIC_TECHNIQUES = {
    "TA0002": ["T1059", "T1059.001", "T1059.003", "T1059.005", "T1204", "T1569"],
    "TA0003": ["T1053", "T1053.005", "T1547", "T1547.001", "T1098", "T1136"],
    "TA0004": ["T1055", "T1068", "T1134", "T1548"],
    "TA0005": ["T1027", "T1036", "T1070", "T1112", "T1218", "T1562"],
    "TA0006": ["T1003", "T1003.001", "T1110", "T1555", "T1558"],
    "TA0007": ["T1007", "T1016", "T1033", "T1057", "T1069", "T1082", "T1083", "T1087"],
    "TA0008": ["T1021", "T1021.001", "T1021.002", "T1550", "T1563", "T1566"],
    "TA0009": ["T1005", "T1039", "T1074", "T1113", "T1560"],
    "TA0010": ["T1041", "T1048", "T1567"],
    "TA0011": ["T1071", "T1095", "T1105", "T1571", "T1573"],
    "TA0001": ["T1078", "T1190", "T1566", "T1566.001", "T1566.002"],
    "TA0040": ["T1485", "T1486", "T1489", "T1490", "T1498"],
}


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def load_rule(path: Path) -> dict | None:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def collect_rules(config: dict) -> list[tuple[Path, dict]]:
    rules = []
    for d in config.get("rule_dirs", []):
        rule_dir = ROOT / d
        if rule_dir.exists():
            for path in sorted(rule_dir.glob("*.yml")):
                rule = load_rule(path)
                if rule:
                    rules.append((path, rule))
    return rules


def extract_techniques(rule: dict) -> list[str]:
    """Extract MITRE technique IDs from a rule."""
    techniques = []

    # From mitre field (list of technique IDs)
    mitre = rule.get("mitre", [])
    if isinstance(mitre, list):
        for t in mitre:
            t_str = str(t).strip().upper()
            if t_str.startswith("T") and len(t_str) >= 5:
                techniques.append(t_str)

    # From tags field
    tags = rule.get("tags", [])
    import re
    for tag in tags:
        m = re.search(r't(\d{4}(?:\.\d{3})?)', str(tag), re.IGNORECASE)
        if m:
            techniques.append(f"T{m.group(1).upper()}")

    return list(set(techniques))


def extract_tactic(rule: dict, path: Path) -> str:
    """Infer tactic from rule directory name."""
    tactic_dir = path.parent.name.lower().replace("_", " ")
    return TACTIC_NAME_TO_ID.get(tactic_dir, "unknown")


def has_splunk(rule: dict) -> bool:
    search = rule.get("search", "")
    if search and str(search).strip():
        return True
    detection = rule.get("detection", {})
    if isinstance(detection, dict) and detection.get("raw_query"):
        return True
    return False


def has_sentinel(rule: dict) -> bool:
    kql = rule.get("kql_search", "")
    return bool(kql and str(kql).strip())


def analyze_coverage(rules: list[tuple[Path, dict]]) -> dict:
    """
    Analyze coverage across all rules.
    Returns a dict with technique-level coverage data.
    """
    # technique_id → {rules: [...], splunk: bool, sentinel: bool, tactic: str}
    coverage: dict[str, dict] = defaultdict(lambda: {
        "rules": [],
        "splunk": False,
        "sentinel": False,
        "tactic": "unknown",
        "levels": []
    })

    tactic_summary: dict[str, dict] = defaultdict(lambda: {
        "total": 0,
        "splunk": 0,
        "sentinel": 0,
        "both": 0,
        "techniques": set()
    })

    total_rules = len(rules)
    splunk_rules = 0
    sentinel_rules = 0
    both_rules = 0

    for path, rule in rules:
        techniques = extract_techniques(rule)
        tactic_id = extract_tactic(rule, path)
        rule_has_splunk = has_splunk(rule)
        rule_has_sentinel = has_sentinel(rule)
        level = rule.get("level") or rule.get("severity", "unknown")
        title = rule.get("title") or rule.get("name", path.stem)
        rule_id = str(rule.get("id", ""))

        if rule_has_splunk:
            splunk_rules += 1
        if rule_has_sentinel:
            sentinel_rules += 1
        if rule_has_splunk and rule_has_sentinel:
            both_rules += 1

        for technique in techniques:
            coverage[technique]["rules"].append({
                "id": rule_id,
                "title": title,
                "level": level,
                "splunk": rule_has_splunk,
                "sentinel": rule_has_sentinel,
                "path": str(path.relative_to(ROOT))
            })
            if rule_has_splunk:
                coverage[technique]["splunk"] = True
            if rule_has_sentinel:
                coverage[technique]["sentinel"] = True
            coverage[technique]["tactic"] = tactic_id
            if level not in coverage[technique]["levels"]:
                coverage[technique]["levels"].append(level)

            # Tactic summary
            tactic_summary[tactic_id]["techniques"].add(technique)
            if rule_has_splunk:
                tactic_summary[tactic_id]["splunk"] += 1
            if rule_has_sentinel:
                tactic_summary[tactic_id]["sentinel"] += 1
            if rule_has_splunk and rule_has_sentinel:
                tactic_summary[tactic_id]["both"] += 1
            tactic_summary[tactic_id]["total"] += 1

    return {
        "coverage": dict(coverage),
        "tactic_summary": {k: {**v, "techniques": list(v["techniques"])}
                           for k, v in tactic_summary.items()},
        "stats": {
            "total_rules": total_rules,
            "splunk_rules": splunk_rules,
            "sentinel_rules": sentinel_rules,
            "both_rules": both_rules,
            "techniques_covered": len(coverage),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        }
    }


def generate_html(data: dict, output_path: Path) -> None:
    """Generate an interactive HTML coverage heatmap."""
    coverage = data["coverage"]
    tactic_summary = data["tactic_summary"]
    stats = data["stats"]

    # Build tactic columns
    tactic_html = ""
    for tactic_id, tactic_name in TACTICS:
        summary = tactic_summary.get(tactic_id, {})
        technique_ids = summary.get("techniques", [])

        # Also include any techniques from coverage that map to this tactic
        extra = [t for t, d in coverage.items() if d["tactic"] == tactic_id
                 and t not in technique_ids]
        all_techniques = sorted(set(technique_ids + extra))

        technique_cells = ""
        for tech_id in all_techniques:
            tech_data = coverage.get(tech_id, {})
            rules = tech_data.get("rules", [])
            splunk = tech_data.get("splunk", False)
            sentinel = tech_data.get("sentinel", False)

            if splunk and sentinel:
                cell_class = "covered-both"
                badge = "S+KQL"
            elif splunk:
                cell_class = "covered-splunk"
                badge = "SPL"
            elif sentinel:
                cell_class = "covered-sentinel"
                badge = "KQL"
            else:
                cell_class = "uncovered"
                badge = ""

            rule_titles = "\n".join(
                f"• [{r['level'].upper()}] {r['title']}" for r in rules
            )
            tooltip = f"{tech_id}&#10;{rule_titles}" if rule_titles else tech_id

            technique_cells += f"""
            <div class="technique {cell_class}" title="{tooltip}" 
                 onclick="showDetail('{tech_id}')">
                <span class="tech-id">{tech_id}</span>
                {f'<span class="badge">{badge}</span>' if badge else ''}
            </div>"""

        covered = len([t for t in all_techniques if t in coverage])
        total = len(all_techniques)
        pct = int((covered / total * 100)) if total > 0 else 0

        tactic_html += f"""
        <div class="tactic-column">
            <div class="tactic-header">
                <div class="tactic-name">{tactic_name}</div>
                <div class="tactic-id">{tactic_id}</div>
                <div class="tactic-coverage">{covered}/{total} ({pct}%)</div>
            </div>
            <div class="techniques">
                {technique_cells}
            </div>
        </div>"""

    # Detail panel data
    coverage_json = json.dumps(coverage, indent=2)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MITRE ATT&CK Coverage Dashboard</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            min-height: 100vh;
        }}

        /* Header */
        .header {{
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 20px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .header h1 {{
            font-size: 20px;
            font-weight: 600;
            color: #f0f6fc;
        }}
        .header .subtitle {{
            font-size: 13px;
            color: #8b949e;
            margin-top: 4px;
        }}
        .generated {{
            font-size: 12px;
            color: #6e7681;
        }}

        /* Stats bar */
        .stats-bar {{
            display: flex;
            gap: 24px;
            padding: 16px 32px;
            background: #161b22;
            border-bottom: 1px solid #30363d;
        }}
        .stat {{
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: 700;
            color: #f0f6fc;
        }}
        .stat-label {{
            font-size: 12px;
            color: #8b949e;
            margin-top: 2px;
        }}

        /* Legend */
        .legend {{
            display: flex;
            gap: 16px;
            padding: 12px 32px;
            background: #0d1117;
            border-bottom: 1px solid #21262d;
            align-items: center;
        }}
        .legend-label {{ font-size: 12px; color: #8b949e; margin-right: 8px; }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            color: #c9d1d9;
        }}
        .legend-box {{
            width: 16px;
            height: 16px;
            border-radius: 3px;
        }}

        /* Matrix */
        .matrix-container {{
            padding: 24px 32px;
            overflow-x: auto;
        }}
        .matrix {{
            display: flex;
            gap: 8px;
            min-width: max-content;
        }}
        .tactic-column {{
            min-width: 130px;
            max-width: 150px;
        }}
        .tactic-header {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px 6px 0 0;
            padding: 10px;
            margin-bottom: 4px;
        }}
        .tactic-name {{
            font-size: 12px;
            font-weight: 600;
            color: #f0f6fc;
            line-height: 1.3;
        }}
        .tactic-id {{
            font-size: 10px;
            color: #6e7681;
            margin-top: 2px;
        }}
        .tactic-coverage {{
            font-size: 11px;
            color: #58a6ff;
            margin-top: 4px;
        }}
        .techniques {{
            display: flex;
            flex-direction: column;
            gap: 3px;
        }}
        .technique {{
            padding: 6px 8px;
            border-radius: 4px;
            cursor: pointer;
            transition: opacity 0.15s;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border: 1px solid transparent;
        }}
        .technique:hover {{ opacity: 0.85; border-color: #58a6ff; }}
        .tech-id {{
            font-size: 11px;
            font-weight: 500;
        }}
        .badge {{
            font-size: 9px;
            font-weight: 600;
            padding: 1px 4px;
            border-radius: 3px;
            background: rgba(0,0,0,0.3);
        }}

        /* Coverage colors */
        .covered-both    {{ background: #1f6feb; color: #ffffff; }}
        .covered-splunk  {{ background: #388bfd; color: #ffffff; }}
        .covered-sentinel {{ background: #56d364; color: #0d1117; }}
        .uncovered       {{ background: #21262d; color: #6e7681; }}

        /* Detail panel */
        .detail-panel {{
            position: fixed;
            right: 0;
            top: 0;
            width: 380px;
            height: 100vh;
            background: #161b22;
            border-left: 1px solid #30363d;
            padding: 24px;
            overflow-y: auto;
            display: none;
            z-index: 100;
        }}
        .detail-panel.visible {{ display: block; }}
        .detail-close {{
            position: absolute;
            top: 16px;
            right: 16px;
            background: none;
            border: none;
            color: #8b949e;
            font-size: 20px;
            cursor: pointer;
        }}
        .detail-close:hover {{ color: #f0f6fc; }}
        .detail-technique-id {{
            font-size: 24px;
            font-weight: 700;
            color: #58a6ff;
            margin-bottom: 4px;
        }}
        .detail-title {{
            font-size: 14px;
            color: #8b949e;
            margin-bottom: 16px;
        }}
        .detail-backends {{
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
        }}
        .backend-badge {{
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }}
        .backend-splunk  {{ background: #388bfd; color: white; }}
        .backend-sentinel {{ background: #56d364; color: #0d1117; }}
        .backend-none {{ background: #21262d; color: #6e7681; }}
        .detail-rules-title {{
            font-size: 12px;
            font-weight: 600;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 10px;
        }}
        .rule-card {{
            background: #0d1117;
            border: 1px solid #21262d;
            border-radius: 6px;
            padding: 10px 12px;
            margin-bottom: 8px;
        }}
        .rule-card-title {{
            font-size: 13px;
            font-weight: 500;
            color: #f0f6fc;
            margin-bottom: 6px;
        }}
        .rule-card-meta {{
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }}
        .rule-pill {{
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: 600;
        }}
        .pill-critical {{ background: #da3633; color: white; }}
        .pill-high     {{ background: #d29922; color: #0d1117; }}
        .pill-medium   {{ background: #388bfd; color: white; }}
        .pill-low      {{ background: #21262d; color: #8b949e; }}
        .pill-splunk   {{ background: #388bfd20; color: #58a6ff; border: 1px solid #388bfd; }}
        .pill-sentinel {{ background: #56d36420; color: #56d364; border: 1px solid #56d364; }}
        .no-rules {{
            color: #6e7681;
            font-size: 13px;
            font-style: italic;
        }}
    </style>
</head>
<body>

<div class="header">
    <div>
        <h1>MITRE ATT&CK Coverage Dashboard</h1>
        <div class="subtitle">Detection-as-Code Pipeline — Rule Coverage by Technique and Backend</div>
    </div>
    <div class="generated">Generated: {stats['generated_at']}</div>
</div>

<div class="stats-bar">
    <div class="stat">
        <div class="stat-value">{stats['total_rules']}</div>
        <div class="stat-label">Total Rules</div>
    </div>
    <div class="stat">
        <div class="stat-value" style="color:#388bfd">{stats['splunk_rules']}</div>
        <div class="stat-label">Splunk (SPL)</div>
    </div>
    <div class="stat">
        <div class="stat-value" style="color:#56d364">{stats['sentinel_rules']}</div>
        <div class="stat-label">Sentinel (KQL)</div>
    </div>
    <div class="stat">
        <div class="stat-value" style="color:#1f6feb">{stats['both_rules']}</div>
        <div class="stat-label">Both Backends</div>
    </div>
    <div class="stat">
        <div class="stat-value" style="color:#f0f6fc">{stats['techniques_covered']}</div>
        <div class="stat-label">Techniques Covered</div>
    </div>
</div>

<div class="legend">
    <span class="legend-label">Coverage:</span>
    <div class="legend-item">
        <div class="legend-box" style="background:#1f6feb"></div>
        Both Backends
    </div>
    <div class="legend-item">
        <div class="legend-box" style="background:#388bfd"></div>
        Splunk Only
    </div>
    <div class="legend-item">
        <div class="legend-box" style="background:#56d364"></div>
        Sentinel Only
    </div>
    <div class="legend-item">
        <div class="legend-box" style="background:#21262d"></div>
        Not Covered
    </div>
</div>

<div class="matrix-container">
    <div class="matrix">
        {tactic_html}
    </div>
</div>

<div class="detail-panel" id="detailPanel">
    <button class="detail-close" onclick="closeDetail()">×</button>
    <div class="detail-technique-id" id="detailTechId"></div>
    <div class="detail-title" id="detailTitle"></div>
    <div class="detail-backends" id="detailBackends"></div>
    <div class="detail-rules-title">Detection Rules</div>
    <div id="detailRules"></div>
</div>

<script>
const coverageData = {coverage_json};

function showDetail(techId) {{
    const panel = document.getElementById('detailPanel');
    const data = coverageData[techId] || {{}};
    const rules = data.rules || [];

    document.getElementById('detailTechId').textContent = techId;
    document.getElementById('detailTitle').textContent = 
        rules.length > 0 ? `${{rules.length}} rule${{rules.length !== 1 ? 's' : ''}} covering this technique` : 'No rules defined';

    // Backend badges
    const backends = document.getElementById('detailBackends');
    backends.innerHTML = '';
    if (data.splunk) {{
        backends.innerHTML += '<span class="backend-badge backend-splunk">Splunk SPL</span>';
    }}
    if (data.sentinel) {{
        backends.innerHTML += '<span class="backend-badge backend-sentinel">Sentinel KQL</span>';
    }}
    if (!data.splunk && !data.sentinel) {{
        backends.innerHTML += '<span class="backend-badge backend-none">No backend coverage</span>';
    }}

    // Rule cards
    const rulesDiv = document.getElementById('detailRules');
    if (rules.length === 0) {{
        rulesDiv.innerHTML = '<div class="no-rules">No detection rules cover this technique yet.</div>';
    }} else {{
        rulesDiv.innerHTML = rules.map(r => `
            <div class="rule-card">
                <div class="rule-card-title">${{r.title}}</div>
                <div class="rule-card-meta">
                    <span class="rule-pill pill-${{r.level}}">${{r.level.toUpperCase()}}</span>
                    ${{r.splunk ? '<span class="rule-pill pill-splunk">SPL</span>' : ''}}
                    ${{r.sentinel ? '<span class="rule-pill pill-sentinel">KQL</span>' : ''}}
                    <span style="font-size:10px;color:#6e7681">${{r.id}}</span>
                </div>
            </div>
        `).join('');
    }}

    panel.classList.add('visible');
}}

function closeDetail() {{
    document.getElementById('detailPanel').classList.remove('visible');
}}

// Close on escape
document.addEventListener('keydown', e => {{
    if (e.key === 'Escape') closeDetail();
}});
</script>
</body>
</html>"""

    output_path.write_text(html)


def generate_markdown(data: dict, output_path: Path) -> None:
    """Generate a Markdown coverage summary."""
    coverage = data["coverage"]
    tactic_summary = data["tactic_summary"]
    stats = data["stats"]

    lines = [
        "# MITRE ATT&CK Coverage Report",
        f"\n> Generated: {stats['generated_at']}",
        "\n## Summary\n",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total Rules | {stats['total_rules']} |",
        f"| Splunk (SPL) Coverage | {stats['splunk_rules']} rules |",
        f"| Sentinel (KQL) Coverage | {stats['sentinel_rules']} rules |",
        f"| Both Backends | {stats['both_rules']} rules |",
        f"| Techniques Covered | {stats['techniques_covered']} |",
        "\n## Coverage by Tactic\n",
        "| Tactic | Techniques Covered | Splunk | Sentinel |",
        "|--------|-------------------|--------|----------|",
    ]

    for tactic_id, tactic_name in TACTICS:
        summary = tactic_summary.get(tactic_id, {})
        techniques = summary.get("techniques", [])
        splunk = summary.get("splunk", 0)
        sentinel = summary.get("sentinel", 0)
        covered = len([t for t in techniques if t in coverage])
        lines.append(f"| {tactic_name} | {covered} | {splunk} rules | {sentinel} rules |")

    lines.append("\n## Technique Detail\n")
    lines.append("| Technique | Rules | Splunk | Sentinel | Severity |")
    lines.append("|-----------|-------|--------|----------|----------|")

    for tech_id in sorted(coverage.keys()):
        tech_data = coverage[tech_id]
        rules = tech_data["rules"]
        splunk = "✓" if tech_data["splunk"] else "✗"
        sentinel = "✓" if tech_data["sentinel"] else "✗"
        levels = ", ".join(sorted(set(r["level"] for r in rules)))
        rule_titles = "<br>".join(f"`{r['id']}` {r['title']}" for r in rules)
        lines.append(f"| {tech_id} | {rule_titles} | {splunk} | {sentinel} | {levels} |")

    output_path.write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Generate MITRE ATT&CK coverage dashboard")
    parser.add_argument("--html-only", action="store_true", help="Generate HTML only")
    parser.add_argument("--markdown-only", action="store_true", help="Generate Markdown only")
    parser.add_argument("--output-dir", type=Path, default=ROOT,
                        help="Output directory (default: repo root)")
    args = parser.parse_args()

    config = load_config()
    rules = collect_rules(config)

    if not rules:
        print("No rules found.")
        sys.exit(0)

    print(f"\n{ANSI_BOLD}MITRE ATT&CK Coverage Generator{ANSI_RESET}  ({len(rules)} rules)\n")

    data = analyze_coverage(rules)
    stats = data["stats"]

    print(f"  Total rules:        {stats['total_rules']}")
    print(f"  Splunk coverage:    {stats['splunk_rules']} rules")
    print(f"  Sentinel coverage:  {stats['sentinel_rules']} rules")
    print(f"  Both backends:      {stats['both_rules']} rules")
    print(f"  Techniques covered: {stats['techniques_covered']}")
    print()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    if not args.markdown_only:
        html_path = args.output_dir / "coverage_report.html"
        generate_html(data, html_path)
        print(f"  {ANSI_GREEN}✓{ANSI_RESET}  HTML heatmap → {html_path}")

    if not args.html_only:
        md_path = args.output_dir / "COVERAGE.md"
        generate_markdown(data, md_path)
        print(f"  {ANSI_GREEN}✓{ANSI_RESET}  Markdown report → {md_path}")

    print(f"\n{ANSI_GREEN}✓ Coverage report complete{ANSI_RESET}\n")


if __name__ == "__main__":
    main()