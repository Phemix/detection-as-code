#!/usr/bin/env python3
"""
inventory.py — Generate a rule registry from the detection library.
Supports SSC-style schema with mitre: field and search: block.

Usage:
  python scripts/inventory.py
  python scripts/inventory.py --json
  python scripts/inventory.py --output RULES.md
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
CONFIG_FILE = ROOT / "sigma_config.yml"
TESTS_DIR = ROOT / "tests" / "sample_logs"

TACTIC_ORDER = [
    "reconnaissance", "resource_development", "initial_access",
    "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery",
    "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact"
]

LEVEL_EMOJI = {
    "critical": "🔴", "high": "🟠", "medium": "🟡",
    "low": "🔵", "informational": "⚪",
}

STATUS_EMOJI = {
    "stable": "✅", "experimental": "🧪",
    "test": "🔬", "deprecated": "❌",
}

TYPE_EMOJI = {
    "detection": "🛡", "hunting": "🔍",
    "correlation": "🔗", "baseline": "📊",
}

SCORE_EMOJI = {
    range(80, 101): "🟢",
    range(60, 80):  "🟡",
    range(40, 60):  "🟠",
    range(0, 40):   "🔴",
}


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def load_rules(config: dict) -> list[dict]:
    rules = []
    for d in config.get("rule_dirs", []):
        rule_dir = ROOT / d
        if not rule_dir.exists():
            continue
        tactic = rule_dir.name
        for path in sorted(rule_dir.glob("*.yml")):
            with open(path) as f:
                try:
                    rule = yaml.safe_load(f)
                    if isinstance(rule, dict):
                        rule["_path"] = str(path.relative_to(ROOT))
                        rule["_tactic"] = tactic
                        rule["_stem"] = path.stem
                        rules.append(rule)
                except yaml.YAMLError:
                    pass
    return rules


def extract_techniques(rule: dict) -> list[str]:
    mitre = rule.get("mitre", [])
    if isinstance(mitre, list) and mitre:
        return sorted(set(str(t) for t in mitre))
    tags = rule.get("tags", [])
    techniques = []
    for tag in tags:
        m = re.search(r't(\d{4}(?:\.\d{3})?)', str(tag), re.IGNORECASE)
        if m:
            techniques.append(f"T{m.group(1).upper()}")
    return sorted(set(techniques))


# ── Scoring (inline — avoids circular import) ──────────────────────────────

def _load_test_cases(stem: str) -> list[dict]:
    test_file = TESTS_DIR / f"{stem}.json"
    if not test_file.exists():
        return []
    try:
        with open(test_file) as f:
            return json.load(f)
    except Exception:
        return []


def compute_score(rule: dict) -> int:
    """Compute a 0-100 quality score for a rule."""
    score = 0
    stem = rule.get("_stem", "")

    # 1. Test Coverage (0-25)
    test_cases = _load_test_cases(stem)
    if test_cases:
        score += 10
        if any(c.get("expected_match", True) for c in test_cases):
            score += 8
        if any(not c.get("expected_match", True) for c in test_cases):
            score += 7

    # 2. Backend Coverage (0-20)
    has_splunk = bool(
        (rule.get("search") or "").strip() or
        (rule.get("detection", {}) or {}).get("raw_query", "")
    )
    has_sentinel = bool((rule.get("kql_search") or "").strip())
    if has_splunk:
        score += 10
    if has_sentinel:
        score += 10

    # 3. Documentation (0-20)
    for field in ["description", "falsepositives", "how_to_implement", "data_source"]:
        val = rule.get(field)
        if val and str(val).strip().lower() not in ("none", "unknown", "todo", "tbd", "n/a"):
            score += 5

    # 4. MITRE Mapping (0-15)
    techniques = extract_techniques(rule)
    if techniques:
        score += 8
        if any("." in t for t in techniques):
            score += 4
        if len(techniques) > 1:
            score += 3

    # 5. Promotion Status (0-20)
    status_scores = {"stable": 20, "test": 10, "experimental": 5}
    score += status_scores.get(str(rule.get("status", "")).lower(), 0)

    return min(score, 100)


def score_emoji(score: int) -> str:
    for r, emoji in SCORE_EMOJI.items():
        if score in r:
            return emoji
    return "⚪"


def build_manifest(rules: list[dict]) -> dict:
    manifest = {
        "total": len(rules),
        "by_level": defaultdict(int),
        "by_status": defaultdict(int),
        "by_tactic": defaultdict(int),
        "by_type": defaultdict(int),
        "mitre_coverage": set(),
        "rules": []
    }

    for rule in rules:
        level = rule.get("level") or rule.get("severity", "unknown")
        status = rule.get("status", "unknown")
        rule_type = rule.get("type", "detection")
        tactic = rule.get("_tactic", "unknown")
        techniques = extract_techniques(rule)
        score = compute_score(rule)

        manifest["by_level"][level] += 1
        manifest["by_status"][status] += 1
        manifest["by_tactic"][tactic] += 1
        manifest["by_type"][rule_type] += 1
        manifest["mitre_coverage"].update(techniques)

        manifest["rules"].append({
            "title": rule.get("title") or rule.get("name", ""),
            "id": str(rule.get("id", "")),
            "type": rule_type,
            "status": status,
            "level": level,
            "tactic": tactic,
            "techniques": techniques,
            "analytic_story": rule.get("analytic_story", []),
            "author": rule.get("author", ""),
            "date": str(rule.get("date") or rule.get("creation_date", "")),
            "path": rule.get("_path", ""),
            "score": score,
        })

    manifest["mitre_coverage"] = sorted(manifest["mitre_coverage"])
    for key in ["by_level", "by_status", "by_tactic", "by_type"]:
        manifest[key] = dict(manifest[key])
    return manifest


def render_markdown(manifest: dict) -> str:
    lines = []
    lines.append("# Detection Rule Inventory\n")
    lines.append(f"> Auto-generated by `scripts/inventory.py` · {manifest['total']} rules\n")

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Level | Count | | Type | Count |")
    lines.append("|-------|-------|-|------|-------|")
    levels = ["critical", "high", "medium", "low", "informational"]
    types = ["detection", "hunting", "correlation", "baseline"]
    for lv, tp in zip(levels, types):
        lc = manifest["by_level"].get(lv, 0)
        tc = manifest["by_type"].get(tp, 0)
        le = LEVEL_EMOJI.get(lv, "")
        tte = TYPE_EMOJI.get(tp, "")
        lines.append(f"| {le} {lv.capitalize()} | {lc} | | {tte} {tp.capitalize()} | {tc} |")

    # Score summary
    scores = [r["score"] for r in manifest["rules"]]
    if scores:
        avg_score = int(sum(scores) / len(scores))
        lines.append("")
        lines.append(f"**Average Rule Score:** {avg_score}/100  "
                     f"| 🟢 ≥80: {sum(1 for s in scores if s >= 80)}  "
                     f"🟡 60-79: {sum(1 for s in scores if 60 <= s < 80)}  "
                     f"🟠 40-59: {sum(1 for s in scores if 40 <= s < 60)}  "
                     f"🔴 <40: {sum(1 for s in scores if s < 40)}")

    lines.append("")
    lines.append(f"**MITRE ATT&CK Coverage:** {len(manifest['mitre_coverage'])} techniques")
    if manifest["mitre_coverage"]:
        lines.append("\n`" + "` `".join(manifest["mitre_coverage"]) + "`")
    lines.append("")

    # Rules by tactic
    lines.append("## Rules by Tactic\n")
    by_tactic = defaultdict(list)
    for rule in manifest["rules"]:
        by_tactic[rule["tactic"]].append(rule)

    for tactic in TACTIC_ORDER:
        tactic_rules = by_tactic.get(tactic, [])
        if not tactic_rules:
            continue
        lines.append(f"### {tactic.replace('_', ' ').title()} ({len(tactic_rules)})\n")
        lines.append("| ID | Title | Type | Level | Status | Score | MITRE | Date |")
        lines.append("|----|-------|------|-------|--------|-------|-------|------|")
        for r in sorted(tactic_rules, key=lambda x: x.get("level", "z")):
            le = LEVEL_EMOJI.get(r["level"], "")
            se = STATUS_EMOJI.get(r["status"], "")
            te = TYPE_EMOJI.get(r["type"], "")
            sc = r.get("score", 0)
            se_score = f"{score_emoji(sc)} {sc}/100"
            mitre = ", ".join(r["techniques"]) if r["techniques"] else "—"
            lines.append(
                f"| `{r['id']}` | [{r['title']}]({r['path']}) | "
                f"{te} {r['type']} | {le} {r['level']} | "
                f"{se} {r['status']} | {se_score} | {mitre} | {r['date']} |"
            )
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate detection rule inventory")
    parser.add_argument("--json", action="store_true", help="Output JSON manifest")
    parser.add_argument("--output", type=Path, help="Write output to file")
    args = parser.parse_args()

    config = load_config()
    rules = load_rules(config)

    if not rules:
        print("No rules found.", file=sys.stderr)
        sys.exit(0)

    manifest = build_manifest(rules)
    output = json.dumps(manifest, indent=2) if args.json else render_markdown(manifest)

    if args.output:
        args.output.write_text(output)
        print(f"Inventory written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()