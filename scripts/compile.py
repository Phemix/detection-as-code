#!/usr/bin/env python3
"""
compile.py — Compile SSC-style detection rules to deployable SPL.
Reads the 'search' field and wraps with metadata comments,
schedule info, and normalized output fields.

Usage:
  python scripts/compile.py
  python scripts/compile.py --backend splunk
  python scripts/compile.py --file rules/...
  python scripts/compile.py --dry-run
"""

import argparse
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
CONFIG_FILE = ROOT / "sigma_config.yml"

ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def load_rule(path: Path) -> tuple[dict | None, str | None]:
    try:
        with open(path) as f:
            rule = yaml.safe_load(f)
        if not isinstance(rule, dict):
            return None, "File does not parse to a YAML mapping"
        return rule, None
    except yaml.YAMLError as e:
        return None, f"YAML parse error: {e}"


def extract_mitre(rule: dict) -> str:
    # Support both mitre: [T1059.001] and tags: [attack.t1059.001]
    mitre_field = rule.get("mitre", [])
    if isinstance(mitre_field, list) and mitre_field:
        return ", ".join(str(t) for t in mitre_field)

    tags = rule.get("tags", [])
    techniques = []
    for tag in tags:
        m = re.search(r't(\d{4}(?:\.\d{3})?)', str(tag), re.IGNORECASE)
        if m:
            techniques.append(f"T{m.group(1).upper()}")
    return ", ".join(sorted(set(techniques))) or "unknown"


def get_search(rule: dict) -> str:
    # Prefer 'search' field (SSC style), fall back to detection.raw_query
    search = rule.get("search", "")
    if search:
        return str(search).strip()
    detection = rule.get("detection", {})
    if isinstance(detection, dict):
        return str(detection.get("raw_query", "")).strip()
    return ""


def get_schedule_comment(rule: dict) -> str:
    schedule = rule.get("schedule")
    if not schedule or not isinstance(schedule, dict):
        return "| comment \"Schedule: not defined\""
    cron = schedule.get("cron") or schedule.get("every", "not set")
    earliest = schedule.get("earliest_time", "not set")
    latest = schedule.get("latest_time", "not set")
    return (
        f"| comment \"Schedule: {cron}  |  "
        f"earliest: {earliest}  latest: {latest}\""
    )


def compile_splunk(rule: dict, path: Path, output_dir: Path, dry_run: bool = False) -> tuple[bool, str]:
    search = get_search(rule)
    if not search:
        return False, "No SPL found in 'search' or 'detection.raw_query'"

    title = rule.get("title") or rule.get("name", path.stem)
    rule_id = str(rule.get("id", ""))
    level = rule.get("level") or rule.get("severity", "unknown")
    rule_type = rule.get("type", "detection")
    author = rule.get("author", "unknown")
    date = str(rule.get("date") or rule.get("creation_date", "unknown"))
    modified = str(rule.get("modified") or rule.get("modification_date", date))
    mitre = extract_mitre(rule)
    schedule_comment = get_schedule_comment(rule)

    compiled = f"""\
| comment "────────────────────────────────────────────"
| comment "Rule:     {title}"
| comment "ID:       {rule_id}"
| comment "Type:     {rule_type}"
| comment "Severity: {level}"
| comment "MITRE:    {mitre}"
| comment "Author:   {author}"
| comment "Created:  {date}  Modified: {modified}"
{schedule_comment}
| comment "────────────────────────────────────────────"

{search}

| eval rule_name="{title}", severity="{level}", mitre="{mitre}", rule_id="{rule_id}"
| table _time, rule_name, severity, mitre, rule_id, host, user, process, src, dest
"""

    rel = path.relative_to(ROOT / "rules")
    out_path = output_dir / rel.with_suffix(".spl")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if dry_run:
        return True, f"[dry-run] Would write: {out_path.relative_to(ROOT)}"

    out_path.write_text(compiled)
    return True, str(out_path.relative_to(ROOT))


def collect_rules(config: dict, single_file: Path | None = None) -> list[Path]:
    """rule collect"""
    if single_file:
        return [single_file]
    paths = []
    for d in config.get("rule_dirs", []):
        rule_dir = ROOT / d
        if rule_dir.exists():
            paths.extend(sorted(rule_dir.glob("*.yml")))
    return paths


def main():
    parser = argparse.ArgumentParser(description="Compile detection rules to SPL")
    parser.add_argument("--backend", default="splunk", help="Target backend (default: splunk)")
    parser.add_argument("--file", type=Path, help="Compile a single rule file")
    parser.add_argument("--dry-run", action="store_true", help="Show output without writing")
    args = parser.parse_args()

    config = load_config()
    if args.file:
        args.file = args.file.resolve()
    rules = collect_rules(config, args.file)

    if not rules:
        print("No rule files found.")
        sys.exit(0)

    backend_cfg = config.get("backends", {}).get(args.backend, {})
    output_dir = ROOT / backend_cfg.get("output_dir", f"compiled/{args.backend}")

    print(f"\n{ANSI_BOLD}Compilation Pipeline{ANSI_RESET}  ({len(rules)} rules  backend: {args.backend})\n")

    total_ok = total_fail = 0

    for path in rules:
        rule, parse_err = load_rule(path)
        if parse_err:
            print(f"  {ANSI_RED}✗{ANSI_RESET}  {path.name}")
            print(f"       {ANSI_RED}{parse_err}{ANSI_RESET}")
            total_fail += 1
            continue

        if args.backend == "splunk":
            ok, msg = compile_splunk(rule, path, output_dir, args.dry_run)
        else:
            ok, msg = False, f"Backend '{args.backend}' not yet implemented"

        if ok:
            print(f"  {ANSI_GREEN}✓{ANSI_RESET}  {path.name}  →  {msg}")
            total_ok += 1
        else:
            print(f"  {ANSI_RED}✗{ANSI_RESET}  {path.name}")
            print(f"       {ANSI_RED}{msg}{ANSI_RESET}")
            total_fail += 1

    print(f"\n{'─'*55}")
    print(f"  Compiled: {ANSI_GREEN}{total_ok}{ANSI_RESET}")
    print(f"  Failed:   {ANSI_RED}{total_fail}{ANSI_RESET}" if total_fail else f"  Failed:   {total_fail}")

    if total_fail > 0:
        print(f"\n{ANSI_RED}✗ Compilation completed with errors{ANSI_RESET}\n")
        sys.exit(1)
    else:
        print(f"\n{ANSI_GREEN}✓ All rules compiled successfully{ANSI_RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
