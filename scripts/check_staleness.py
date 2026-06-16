#!/usr/bin/env python3
"""
check_staleness.py — Warn on rules that have been experimental or test
for longer than the configured threshold without being promoted.

Runs as a CI check on push to main. Does NOT fail the pipeline —
outputs a warning report only. The decision to promote is always manual.

Usage:
  python scripts/check_staleness.py
  python scripts/check_staleness.py --days 14     # custom threshold
  python scripts/check_staleness.py --fail        # fail CI if stale rules found
"""

import argparse
import sys
from datetime import date, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
CONFIG_FILE = ROOT / "sigma_config.yml"

ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"

PROMOTABLE_STATUSES = {"experimental", "test"}
DEFAULT_THRESHOLD_DAYS = 30


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def load_rule(path: Path) -> dict | None:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def parse_date(val) -> date | None:
    if not val:
        return None
    try:
        return datetime.strptime(str(val).strip(), "%Y-%m-%d").date()
    except ValueError:
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


def check_staleness(rules: list[tuple[Path, dict]], threshold_days: int) -> list[dict]:
    stale = []
    today = date.today()

    for path, rule in rules:
        status = rule.get("status", "").lower()
        if status not in PROMOTABLE_STATUSES:
            continue

        # Use modified date first, fall back to creation date
        modified = parse_date(rule.get("modified") or rule.get("modification_date"))
        created = parse_date(rule.get("date") or rule.get("creation_date"))
        reference_date = modified or created

        if not reference_date:
            continue

        age_days = (today - reference_date).days

        if age_days >= threshold_days:
            stale.append({
                "path": str(path.relative_to(ROOT)),
                "title": rule.get("title") or rule.get("name", path.stem),
                "id": str(rule.get("id", "")),
                "status": status,
                "level": rule.get("level") or rule.get("severity", "unknown"),
                "age_days": age_days,
                "reference_date": str(reference_date),
            })

    # Sort by age descending — oldest first
    return sorted(stale, key=lambda x: x["age_days"], reverse=True)


def main():
    parser = argparse.ArgumentParser(
        description="Check for stale detection rules that need promotion review"
    )
    parser.add_argument(
        "--days", type=int, default=DEFAULT_THRESHOLD_DAYS,
        help=f"Days threshold for staleness (default: {DEFAULT_THRESHOLD_DAYS})"
    )
    parser.add_argument(
        "--fail", action="store_true",
        help="Exit with code 1 if stale rules found (default: warn only)"
    )
    args = parser.parse_args()

    config = load_config()
    rules = collect_rules(config)
    stale = check_staleness(rules, args.days)

    print(f"\n{ANSI_BOLD}Promotion Staleness Check{ANSI_RESET}  "
          f"(threshold: {args.days} days  total rules: {len(rules)})\n")

    if not stale:
        print(f"  {ANSI_GREEN}✓{ANSI_RESET}  No stale rules found — all experimental/test rules "
              f"are within the {args.days}-day window.\n")
        sys.exit(0)

    print(f"  {ANSI_YELLOW}⚠{ANSI_RESET}  {len(stale)} rule(s) have been in "
          f"experimental/test status for {args.days}+ days:\n")

    for rule in stale:
        age_str = f"{rule['age_days']} days"
        print(f"  {ANSI_YELLOW}⚠{ANSI_RESET}  [{rule['id']}] {rule['title']}")
        print(f"       Status: {rule['status']}  |  "
              f"Level: {rule['level']}  |  "
              f"Last modified: {rule['reference_date']}  |  "
              f"Age: {age_str}")
        print(f"       File: {rule['path']}")
        print(f"       Run: make promote FILE={rule['path']}\n")

    print(f"{'─'*55}")
    print(f"  Stale rules: {ANSI_YELLOW}{len(stale)}{ANSI_RESET}")
    print(f"\n  These rules have not been promoted in {args.days}+ days.")
    print(f"  Review and either promote or document why they remain in {PROMOTABLE_STATUSES}.")
    print(f"  Run 'make promote FILE=<path>' to start the promotion checklist.\n")

    if args.fail:
        print(f"{ANSI_RED}✗ Staleness check failed{ANSI_RESET}\n")
        sys.exit(1)
    else:
        print(f"{ANSI_YELLOW}⚠ Staleness warning (pipeline not blocked){ANSI_RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()