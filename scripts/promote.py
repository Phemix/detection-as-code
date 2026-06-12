#!/usr/bin/env python3
"""
promote.py — Promote a detection rule from experimental to stable.
Runs a pre-promotion checklist and updates the rule's status and date.

Promotion requirements (all must pass):
  1. Rule currently has status: experimental or test
  2. At least 2 test cases exist (min 1 true positive, 1 true negative)
  3. All test cases pass
  4. falsepositives field is documented (not generic)
  5. how_to_implement field is present
  6. schedule block is complete (cron, earliest_time, latest_time)
  7. author field is set
  8. modified date is set

Usage:
  python scripts/promote.py --file rules/execution/my_rule.yml
  python scripts/promote.py --file rules/execution/my_rule.yml --dry-run
  python scripts/promote.py --file rules/execution/my_rule.yml --to test
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
TESTS_DIR = ROOT / "tests" / "sample_logs"

ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"

STATUS_PROGRESSION = {
    "experimental": "test",
    "test": "stable"
}


def load_rule(path: Path) -> dict | None:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def save_rule(path: Path, rule: dict) -> bool:
    try:
        with open(path, "w") as f:
            yaml.dump(rule, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        return True
    except Exception:
        return False


def load_test_cases(rule_stem: str) -> list[dict]:
    test_file = TESTS_DIR / f"{rule_stem}.json"
    if not test_file.exists():
        return []
    try:
        with open(test_file) as f:
            return json.load(f)
    except Exception:
        return []


def run_tests(rule_path: Path) -> tuple[bool, str]:
    """Run test suite for the rule and return pass/fail."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "test_rules.py"),
         "--file", str(rule_path)],
        capture_output=True, text=True
    )
    passed = result.returncode == 0
    output = result.stdout + result.stderr
    return passed, output


class PromotionChecker:
    def __init__(self):
        self.passed = []
        self.failed = []
        self.warnings = []

    def check(self, name: str, condition: bool, failure_msg: str, warning: bool = False):
        if condition:
            self.passed.append(name)
        elif warning:
            self.warnings.append(f"{name}: {failure_msg}")
        else:
            self.failed.append(f"{name}: {failure_msg}")

    @property
    def can_promote(self) -> bool:
        return len(self.failed) == 0


def run_checklist(rule: dict, rule_path: Path) -> PromotionChecker:
    checker = PromotionChecker()
    test_cases = load_test_cases(rule_path.stem)

    # 1. Status check
    current_status = rule.get("status", "")
    checker.check(
        "Status is promotable",
        current_status in ("experimental", "test"),
        f"Status is '{current_status}' — can only promote experimental or test rules"
    )

    # 2. Test cases exist
    checker.check(
        "Test cases exist",
        len(test_cases) >= 2,
        f"Only {len(test_cases)} test case(s) found — need at least 2 (1 true positive, 1 true negative). "
        f"Add to tests/sample_logs/{rule_path.stem}.json"
    )

    # 3. Has both positive and negative test cases
    if test_cases:
        has_positive = any(c.get("expected_match", True) for c in test_cases)
        has_negative = any(not c.get("expected_match", True) for c in test_cases)
        checker.check(
            "Has true positive test case",
            has_positive,
            "No true positive test case — add a case with expected_match: true"
        )
        checker.check(
            "Has true negative test case",
            has_negative,
            "No true negative (false positive) test case — add a case with expected_match: false"
        )

    # 4. Tests pass
    if len(test_cases) >= 1:
        tests_passed, test_output = run_tests(rule_path)
        checker.check(
            "All tests pass",
            tests_passed,
            f"Test failures detected — fix before promoting:\n{test_output}"
        )
    else:
        checker.check("All tests pass", False, "No test cases to run")

    # 5. Falsepositives documented
    fp = rule.get("falsepositives", [])
    is_generic = (
        not fp or
        (isinstance(fp, list) and len(fp) == 1 and
         str(fp[0]).lower() in ("none", "unknown", "todo"))
    )
    checker.check(
        "False positives documented",
        not is_generic,
        "falsepositives is empty or generic — document specific known FP scenarios"
    )

    # 6. how_to_implement present
    how_to = rule.get("how_to_implement", "").strip()
    checker.check(
        "how_to_implement documented",
        len(how_to) > 20,
        "how_to_implement is missing or too short — document required data sources and setup"
    )

    # 7. Schedule complete
    schedule = rule.get("schedule", {})
    has_cron = bool(schedule.get("cron") or schedule.get("every")) if isinstance(schedule, dict) else False
    has_earliest = bool(schedule.get("earliest_time")) if isinstance(schedule, dict) else False
    has_latest = bool(schedule.get("latest_time")) if isinstance(schedule, dict) else False
    checker.check(
        "Schedule complete",
        has_cron and has_earliest and has_latest,
        "schedule block missing cron/every, earliest_time, or latest_time"
    )

    # 8. Author set
    checker.check(
        "Author set",
        bool(str(rule.get("author", "")).strip()),
        "author field is empty"
    )

    # 9. Description length
    desc = str(rule.get("description", "")).strip()
    checker.check(
        "Description is substantive",
        len(desc) >= 80,
        f"Description is short ({len(desc)} chars) — expand to at least 80 chars",
        warning=True
    )

    # 10. data_source documented
    checker.check(
        "Data source documented",
        bool(rule.get("data_source") or rule.get("logsource")),
        "data_source or logsource not documented",
        warning=True
    )

    return checker


def promote_rule(rule_path: Path, target_status: str | None, dry_run: bool) -> bool:
    rule_path = rule_path.resolve()
    rule = load_rule(rule_path)

    if not rule:
        print(f"{ANSI_RED}Failed to load rule: {rule_path}{ANSI_RESET}")
        return False

    title = rule.get("title", rule_path.stem)
    rule_id = rule.get("id", "")
    current_status = rule.get("status", "unknown")

    print(f"\n{ANSI_BOLD}Promotion Checklist{ANSI_RESET}")
    print(f"  Rule:    {title}")
    print(f"  ID:      {rule_id}")
    print(f"  Current: {current_status}")

    # Determine target status
    if target_status:
        next_status = target_status
    else:
        next_status = STATUS_PROGRESSION.get(current_status)
        if not next_status:
            print(f"\n{ANSI_RED}Cannot promote '{current_status}' rules.{ANSI_RESET}")
            print(f"  Only 'experimental' → 'test' → 'stable' progression is supported.")
            return False

    print(f"  Target:  {next_status}\n")

    # Run checklist
    checker = run_checklist(rule, rule_path)

    # Print results
    for item in checker.passed:
        print(f"  {ANSI_GREEN}✓{ANSI_RESET}  {item}")

    for item in checker.warnings:
        print(f"  {ANSI_YELLOW}⚠{ANSI_RESET}  {item}")

    for item in checker.failed:
        print(f"  {ANSI_RED}✗{ANSI_RESET}  {item}")

    print(f"\n{'─'*55}")

    if not checker.can_promote:
        print(f"\n{ANSI_RED}✗ Promotion blocked — fix the failures above first.{ANSI_RESET}\n")
        return False

    if checker.warnings:
        print(f"\n{ANSI_YELLOW}⚠ Warnings present — promotion allowed but address these soon.{ANSI_RESET}")

    if dry_run:
        print(f"\n{ANSI_YELLOW}[dry-run] Would promote: {current_status} → {next_status}{ANSI_RESET}")
        print(f"[dry-run] Would update modified date to: {date.today().isoformat()}\n")
        return True

    # Apply promotion
    rule["status"] = next_status
    rule["modified"] = date.today().isoformat()

    if not save_rule(rule_path, rule):
        print(f"\n{ANSI_RED}Failed to write updated rule file.{ANSI_RESET}\n")
        return False

    print(f"\n{ANSI_GREEN}✓ Promoted: {current_status} → {next_status}{ANSI_RESET}")
    print(f"  Modified date updated to: {date.today().isoformat()}")
    print(f"\n  Next steps:")
    print(f"    git add {rule_path.relative_to(ROOT)}")
    print(f"    git commit -m 'promote({rule_id}): {current_status} -> {next_status}'")
    print(f"    git push\n")

    return True


def main():
    parser = argparse.ArgumentParser(description="Promote a detection rule to the next status")
    parser.add_argument("--file", type=Path, required=True, help="Rule file to promote")
    parser.add_argument("--to", dest="target", help="Target status (test or stable). Default: next in sequence")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen without changing the file")
    args = parser.parse_args()

    if not args.file.exists():
        print(f"{ANSI_RED}Rule file not found: {args.file}{ANSI_RESET}")
        sys.exit(1)

    success = promote_rule(args.file, args.target, args.dry_run)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
