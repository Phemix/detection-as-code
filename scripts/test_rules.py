#!/usr/bin/env python3
"""
test_rules.py — Run sample log test cases against detection rules.
Uses a Python SPL approximation matcher to validate that rules fire
on known-bad events and don't fire on benign events.

This is a unit test layer — fast, offline, works in CI without Splunk.
For integration testing against real Splunk, use test_rules_splunk.py.

Usage:
  python scripts/test_rules.py                        # test all rules
  python scripts/test_rules.py --rule DET-00001       # test single rule by ID
  python scripts/test_rules.py --file rules/...       # test single rule by path
  python scripts/test_rules.py --verbose              # show event detail on failure
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
TESTS_DIR = ROOT / "tests" / "sample_logs"
CONFIG_FILE = ROOT / "sigma_config.yml"

ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def load_rule(path: Path) -> dict | None:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def load_test_cases(rule_stem: str) -> list[dict]:
    test_file = TESTS_DIR / f"{rule_stem}.json"
    if not test_file.exists():
        return []
    try:
        with open(test_file) as f:
            return json.load(f)
    except Exception:
        return []


# ── SPL Approximation Matcher ─────────────────────────────────────────────
# Supports the most common SPL field matching patterns used in raw_query rules.
# This is intentionally simplified — it catches logic errors, not SPL syntax errors.

def normalize(val: str) -> str:
    """Lowercase and strip for case-insensitive matching."""
    return str(val).lower().strip()


def match_wildcard(event_val: str, pattern: str) -> bool:
    """Match a SPL wildcard pattern (* = any chars) against an event value."""
    ev = normalize(event_val)
    pat = normalize(pattern)

    if pat == "*":
        return True

    # Convert SPL wildcard to regex
    regex = re.escape(pat).replace(r"\*", ".*")
    return bool(re.search(f"^{regex}$", ev))


def field_matches(event: dict, field: str, pattern: str) -> bool:
    """Check if a single field=pattern condition matches the event."""
    val = event.get(field, "")
    if val is None:
        val = ""
    return match_wildcard(str(val), pattern)


def parse_spl_conditions(search: str) -> list[dict]:
    """
    Parse SPL field=value conditions from a search string.
    Returns a list of condition dicts with type and field/value info.

    Supports:
      field="value"
      field="*wildcard*"
      NOT (field="value")
      field IN ("val1","val2")
      (condition1 AND condition2)
      condition1 OR condition2
    """
    conditions = []

    # Extract field IN (...) patterns
    in_pattern = re.finditer(
        r'(\w+)\s+IN\s+\(([^)]+)\)',
        search,
        re.IGNORECASE
    )
    for m in in_pattern:
        field = m.group(1)
        values = [v.strip().strip('"\'') for v in m.group(2).split(',')]
        conditions.append({"type": "in", "field": field, "values": values})

    # Extract NOT (field="value") patterns
    not_pattern = re.finditer(
        r'NOT\s+\(([^)]+)\)',
        search,
        re.IGNORECASE
    )
    for m in not_pattern:
        inner = m.group(1)
        inner_conditions = _parse_field_equals(inner)
        for ic in inner_conditions:
            ic["negated"] = True
            conditions.append(ic)

    # Extract field="value" patterns (not already in NOT blocks)
    # Remove NOT blocks first to avoid double-matching
    search_clean = re.sub(r'NOT\s*\([^)]+\)', '', search, flags=re.IGNORECASE)
    search_clean = re.sub(r'\w+\s+IN\s*\([^)]+\)', '', search_clean, flags=re.IGNORECASE)
    conditions += _parse_field_equals(search_clean)

    return conditions


def _parse_field_equals(text: str) -> list[dict]:
    """Extract field="value" pairs from text."""
    conditions = []
    pattern = re.finditer(r'(\w+)=["\']([^"\']*)["\']', text)
    for m in pattern:
        conditions.append({
            "type": "equals",
            "field": m.group(1),
            "value": m.group(2),
            "negated": False
        })
    return conditions


def evaluate_rule(rule: dict, event: dict) -> bool:
    """
    Evaluate whether a rule's search logic matches an event.
    Uses simplified SPL approximation — sufficient for unit testing.
    """
    search = rule.get("search", "")
    if not search:
        detection = rule.get("detection", {})
        if isinstance(detection, dict):
            search = detection.get("raw_query", "")

    if not search:
        return False

    conditions = parse_spl_conditions(str(search))

    if not conditions:
        # No parseable conditions — can't evaluate
        return False

    # Evaluate each condition
    positive_results = []
    negative_results = []

    for cond in conditions:
        if cond.get("negated"):
            # NOT condition — must NOT match
            if cond["type"] == "equals":
                match = field_matches(event, cond["field"], cond["value"])
                negative_results.append(match)
        elif cond["type"] == "in":
            # Field IN (val1, val2) — any value matches
            match = any(
                match_wildcard(str(event.get(cond["field"], "")), v)
                for v in cond["values"]
            )
            positive_results.append(match)
        elif cond["type"] == "equals":
            match = field_matches(event, cond["field"], cond["value"])
            positive_results.append(match)

    # Rule fires if:
    # - At least one positive condition matches
    # - No negative (NOT) conditions match
    if not positive_results and not negative_results:
        return False

    positive_pass = any(positive_results) if positive_results else True
    negative_pass = not any(negative_results) if negative_results else True

    return positive_pass and negative_pass


def run_rule_tests(
    rule_path: Path,
    verbose: bool = False
) -> tuple[int, int, int]:
    """
    Run test cases for a single rule.
    Returns (passed, failed, skipped).
    """
    rule = load_rule(rule_path)
    if not rule:
        return 0, 0, 1

    test_cases = load_test_cases(rule_path.stem)

    if not test_cases:
        return 0, 0, 1  # skipped — no test cases

    title = rule.get("title", rule_path.stem)
    rule_id = rule.get("id", "")
    print(f"\n  {title} ({rule_id})")

    passed = failed = 0

    for case in test_cases:
        event = case.get("event", {})
        expected = case.get("expected_match", True)
        description = case.get("description", "unnamed test")

        actual = evaluate_rule(rule, event)

        if actual == expected:
            print(f"    {ANSI_GREEN}✓{ANSI_RESET}  {description}")
            passed += 1
        else:
            expected_str = "FIRE" if expected else "NO FIRE"
            actual_str = "FIRE" if actual else "NO FIRE"
            print(f"    {ANSI_RED}✗{ANSI_RESET}  {description}")
            print(f"       Expected: {expected_str}  Got: {actual_str}")
            if verbose:
                print(f"       Event: {json.dumps(event, indent=2)}")
            failed += 1

    return passed, failed, 0


def collect_rules(config: dict, single_file: Path | None = None, rule_id: str | None = None) -> list[Path]:
    if single_file:
        return [single_file.resolve()]

    paths = []
    for d in config.get("rule_dirs", []):
        rule_dir = ROOT / d
        if rule_dir.exists():
            paths.extend(sorted(rule_dir.glob("*.yml")))

    if rule_id:
        # Filter to the specific rule ID
        filtered = []
        for p in paths:
            rule = load_rule(p)
            if rule and str(rule.get("id", "")) == rule_id:
                filtered.append(p)
        return filtered

    return paths


def main():
    parser = argparse.ArgumentParser(description="Run detection rule test cases")
    parser.add_argument("--rule", help="Rule ID to test (e.g. DET-00001)")
    parser.add_argument("--file", type=Path, help="Rule file to test")
    parser.add_argument("--verbose", action="store_true", help="Show event detail on failure")
    args = parser.parse_args()

    config = load_config()
    paths = collect_rules(config, args.file, args.rule)

    if not paths:
        print("No rule files found.")
        sys.exit(0)

    print(f"\n{ANSI_BOLD}Detection Rule Test Runner{ANSI_RESET}  ({len(paths)} rules)\n")

    total_passed = total_failed = total_skipped = 0

    for path in paths:
        passed, failed, skipped = run_rule_tests(path, args.verbose)
        total_passed += passed
        total_failed += failed
        total_skipped += skipped

    print(f"\n{'─'*55}")
    print(f"  Rules:    {len(paths)}")
    print(f"  Passed:   {ANSI_GREEN}{total_passed}{ANSI_RESET}")
    print(f"  Failed:   {ANSI_RED}{total_failed}{ANSI_RESET}" if total_failed else f"  Failed:   {total_failed}")
    print(f"  Skipped:  {ANSI_YELLOW}{total_skipped}{ANSI_RESET} (no test cases)")

    if total_skipped > 0:
        print(f"\n  {ANSI_YELLOW}Tip:{ANSI_RESET} Add test cases to tests/sample_logs/<rule_stem>.json")

    if total_failed > 0:
        print(f"\n{ANSI_RED}✗ Tests failed{ANSI_RESET}\n")
        sys.exit(1)
    elif total_passed == 0:
        print(f"\n{ANSI_YELLOW}⚠ No tests ran — add test cases to get coverage{ANSI_RESET}\n")
        sys.exit(0)
    else:
        print(f"\n{ANSI_GREEN}✓ All tests passed{ANSI_RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
