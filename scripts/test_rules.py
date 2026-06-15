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

def normalize(val: str) -> str:
    return str(val).lower().strip()


def match_wildcard(event_val: str, pattern: str) -> bool:
    ev = normalize(event_val)
    pat = normalize(pattern)
    # Normalize backslash sequences to single backslash
    # YAML double-escapes Windows paths (\\mmc.exe) but events have single (\mmc.exe)
    pat = re.sub(r'\\+', '\\\\', pat)
    ev = re.sub(r'\\+', '\\\\', ev)
    if pat == "*":
        return True
    regex = re.escape(pat).replace(r"\*", ".*")
    return bool(re.search(f"^{regex}$", ev))


def field_matches(event: dict, field: str, pattern: str) -> bool:
    val = event.get(field, "") or ""
    return match_wildcard(str(val), pattern)


def check_not_conditions(search: str, event: dict) -> bool:
    """
    Returns True if the event passes all NOT filters (i.e. should not be excluded).
    Returns False if any NOT condition matches (event should be excluded).

    Handles:
      NOT (field="value" field2="value2")  — all fields in block must match to exclude
      NOT field IN ("val1","val2")          — any value match excludes
      NOT (field IN ("val1","val2"))        — same
    """
    # NOT field IN (...)
    for m in re.finditer(r'NOT\s+(\w+)\s+IN\s+\(([^)]+)\)', search, re.IGNORECASE):
        field = m.group(1)
        values = [v.strip().strip('"\'') for v in m.group(2).split(',')]
        event_val = str(event.get(field, "") or "")
        if any(match_wildcard(event_val, v) for v in values):
            return False  # excluded

    # NOT (...) blocks
    for m in re.finditer(r'NOT\s*\(([^)]+)\)', search, re.IGNORECASE):
        inner = m.group(1)
        # Check if inner is an IN expression
        in_m = re.match(r'(\w+)\s+IN\s+\(([^)]+)\)', inner.strip(), re.IGNORECASE)
        if in_m:
            field = in_m.group(1)
            values = [v.strip().strip('"\'') for v in in_m.group(2).split(',')]
            event_val = str(event.get(field, "") or "")
            if any(match_wildcard(event_val, v) for v in values):
                return False
        else:
            # field="value" pairs — ALL must match to trigger exclusion
            pairs = re.findall(r'(\w+)=["\']([^"\']*)["\']', inner)
            if pairs and all(field_matches(event, f, v) for f, v in pairs):
                return False

    return True  # not excluded


def check_positive_conditions(search: str, event: dict) -> bool:
    """
    Returns True if the event matches the positive detection logic.

    Strategy: remove NOT blocks, then evaluate remaining conditions.
    Parenthesized groups connected by OR — any group matching is sufficient.
    Within a group, multiple conditions on the same field are AND-ed.
    Across fields within a group, conditions are OR-ed.
    """
    # Strip NOT blocks and pipe commands
    clean = re.sub(r'NOT\s+\w+\s+IN\s*\([^)]+\)', '', search, flags=re.IGNORECASE)
    clean = re.sub(r'NOT\s*\([^)]+\)', '', clean, flags=re.IGNORECASE)
    clean = re.sub(r'\|.*', '', clean, flags=re.DOTALL)  # strip pipe commands
    clean = re.sub(r'index\s*=\s*\S+', '', clean, flags=re.IGNORECASE)
    clean = re.sub(r'source\s*=\s*"[^"]*"', '', clean, flags=re.IGNORECASE)
    clean = re.sub(r'EventID\s*=\s*\d+', '', clean, flags=re.IGNORECASE)

    # Extract parenthesized OR groups at the top level
    # Try matching each paren group as an independent OR alternative
    paren_groups = re.findall(r'\(([^()]+)\)', clean)

    if paren_groups:
        # Each paren group is an OR alternative — if any group matches, fire
        for group in paren_groups:
            if _eval_group(group, event):
                return True
        # Also check any field conditions outside parens
        outside = re.sub(r'\([^()]+\)', '', clean)
        if outside.strip() and _eval_group(outside, event):
            return True
        return False
    else:
        # No paren groups — evaluate flat conditions
        return _eval_group(clean, event)


def _eval_group(text: str, event: dict) -> bool:
    """
    Evaluate a group of SPL conditions against an event.

    Rules:
    - field IN (...) — any value matches → True
    - field="value" — wildcard match
    - Multiple conditions on same field → AND (all must match)
    - Conditions on different fields → OR (any match is enough)
    - OR keyword between conditions → split and evaluate each side
    """
    # Handle explicit OR keyword — split into alternatives
    or_parts = re.split(r'\bOR\b', text, flags=re.IGNORECASE)
    if len(or_parts) > 1:
        return any(_eval_and_block(part, event) for part in or_parts)

    return _eval_and_block(text, event)


def _eval_and_block(text: str, event: dict) -> bool:
    """
    Evaluate a block where multiple conditions on the same field are AND-ed.
    Conditions across different fields are OR-ed.
    """
    # field IN (...) conditions
    in_matches = []
    for m in re.finditer(r'(\w+)\s+IN\s+\(([^)]+)\)', text, re.IGNORECASE):
        field = m.group(1)
        values = [v.strip().strip('"\'') for v in m.group(2).split(',')]
        event_val = str(event.get(field, "") or "")
        in_matches.append(any(match_wildcard(event_val, v) for v in values))

    # field="value" conditions — group by field, AND within same field
    text_no_in = re.sub(r'\w+\s+IN\s*\([^)]+\)', '', text, flags=re.IGNORECASE)
    pairs = re.findall(r'(\w+)=["\']([^"\']*)["\']', text_no_in)

    # Group by field
    from collections import defaultdict
    by_field = defaultdict(list)
    for field, val in pairs:
        by_field[field].append(val)

    field_matches_list = []
    for field, patterns in by_field.items():
        event_val = str(event.get(field, "") or "")
        # ALL patterns for this field must match (AND within field)
        field_matches_list.append(all(match_wildcard(event_val, p) for p in patterns))

    all_conditions = in_matches + field_matches_list

    if not all_conditions:
        return False

    # Any field group matching is sufficient (OR across fields)
    return any(all_conditions)


def evaluate_rule(rule: dict, event: dict) -> bool:
    """
    Evaluate whether a rule's search logic matches an event.
    Two-phase: check NOT conditions first, then positive conditions.
    """
    search = rule.get("search", "")
    if not search:
        detection = rule.get("detection", {})
        if isinstance(detection, dict):
            search = detection.get("raw_query", "")

    if not search:
        return False

    search = str(search)

    # Phase 1: Check NOT conditions — if any match, rule does not fire
    if not check_not_conditions(search, event):
        return False

    # Phase 2: Check positive conditions — at least one must match
    return check_positive_conditions(search, event)


def run_rule_tests(rule_path: Path, verbose: bool = False) -> tuple[int, int, int]:
    rule = load_rule(rule_path)
    if not rule:
        return 0, 0, 1

    test_cases = load_test_cases(rule_path.stem)
    if not test_cases:
        return 0, 0, 1

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