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

KNOWN LIMITATIONS:
  - NOT conditions nested inside OR groups are evaluated globally.
    e.g. (ParentImage IN (...) OR NOT (CommandLine="*val*")) — the NOT
    is extracted globally rather than as part of the OR alternative.
    Test cases should avoid relying on this pattern.
  - Complex nested parentheses beyond two levels may not evaluate correctly.
  - SPL eval, stats, rex, and other commands are ignored.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
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
    """
    Match a SPL wildcard pattern against an event value.
    Normalizes backslash sequences to handle YAML double-escaping of Windows paths.
    """
    ev = normalize(event_val)
    pat = normalize(pattern)
    # Collapse any run of backslashes to a single backslash.
    # YAML double-escapes Windows paths: \\mmc.exe → \\\\mmc.exe in the string.
    pat = re.sub(r'\\+', '\\\\', pat)
    ev = re.sub(r'\\+', '\\\\', ev)
    if pat == "*":
        return True
    regex = re.escape(pat).replace(r'\*', '.*')
    return bool(re.search(f"^{regex}$", ev))


def field_val(event: dict, field: str) -> str:
    return str(event.get(field, "") or "")


def check_not_conditions(search: str, event: dict) -> bool:
    """
    Evaluate all NOT conditions in the search string.
    Returns False if the event matches any NOT condition (i.e. should be excluded).

    Handles:
      NOT field IN ("val1","val2")        — any value match → exclude
      NOT (field IN ("val1","val2"))      — any value match → exclude
      NOT (field1="v1" field2="v2")       — ALL fields must match → exclude
    """
    # NOT field IN (...)
    for m in re.finditer(r'NOT\s+(\w+)\s+IN\s+\(([^)]+)\)', search, re.IGNORECASE):
        field = m.group(1)
        values = [v.strip().strip('"\'') for v in m.group(2).split(',')]
        if any(match_wildcard(field_val(event, field), v) for v in values):
            return False

    # NOT (...) blocks
    for m in re.finditer(r'NOT\s*\(([^)]+)\)', search, re.IGNORECASE):
        inner = m.group(1)
        in_m = re.match(r'(\w+)\s+IN\s+\(([^)]+)\)', inner.strip(), re.IGNORECASE)
        if in_m:
            field = in_m.group(1)
            values = [v.strip().strip('"\'') for v in in_m.group(2).split(',')]
            if any(match_wildcard(field_val(event, field), v) for v in values):
                return False
        else:
            # All field="value" pairs in the block must match to trigger exclusion
            pairs = re.findall(r'(\w+)=["\']([^"\']*)["\']', inner)
            if pairs and all(match_wildcard(field_val(event, f), v) for f, v in pairs):
                return False

    return True


def split_or(text: str) -> list[str]:
    """Split text on OR keyword, respecting parenthesis depth."""
    parts = []
    depth = 0
    buf = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == '(':
            depth += 1
            buf.append(c)
        elif c == ')':
            depth -= 1
            buf.append(c)
        elif depth == 0 and text[i:i+2].upper() == 'OR' and (i == 0 or not text[i-1].isalnum()):
            after = text[i+2:i+3]
            if not after or not after.isalnum():
                parts.append(''.join(buf))
                buf = []
                i += 2
                continue
            else:
                buf.append(c)
        else:
            buf.append(c)
        i += 1
    if buf:
        parts.append(''.join(buf))
    return [p.strip() for p in parts if p.strip()]


def eval_clause(text: str, event: dict) -> bool:
    """
    Evaluate a flat block of SPL conditions (no nested OR).

    Semantics:
    - field IN (...): satisfied if any value matches (OR within values)
    - field="v1" field="v2" on SAME field: both must match (AND within field)
    - Conditions on DIFFERENT fields: ALL must match (AND across fields)
    """
    reqs: dict[str, list[bool]] = defaultdict(list)

    # IN conditions — OR within values, one result per field
    for m in re.finditer(r'(\w+)\s+IN\s+\(([^)]+)\)', text, re.IGNORECASE):
        field = m.group(1)
        values = [v.strip().strip('"\'') for v in m.group(2).split(',')]
        reqs[field].append(any(match_wildcard(field_val(event, field), v) for v in values))

    # field="value" pairs
    text_no_in = re.sub(r'\w+\s+IN\s*\([^)]+\)', '', text, flags=re.IGNORECASE)
    for m in re.finditer(r'(\w+)=["\']([^"\']*)["\']', text_no_in):
        field, pattern = m.group(1), m.group(2)
        reqs[field].append(match_wildcard(field_val(event, field), pattern))

    if not reqs:
        return False

    # All field requirements must be satisfied (AND across fields)
    # Within a field, all requirements must be true
    return all(all(v) for v in reqs.values())


def eval_expression(text: str, event: dict) -> bool:
    """
    Recursively evaluate an SPL expression.

    Handles:
    - Nested parentheses (recursive evaluation)
    - OR alternatives at any level
    - AND semantics across conditions and paren groups
    """
    text = text.strip()

    # Unwrap outer parens if they wrap the entire expression
    if text.startswith('(') and text.endswith(')'):
        depth = 0
        fully_wrapped = True
        for i, c in enumerate(text):
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            if depth == 0 and i < len(text) - 1:
                fully_wrapped = False
                break
        if fully_wrapped:
            text = text[1:-1].strip()

    # Split on top-level OR
    or_parts = split_or(text)
    if len(or_parts) > 1:
        return any(eval_expression(part, event) for part in or_parts)

    # No top-level OR — AND block
    # Find inner paren groups (not IN value lists) and evaluate recursively
    paren_results = []
    remaining = text

    for m in re.finditer(r'\(([^()]+)\)', text):
        before = text[:m.start()].rstrip()
        if re.search(r'\bIN\s*$', before, re.IGNORECASE):
            continue  # skip IN value lists
        paren_results.append(eval_expression(m.group(1), event))
        remaining = remaining.replace(m.group(0), ' ', 1)

    # Evaluate flat conditions outside paren groups
    flat = eval_clause(remaining, event)

    # All paren groups must pass
    if paren_results and not all(paren_results):
        return False

    # If there are flat conditions, they must also pass
    has_flat = bool(re.search(r'(\w+\s+IN\s*\(|\w+=["\'])', remaining, re.IGNORECASE))
    if has_flat and not flat:
        return False

    # If no conditions at all, don't fire
    if not paren_results and not has_flat:
        return False

    return True


def check_positive_conditions(search: str, event: dict) -> bool:
    """Clean the search and evaluate positive conditions."""
    clean = re.sub(r'NOT\s+\w+\s+IN\s*\([^)]+\)', '', search, flags=re.IGNORECASE)
    clean = re.sub(r'NOT\s*\([^)]+\)', '', clean, flags=re.IGNORECASE)
    clean = re.sub(r'\|.*', '', clean, flags=re.DOTALL)
    clean = re.sub(r'index\s*=\s*\S+', '', clean, flags=re.IGNORECASE)
    clean = re.sub(r'source\s*=\s*"[^"]*"', '', clean, flags=re.IGNORECASE)
    clean = re.sub(r'EventID\s*=\s*\d+', '', clean, flags=re.IGNORECASE)
    return eval_expression(clean, event)


def evaluate_rule(rule: dict, event: dict) -> bool:
    """
    Evaluate whether a rule's search logic matches an event.
    Phase 1: NOT conditions — if any match, rule does not fire.
    Phase 2: Positive conditions — all requirements must be met.
    """
    search = rule.get("search", "")
    if not search:
        detection = rule.get("detection", {})
        if isinstance(detection, dict):
            search = detection.get("raw_query", "")
    if not search:
        return False

    search = str(search)

    if not check_not_conditions(search, event):
        return False

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

    passed = failed = skipped = 0

    for case in test_cases:
        description = case.get("description", "unnamed test")

        # Skip cases marked as requiring Splunk replay testing
        if case.get("_skip"):
            print(f"    {ANSI_YELLOW}↷{ANSI_RESET}  {description}")
            skipped += 1
            continue

        event = case.get("event", {})
        expected = case.get("expected_match", True)
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

    return passed, failed, skipped


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