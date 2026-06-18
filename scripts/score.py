#!/usr/bin/env python3
"""
score.py — Detection rule quality scoring system.

Scores each rule on a 0-100 scale across five dimensions:
  1. Test Coverage     (0-25)  — test files, TP/TN cases
  2. Backend Coverage  (0-20)  — Splunk, Sentinel, or both
  3. Documentation     (0-20)  — description, falsepositives, how_to_implement, data_source
  4. MITRE Mapping     (0-15)  — technique presence, sub-techniques, multiple techniques
  5. Promotion Status  (0-20)  — experimental, test, stable

Score interpretation:
  80-100 → Production ready
  60-79  → Good, minor gaps
  40-59  → Needs work before stable
  0-39   → Early stage, do not promote

CI warns on any rule scoring below 60. Does NOT fail the pipeline.

Usage:
  python scripts/score.py                        # score all rules
  python scripts/score.py --rule DET-00001       # score single rule by ID
  python scripts/score.py --file rules/...       # score single rule by path
  python scripts/score.py --threshold 60         # custom warning threshold
  python scripts/score.py --fail                 # fail CI if any rule below threshold
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
CONFIG_FILE = ROOT / "sigma_config.yml"
TESTS_DIR = ROOT / "tests" / "sample_logs"

ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_BLUE = "\033[34m"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"

DEFAULT_THRESHOLD = 60

# Score weights
WEIGHTS = {
    "test_coverage": 25,
    "backend_coverage": 20,
    "documentation": 20,
    "mitre_mapping": 15,
    "promotion_status": 20,
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


def load_test_cases(rule_stem: str) -> list[dict]:
    test_file = TESTS_DIR / f"{rule_stem}.json"
    if not test_file.exists():
        return []
    try:
        with open(test_file) as f:
            return json.load(f)
    except Exception:
        return []


def collect_rules(
    config: dict,
    single_file: Path | None = None,
    rule_id: str | None = None
) -> list[Path]:
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


# ── Scoring Functions ─────────────────────────────────────────────────────

def score_test_coverage(rule: dict, path: Path) -> tuple[int, list[str]]:
    """Score test coverage (0-25)."""
    points = 0
    breakdown = []
    max_pts = WEIGHTS["test_coverage"]

    test_cases = load_test_cases(path.stem)

    if not test_cases:
        breakdown.append(f"  ✗  No test file found (tests/sample_logs/{path.stem}.json)")
        return 0, breakdown

    points += 10
    breakdown.append(f"  ✓  Test file exists (+10)")

    has_tp = any(c.get("expected_match", True) for c in test_cases)
    has_tn = any(not c.get("expected_match", True) for c in test_cases)

    if has_tp:
        points += 8
        breakdown.append(f"  ✓  True positive test cases present (+8)")
    else:
        breakdown.append(f"  ✗  No true positive test cases")

    if has_tn:
        points += 7
        breakdown.append(f"  ✓  True negative test cases present (+7)")
    else:
        breakdown.append(f"  ✗  No true negative test cases")

    return min(points, max_pts), breakdown


def score_backend_coverage(rule: dict) -> tuple[int, list[str]]:
    """Score backend coverage (0-20)."""
    points = 0
    breakdown = []

    has_splunk = bool(rule.get("search", "").strip() if rule.get("search") else
                      (rule.get("detection", {}) or {}).get("raw_query", ""))
    has_sentinel = bool((rule.get("kql_search") or "").strip())

    if has_splunk:
        points += 10
        breakdown.append("  ✓  Splunk (SPL) search defined (+10)")
    else:
        breakdown.append("  ✗  No Splunk search defined")

    if has_sentinel:
        points += 10
        breakdown.append("  ✓  Sentinel (KQL) search defined (+10)")
    else:
        breakdown.append("  ✗  No Sentinel KQL search defined")

    return points, breakdown


def score_documentation(rule: dict) -> tuple[int, list[str]]:
    """Score documentation completeness (0-20)."""
    points = 0
    breakdown = []

    checks = [
        ("description", "Description"),
        ("falsepositives", "False positives"),
        ("how_to_implement", "How to implement"),
        ("data_source", "Data source"),
    ]

    for field, label in checks:
        val = rule.get(field)
        if val and str(val).strip() and str(val).strip().lower() not in (
            "none", "unknown", "todo", "tbd", "n/a"
        ):
            points += 5
            breakdown.append(f"  ✓  {label} documented (+5)")
        else:
            breakdown.append(f"  ✗  {label} missing or placeholder")

    return points, breakdown


def score_mitre_mapping(rule: dict) -> tuple[int, list[str]]:
    """Score MITRE ATT&CK mapping quality (0-15)."""
    points = 0
    breakdown = []

    techniques = []
    mitre = rule.get("mitre", [])
    if isinstance(mitre, list):
        for t in mitre:
            t_str = str(t).strip().upper()
            if t_str.startswith("T") and len(t_str) >= 5:
                techniques.append(t_str)

    tags = rule.get("tags", [])
    for tag in tags:
        m = re.search(r't(\d{4}(?:\.\d{3})?)', str(tag), re.IGNORECASE)
        if m:
            techniques.append(f"T{m.group(1).upper()}")

    techniques = list(set(techniques))

    if not techniques:
        breakdown.append("  ✗  No MITRE technique mapped")
        return 0, breakdown

    points += 8
    breakdown.append(f"  ✓  MITRE technique(s) mapped: {', '.join(sorted(techniques))} (+8)")

    has_subtechnique = any("." in t for t in techniques)
    if has_subtechnique:
        points += 4
        breakdown.append("  ✓  Sub-technique specificity (+4)")
    else:
        breakdown.append("  ✗  No sub-technique (e.g. T1003.001 vs T1003)")

    if len(techniques) > 1:
        points += 3
        breakdown.append(f"  ✓  Multiple techniques mapped ({len(techniques)}) (+3)")

    return min(points, WEIGHTS["mitre_mapping"]), breakdown


def score_promotion_status(rule: dict) -> tuple[int, list[str]]:
    """Score promotion lifecycle status (0-20)."""
    status = str(rule.get("status", "")).lower().strip()

    status_scores = {
        "stable": (20, "  ✓  Status: stable (+20)"),
        "test": (10, "  ~  Status: test (+10)"),
        "experimental": (5, "  ~  Status: experimental (+5)"),
    }

    if status in status_scores:
        pts, msg = status_scores[status]
        return pts, [msg]
    else:
        return (0, [f"  ✗  Status: '{status}' — unrecognized or missing"])


def score_rule(rule: dict, path: Path) -> dict:
    """Score a rule across all dimensions. Returns full scoring report."""
    tc_pts, tc_bd = score_test_coverage(rule, path)
    bc_pts, bc_bd = score_backend_coverage(rule)
    doc_pts, doc_bd = score_documentation(rule)
    mitre_pts, mitre_bd = score_mitre_mapping(rule)
    promo_pts, promo_bd = score_promotion_status(rule)

    total = tc_pts + bc_pts + doc_pts + mitre_pts + promo_pts

    return {
        "title": rule.get("title") or rule.get("name", path.stem),
        "id": str(rule.get("id", "")),
        "level": rule.get("level") or rule.get("severity", "unknown"),
        "status": rule.get("status", "unknown"),
        "total": total,
        "dimensions": {
            "test_coverage":    {"score": tc_pts,    "max": WEIGHTS["test_coverage"],    "breakdown": tc_bd},
            "backend_coverage": {"score": bc_pts,    "max": WEIGHTS["backend_coverage"], "breakdown": bc_bd},
            "documentation":    {"score": doc_pts,   "max": WEIGHTS["documentation"],    "breakdown": doc_bd},
            "mitre_mapping":    {"score": mitre_pts, "max": WEIGHTS["mitre_mapping"],    "breakdown": mitre_bd},
            "promotion_status": {"score": promo_pts, "max": WEIGHTS["promotion_status"], "breakdown": promo_bd},
        }
    }


def score_label(score: int, threshold: int) -> str:
    if score >= 80:
        return f"{ANSI_GREEN}Production ready{ANSI_RESET}"
    elif score >= threshold:
        return f"{ANSI_YELLOW}Good, minor gaps{ANSI_RESET}"
    elif score >= 40:
        return f"{ANSI_YELLOW}Needs work{ANSI_RESET}"
    else:
        return f"{ANSI_RED}Early stage{ANSI_RESET}"


def score_bar(score: int, width: int = 20) -> str:
    filled = int(score / 100 * width)
    empty = width - filled
    if score >= 80:
        color = ANSI_GREEN
    elif score >= 60:
        color = ANSI_YELLOW
    else:
        color = ANSI_RED
    return f"{color}{'█' * filled}{ANSI_DIM}{'░' * empty}{ANSI_RESET}"


def print_score(result: dict, verbose: bool, threshold: int) -> None:
    score = result["total"]
    below = score < threshold
    indicator = f"{ANSI_RED}⚠{ANSI_RESET}" if below else f"{ANSI_GREEN}✓{ANSI_RESET}"

    print(f"\n  {indicator}  {ANSI_BOLD}{result['title']}{ANSI_RESET} ({result['id']})")
    print(f"     {score_bar(score)}  {ANSI_BOLD}{score}/100{ANSI_RESET}  {score_label(score, threshold)}")
    print(f"     Status: {result['status']}  |  Level: {result['level']}")

    if verbose or below:
        print()
        for dim_name, dim_data in result["dimensions"].items():
            dim_label = dim_name.replace("_", " ").title()
            dim_score = dim_data["score"]
            dim_max = dim_data["max"]
            pct = int(dim_score / dim_max * 100) if dim_max > 0 else 0
            print(f"     {dim_label:<20} {dim_score:>2}/{dim_max}  ({pct}%)")
            if verbose:
                for line in dim_data["breakdown"]:
                    print(f"     {line}")


def main():
    parser = argparse.ArgumentParser(description="Score detection rules on quality dimensions")
    parser.add_argument("--rule", help="Rule ID to score (e.g. DET-00001)")
    parser.add_argument("--file", type=Path, help="Rule file to score")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help=f"Warning threshold (default: {DEFAULT_THRESHOLD})")
    parser.add_argument("--verbose", action="store_true",
                        help="Show full breakdown for every rule")
    parser.add_argument("--fail", action="store_true",
                        help="Exit with code 1 if any rule is below threshold")
    args = parser.parse_args()

    config = load_config()
    paths = collect_rules(config, args.file, args.rule)

    if not paths:
        print("No rule files found.")
        sys.exit(0)

    print(f"\n{ANSI_BOLD}Detection Rule Scorer{ANSI_RESET}  "
          f"({len(paths)} rules  |  threshold: {args.threshold}/100)\n")

    results = []
    below_threshold = []

    for path in paths:
        rule = load_rule(path)
        if not rule:
            continue
        result = score_rule(rule, path)
        results.append(result)
        if result["total"] < args.threshold:
            below_threshold.append(result)
        print_score(result, args.verbose, args.threshold)

    # Summary
    if results:
        avg = int(sum(r["total"] for r in results) / len(results))
        print(f"\n{'─'*55}")
        print(f"  Rules scored:    {len(results)}")
        print(f"  Average score:   {avg}/100")
        print(f"  Below threshold: {ANSI_YELLOW}{len(below_threshold)}{ANSI_RESET} "
              f"(< {args.threshold}/100)")

        if below_threshold:
            print(f"\n  {ANSI_YELLOW}Rules needing attention:{ANSI_RESET}")
            for r in below_threshold:
                print(f"    {r['id']}  {r['title']}  →  {r['total']}/100")

        print()

        if below_threshold and args.fail:
            print(f"{ANSI_RED}✗ Score check failed — {len(below_threshold)} rule(s) below threshold{ANSI_RESET}\n")
            sys.exit(1)
        elif below_threshold:
            print(f"{ANSI_YELLOW}⚠ Score warning — {len(below_threshold)} rule(s) below {args.threshold}/100 "
                  f"(pipeline not blocked){ANSI_RESET}\n")
            sys.exit(0)
        else:
            print(f"{ANSI_GREEN}✓ All rules meet the quality threshold{ANSI_RESET}\n")
            sys.exit(0)


if __name__ == "__main__":
    main()