#!/usr/bin/env python3
"""
validate.py — Detection-as-Code rule validation pipeline
Schema: SSC-style YAML with raw SPL in 'search' block.

Usage:
  python scripts/validate.py
  python scripts/validate.py --file rules/...
  python scripts/validate.py --strict
  python scripts/validate.py --report
"""

import argparse
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).parent.parent
CONFIG_FILE = ROOT / "sigma_config.yml"

ALLOWED_TYPES = ["detection", "hunting", "correlation", "baseline"]

ABSTRACT_SIGMA_MODIFIERS = [
    "|contains", "|endswith", "|startswith", "|re", "|all",
    "|cidr", "|windash", "|base64", "|wide", "|gt", "|gte", "|lt", "|lte"
]


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


def is_valid_id(val: str) -> bool:
    # Accept UUID v4 or DET-NNNNN format
    try:
        uuid.UUID(str(val))
        return True
    except (ValueError, AttributeError):
        pass
    return bool(re.match(r'^DET-\d{3,6}$', str(val)))


def flatten_tags(tags: Any) -> list[str]:
    if isinstance(tags, list):
        return [str(t) for t in tags]
    return []


class RuleValidator:
    def __init__(self, config: dict, strict: bool = False):
        self.config = config
        self.strict = strict
        self.val_cfg = config.get("validation", {})
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def reset(self):
        self.errors = []
        self.warnings = []

    def error(self, msg: str):
        self.errors.append(msg)

    def warn(self, msg: str):
        self.warnings.append(msg)

    def validate(self, rule: dict, path: Path) -> tuple[list[str], list[str]]:
        self.reset()
        self._check_required_fields(rule)
        self._check_id(rule)
        self._check_status(rule)
        self._check_type(rule)
        self._check_level(rule)
        self._check_mitre(rule)
        self._check_description(rule)
        self._check_data_source(rule)
        self._check_search(rule)
        self._check_schedule(rule)
        self._check_falsepositives(rule)
        self._check_author(rule)
        self._check_date(rule)
        return self.errors, self.warnings

    def _check_required_fields(self, rule: dict):
        for field in self.val_cfg.get("required_fields", []):
            if field not in rule or rule[field] is None:
                self.error(f"Missing required field: '{field}'")

    def _check_id(self, rule: dict):
        rule_id = rule.get("id")
        if rule_id and not is_valid_id(str(rule_id)):
            self.error(f"'id' must be UUID v4 or DET-NNNNN format, got: '{rule_id}'")

    def _check_status(self, rule: dict):
        status = rule.get("status")
        allowed = self.val_cfg.get("allowed_statuses", [])
        if status and allowed and status not in allowed:
            self.error(f"Invalid status '{status}'. Allowed: {allowed}")

    def _check_type(self, rule: dict):
        rule_type = str(rule.get("type", "")).lower()
        if rule_type and rule_type not in ALLOWED_TYPES:
            self.error(f"Invalid type '{rule_type}'. Allowed: {ALLOWED_TYPES}")
        if not rule_type:
            self.warn(f"No 'type' set — expected one of: {ALLOWED_TYPES}")

    def _check_level(self, rule: dict):
        level = rule.get("level") or rule.get("severity")
        allowed = self.val_cfg.get("allowed_levels", [])
        if level and allowed and str(level) not in allowed:
            self.error(f"Invalid level/severity '{level}'. Allowed: {allowed}")
        if not level:
            self.warn("No 'level' or 'severity' set")

    def _check_mitre(self, rule: dict):
        # Accept mitre: [T1059.001] or tags: [attack.t1059.001]
        mitre = rule.get("mitre", [])
        tags = flatten_tags(rule.get("tags", []))

        has_mitre_field = isinstance(mitre, list) and len(mitre) > 0
        has_tag = any(re.search(r'attack\.t\d{4}', t, re.IGNORECASE) for t in tags)

        if not has_mitre_field and not has_tag:
            self.error(
                "No MITRE technique found. Add 'mitre: [T1059.001]' "
                "or 'tags: [attack.t1059.001]'"
            )
            return

        if has_mitre_field:
            for t in mitre:
                if not re.match(r'^T\d{4}(\.\d{3})?$', str(t)):
                    self.warn(f"MITRE technique '{t}' format looks unusual — expected T1059 or T1059.001")

    def _check_description(self, rule: dict):
        desc = str(rule.get("description", "")).strip()
        min_len = self.val_cfg.get("min_description_length", 30)
        if len(desc) < min_len:
            self.warn(f"Description is short ({len(desc)} chars). Aim for >{min_len} chars.")

    def _check_data_source(self, rule: dict):
        logsource = rule.get("logsource")
        data_source = rule.get("data_source")
        if not logsource and not data_source:
            self.warn("No 'logsource' or 'data_source' — document required telemetry")

    def _check_search(self, rule: dict):
        search = rule.get("search")
        # Also accept legacy detection.raw_query
        detection = rule.get("detection", {})
        raw_query = detection.get("raw_query") if isinstance(detection, dict) else None

        if not search and not raw_query:
            self.error("Missing SPL — add a 'search: |' block with your SPL query")
            return

        query = str(search or raw_query).strip()

        if not query:
            self.error("'search' block is empty")
            return

        if "TODO" in query or "PLACEHOLDER" in query.upper():
            self.warn("'search' contains a placeholder — replace before deploying")

        if len(query) < 10:
            self.warn("'search' looks very short — verify this is a complete SPL query")

        for modifier in ABSTRACT_SIGMA_MODIFIERS:
            if modifier in query:
                self.error(
                    f"Abstract Sigma modifier '{modifier}' found in search. "
                    f"Raw SPL only — remove abstract Sigma syntax."
                )

    def _check_schedule(self, rule: dict):
        schedule = rule.get("schedule")
        if not schedule:
            self.warn("No 'schedule' — add cron/every, earliest_time, latest_time for deployment")
            return
        if isinstance(schedule, dict):
            if not schedule.get("cron") and not schedule.get("every"):
                self.warn("'schedule' missing 'cron' or 'every' field")
            if not schedule.get("earliest_time"):
                self.warn("'schedule.earliest_time' not set — e.g. '-15m'")
            if not schedule.get("latest_time"):
                self.warn("'schedule.latest_time' not set — e.g. 'now'")

    def _check_falsepositives(self, rule: dict):
        fp = rule.get("falsepositives") or rule.get("known_false_positives")
        if not fp:
            self.warn("'falsepositives' is empty — document known FP scenarios")
        elif isinstance(fp, list) and len(fp) == 1 and str(fp[0]).lower() in ("none", "unknown"):
            self.warn("'falsepositives' is generic — add specific patterns")

    def _check_author(self, rule: dict):
        if not str(rule.get("author", "")).strip():
            self.warn("'author' is empty")

    def _check_date(self, rule: dict):
        date = rule.get("date") or rule.get("creation_date")
        if date and not re.match(r'^\d{4}-\d{2}-\d{2}$', str(date)):
            self.warn(f"'date' format should be YYYY-MM-DD, got: '{date}'")


def collect_rules(config: dict, single_file: Path | None = None) -> list[Path]:
    if single_file:
        return [single_file]
    paths = []
    for d in config.get("rule_dirs", []):
        rule_dir = ROOT / d
        if rule_dir.exists():
            paths.extend(sorted(rule_dir.glob("*.yml")))
    return paths


def check_duplicates(rules: list[tuple[Path, dict]]) -> list[str]:
    issues = []
    seen_ids: dict[str, Path] = {}
    seen_titles: dict[str, Path] = {}
    for path, rule in rules:
        rule_id = str(rule.get("id", ""))
        title = str(rule.get("title") or rule.get("name", ""))
        if rule_id and rule_id in seen_ids:
            issues.append(f"Duplicate ID '{rule_id}': {seen_ids[rule_id].name} and {path.name}")
        elif rule_id:
            seen_ids[rule_id] = path
        if title and title in seen_titles:
            issues.append(f"Duplicate title '{title}': {seen_titles[title].name} and {path.name}")
        elif title:
            seen_titles[title] = path
    return issues


def format_result(path: Path, errors: list, warnings: list) -> str:
    rel = path.relative_to(ROOT)
    if not errors and not warnings:
        return f"  \033[32m✓\033[0m  {rel}"
    lines = [f"  \033[31m✗\033[0m  {rel}" if errors else f"  \033[33m⚠\033[0m  {rel}"]
    for e in errors:
        lines.append(f"       \033[31mERROR\033[0m  {e}")
    for w in warnings:
        lines.append(f"       \033[33mWARN\033[0m   {w}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Detection rule validator — SSC-style schema")
    parser.add_argument("--file", type=Path, help="Validate a single rule file")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    parser.add_argument("--report", action="store_true", help="Write JSON report to disk")
    args = parser.parse_args()

    config = load_config()
    paths = collect_rules(config, args.file)

    if not paths:
        print("No rule files found.")
        sys.exit(0)

    print(f"\n\033[1mDetection-as-Code Validator\033[0m  ({len(paths)} rules)\n")

    validator = RuleValidator(config, strict=args.strict)
    loaded: list[tuple[Path, dict]] = []
    results = []
    total_errors = 0
    total_warnings = 0

    for path in paths:
        rule, parse_err = load_rule(path)
        if parse_err:
            print(f"  \033[31m✗\033[0m  {path.name}")
            print(f"       \033[31mERROR\033[0m  {parse_err}")
            total_errors += 1
            results.append({"file": str(path), "errors": [parse_err], "warnings": []})
            continue

        errors, warnings = validator.validate(rule, path)
        loaded.append((path, rule))
        total_errors += len(errors)
        total_warnings += len(warnings)
        results.append({
            "file": str(path.relative_to(ROOT)),
            "title": rule.get("title") or rule.get("name", ""),
            "id": str(rule.get("id", "")),
            "level": rule.get("level") or rule.get("severity", ""),
            "errors": errors,
            "warnings": warnings,
            "passed": len(errors) == 0
        })
        print(format_result(path, errors, warnings))

    dup_issues = check_duplicates(loaded)
    if dup_issues:
        print("\n\033[1mDuplicate check:\033[0m")
        for issue in dup_issues:
            print(f"  \033[31mERROR\033[0m  {issue}")
        total_errors += len(dup_issues)

    print(f"\n{'─'*55}")
    print(f"  Rules:    {len(paths)}")
    print(f"  Errors:   \033[31m{total_errors}\033[0m" if total_errors else f"  Errors:   {total_errors}")
    print(f"  Warnings: \033[33m{total_warnings}\033[0m" if total_warnings else f"  Warnings: {total_warnings}")

    if args.report:
        report = {
            "summary": {"total": len(paths), "errors": total_errors, "warnings": total_warnings},
            "rules": results
        }
        with open("validation_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print("  Report:   validation_report.json")

    if total_errors > 0 or (args.strict and total_warnings > 0):
        print(f"\n\033[31m✗ Validation failed\033[0m\n")
        sys.exit(1)
    else:
        print(f"\n\033[32m✓ All rules passed validation\033[0m\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
