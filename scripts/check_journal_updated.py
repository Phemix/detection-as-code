#!/usr/bin/env python3
"""
check_journal_updated.py — CI guard: fail a PR that touches rules/**
without a matching update under journal/{rule_id}.md.

A rule's journal is its durable memory (origin, tuning history, known
false positives, review status). This check keeps that memory honest —
a PR template field is easy to skip, a failing check isn't.

Usage:
  python scripts/check_journal_updated.py --base origin/main
"""

import argparse
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
JOURNAL_DIR = ROOT / "journal"


def changed_files(base: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-status", f"{base}...HEAD"],
        capture_output=True, text=True, cwd=str(ROOT), check=True,
    )
    files = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status, path = parts[0], parts[-1]
        files.append((status, path))
    return files


def rule_id_for(path: Path) -> str:
    try:
        rule = yaml.safe_load(path.read_text())
    except Exception:
        rule = None
    if rule and rule.get("id"):
        return str(rule["id"]).strip()
    return path.stem


def main():
    parser = argparse.ArgumentParser(description="Fail PRs that change rules/ without a matching journal update")
    parser.add_argument("--base", default="origin/main", help="Base ref to diff against")
    args = parser.parse_args()

    changed = changed_files(args.base)

    changed_rule_files = [
        (status, path) for status, path in changed
        if path.startswith("rules/") and path.endswith(".yml") and status != "D"
    ]
    changed_journal_paths = {
        path for status, path in changed
        if path.startswith("journal/") and path.endswith(".md")
    }

    if not changed_rule_files:
        print("No rule files changed — journal check skipped.")
        return 0

    missing = []
    for status, path in changed_rule_files:
        rule_path = ROOT / path
        if not rule_path.exists():
            continue
        rid = rule_id_for(rule_path)
        expected_journal = f"journal/{rid}.md"
        if expected_journal not in changed_journal_paths:
            missing.append((path, rid, expected_journal))

    if missing:
        print("Rule journal check FAILED\n")
        for path, rid, expected in missing:
            print(f"  {path} ({rid}) changed, but {expected} was not updated in this PR.")
        print(
            "\nEvery rule change needs a journal entry recording what changed and why.\n"
            "Copy journal/rule-journal-template.md to the path above and fill it in\n"
            "(or append a new dated entry under Tuning History if the journal already exists)."
        )
        return 1

    print(f"Rule journal check passed — {len(changed_rule_files)} rule(s), all journaled.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
