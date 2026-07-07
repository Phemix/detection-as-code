#!/usr/bin/env python3
"""
ai_review.py — AI-powered detection rule review using Claude.

Reviews changed detection rules on PRs and posts structured feedback
covering detection logic, MITRE mapping, false positive analysis,
test coverage gaps, and suggested improvements.

Usage:
  python scripts/ai_review.py --file rules/credential_access/lsass.yml
  python scripts/ai_review.py --files "rules/file1.yml rules/file2.yml"
  python scripts/ai_review.py --file rules/... --output markdown
  python scripts/ai_review.py --file rules/... --dry-run

Environment variables:
  ANTHROPIC_API_KEY  — required for API calls
  GITHUB_OUTPUT      — set by GitHub Actions for step outputs
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent

ANSI_GREEN  = "\033[32m"
ANSI_RED    = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_BLUE   = "\033[34m"
ANSI_RESET  = "\033[0m"
ANSI_BOLD   = "\033[1m"

MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 2048

REVIEW_PROMPT = """You are a senior detection engineer reviewing a detection rule for a Detection-as-Code pipeline.

Review the following YAML detection rule and provide structured, actionable feedback.

<rule>
{rule_content}
</rule>

Provide your review in the following format:

## Detection Logic
Analyze the SPL or KQL search block. Is the logic sound? Are there edge cases that could cause misses or false positives? Is the field selection appropriate for the data source?

## MITRE ATT&CK Mapping
Does the MITRE technique mapping accurately reflect what the detection covers? Are there additional techniques or sub-techniques that should be included?

## False Positive Analysis
Based on the falsepositives field and the search logic, what legitimate activity could trigger this rule? Are the existing exclusions sufficient? What additional NOT filters or conditions would improve precision?

## Test Coverage
Review the detection logic and assess what test cases should exist. Are there true positive scenarios not covered? Are there true negative (known-good) scenarios that should be explicitly tested?

## Suggested Improvements
Provide 2-3 specific, actionable improvements to the rule. Focus on detection quality, not style. Each suggestion should include the specific change to make.

## Overall Assessment
Rate the rule: READY_FOR_PROMOTION, NEEDS_MINOR_WORK, or NEEDS_SIGNIFICANT_WORK
Provide one sentence explaining the rating.

Keep feedback concise and technical. Avoid generic advice — be specific to this rule's logic and context."""


def load_rule(path: Path) -> tuple[dict | None, str]:
    """Load a YAML rule file. Returns (rule_dict, raw_content)."""
    try:
        content = path.read_text()
        rule = yaml.safe_load(content)
        return rule, content
    except Exception as e:
        return None, str(e)


def call_claude(rule_content: str, api_key: str) -> str:
    """Call the Anthropic API and return the review text."""
    payload = {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "messages": [
            {
                "role": "user",
                "content": REVIEW_PROMPT.format(rule_content=rule_content)
            }
        ]
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["content"][0]["text"]
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        raise RuntimeError(f"API error {e.code}: {error_body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection error: {e.reason}")


def format_pr_comment(rule_path: Path, rule: dict, review: str) -> str:
    """Format the review as a GitHub PR comment."""
    title = rule.get("title", rule_path.stem)
    rule_id = rule.get("id", "unknown")
    level = rule.get("level") or rule.get("severity", "unknown")
    status = rule.get("status", "unknown")

    # Extract overall assessment for the header
    assessment = "UNKNOWN"
    if "READY_FOR_PROMOTION" in review:
        assessment = "✅ READY_FOR_PROMOTION"
        assessment_color = "green"
    elif "NEEDS_MINOR_WORK" in review:
        assessment = "🟡 NEEDS_MINOR_WORK"
        assessment_color = "yellow"
    elif "NEEDS_SIGNIFICANT_WORK" in review:
        assessment = "🔴 NEEDS_SIGNIFICANT_WORK"
        assessment_color = "red"
    else:
        assessment = "⚪ REVIEW_COMPLETE"
        assessment_color = "gray"

    comment = f"""## 🤖 AI Detection Rule Review

**Rule:** `{rule_id}` — {title}
**Severity:** {level} | **Status:** {status} | **Assessment:** {assessment}

---

{review}

---
*Review generated by Claude ({MODEL}) via the Detection-as-Code AI review pipeline.*
*This is an automated review — use your judgment before acting on suggestions.*"""

    return comment


def format_terminal_output(rule_path: Path, rule: dict, review: str) -> str:
    """Format the review for terminal output."""
    title = rule.get("title", rule_path.stem)
    rule_id = rule.get("id", "unknown")

    output = f"\n{ANSI_BOLD}AI Review: {title} ({rule_id}){ANSI_RESET}\n"
    output += "─" * 60 + "\n"
    output += review
    output += "\n"
    return output


def post_github_comment(comment: str, github_output: str) -> None:
    """Write PR comment content to GitHub Actions output."""
    # Write to GITHUB_OUTPUT for use in subsequent workflow steps
    with open(github_output, "a") as f:
        # Use heredoc syntax for multiline values
        delimiter = "EOF_REVIEW"
        f.write(f"review_comment<<{delimiter}\n")
        f.write(comment)
        f.write(f"\n{delimiter}\n")


def review_rule(
    rule_path: Path,
    api_key: str,
    output_format: str = "terminal",
    dry_run: bool = False
) -> tuple[bool, str]:
    """
    Review a single rule file.
    Returns (success, review_text).
    """
    rule, content = load_rule(rule_path)
    if not rule:
        return False, f"Failed to load rule: {content}"

    title = rule.get("title", rule_path.stem)
    rule_id = rule.get("id", "unknown")

    print(f"  Reviewing: {title} ({rule_id})...", end=" ", flush=True)

    if dry_run:
        print(f"{ANSI_YELLOW}[dry-run]{ANSI_RESET}")
        mock_review = f"""## Detection Logic
[dry-run] Would analyze the detection logic here.

## Overall Assessment
NEEDS_MINOR_WORK — dry run mode, no actual review performed."""
        if output_format == "markdown":
            return True, format_pr_comment(rule_path, rule, mock_review)
        return True, format_terminal_output(rule_path, rule, mock_review)

    try:
        review = call_claude(content, api_key)
        print(f"{ANSI_GREEN}✓{ANSI_RESET}")

        if output_format == "markdown":
            return True, format_pr_comment(rule_path, rule, review)
        return True, format_terminal_output(rule_path, rule, review)

    except RuntimeError as e:
        print(f"{ANSI_RED}✗{ANSI_RESET}")
        return False, f"API call failed: {e}"


def main():
    parser = argparse.ArgumentParser(description="AI-powered detection rule review")
    parser.add_argument("--file", type=Path, help="Single rule file to review")
    parser.add_argument("--files", help="Space-separated list of rule files")
    parser.add_argument(
        "--output",
        choices=["terminal", "markdown"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview without calling API")
    args = parser.parse_args()

    # Get API key
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key and not args.dry_run:
        print(f"{ANSI_RED}✗{ANSI_RESET}  ANTHROPIC_API_KEY environment variable not set.")
        print("  Use --dry-run to preview without an API key.")
        sys.exit(1)

    # Collect rule files to review
    rule_paths = []
    if args.file:
        rule_paths = [args.file]
    elif args.files:
        rule_paths = [Path(f) for f in args.files.split() if f.strip()]
    else:
        print("No rule files specified. Use --file or --files.")
        sys.exit(1)

    # Filter to only existing YAML files
    rule_paths = [p for p in rule_paths if p.exists() and p.suffix == ".yml"]

    if not rule_paths:
        print("No valid rule files found.")
        sys.exit(0)

    print(f"\n{ANSI_BOLD}AI Detection Rule Review{ANSI_RESET}  ({len(rule_paths)} rule(s))\n")

    all_comments = []
    failed = 0

    for path in rule_paths:
        ok, result = review_rule(path, api_key, args.output, args.dry_run)
        if ok:
            all_comments.append(result)
        else:
            print(f"  {ANSI_RED}✗{ANSI_RESET}  {result}")
            failed += 1

    # Output results
    if args.output == "markdown":
        # Combine all reviews into one comment
        combined = "\n\n---\n\n".join(all_comments)

        # Write to GitHub Actions output if available
        github_output = os.environ.get("GITHUB_OUTPUT", "")
        if github_output:
            post_github_comment(combined, github_output)
            print(f"\n{ANSI_GREEN}✓{ANSI_RESET}  Review written to GITHUB_OUTPUT")
        else:
            # Print to stdout for local testing
            print("\n" + combined)
    else:
        for comment in all_comments:
            print(comment)

    print(f"\n{'─'*55}")
    print(f"  Reviewed: {len(rule_paths) - failed}")
    if failed:
        print(f"  Failed:   {ANSI_RED}{failed}{ANSI_RESET}")
        sys.exit(1)
    else:
        print(f"  {ANSI_GREEN}✓ Review complete{ANSI_RESET}\n")


if __name__ == "__main__":
    main()