#!/usr/bin/env python3
"""
ai_debug.py — AI-powered pipeline failure debugger using Claude.

Analyzes CI pipeline failures and suggests specific fixes.
Posts results to GitHub Actions job summary.

Usage:
  python scripts/ai_debug.py --job validate --error "error output here"
  python scripts/ai_debug.py --job test --error "error output" --file rules/...
  python scripts/ai_debug.py --log-file error.log --job compile

Environment variables:
  ANTHROPIC_API_KEY  — required for API calls
  GITHUB_STEP_SUMMARY — set by GitHub Actions for job summary output
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).parent.parent

MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 1024

DEBUG_PROMPT = """You are a senior detection engineer debugging a CI/CD pipeline failure in a Detection-as-Code repository.

The following job failed:

<job>{job}</job>

<error_output>
{error}
</error_output>

{file_context}

Provide a concise debug response in this exact format — keep it under 250 words:

## 🔍 Root Cause
One sentence explaining exactly what went wrong.

## 🛠 Fix
The specific change needed to resolve this. Include exact code, field names, or commands where possible.

## 📋 Steps
1. Step one
2. Step two
(maximum 3 steps)

## ⚡ Quick Command
```bash
# The exact command to run after applying the fix
```

Rules:
- Be specific to this exact error, not generic advice
- If the fix requires editing a file, show the exact change
- If it is a known pipeline pattern (validate/test/compile/score/staleness), use that context
- Never exceed 250 words"""


def load_file_context(file_path: str) -> str:
    """Load relevant file content for context."""
    if not file_path:
        return ""
    path = Path(file_path)
    if not path.exists():
        return ""
    try:
        content = path.read_text()
        # Truncate if too long
        if len(content) > 3000:
            content = content[:3000] + "\n... (truncated)"
        return f"<relevant_file path='{file_path}'>\n{content}\n</relevant_file>"
    except Exception:
        return ""


def call_claude(prompt_text: str, api_key: str) -> str:
    """Call the Anthropic API and return the response text."""
    payload = {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "messages": [{"role": "user", "content": prompt_text}]
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
        raise RuntimeError(f"API error {e.code}: {e.read().decode()}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection error: {e.reason}")


def write_job_summary(content: str) -> None:
    """Write content to GitHub Actions job summary."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(content + "\n")
    else:
        # Local fallback — print to stdout
        print(content)


def main():
    parser = argparse.ArgumentParser(description="AI-powered pipeline failure debugger")
    parser.add_argument("--job", required=True,
                        help="Job that failed (validate/compile/test/score/staleness/deploy)")
    parser.add_argument("--error", default="",
                        help="Error output from the failed job")
    parser.add_argument("--log-file", type=Path,
                        help="Path to file containing error output")
    parser.add_argument("--file", default="",
                        help="Relevant rule or script file path for context")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview without calling API")
    args = parser.parse_args()

    # Get error content
    error_output = args.error
    if args.log_file and args.log_file.exists():
        error_output = args.log_file.read_text()
    if not error_output:
        error_output = "No error output captured."

    # Truncate if too long
    if len(error_output) > 4000:
        error_output = error_output[:4000] + "\n... (truncated)"

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key and not args.dry_run:
        write_job_summary("## 🤖 AI Debug Assistant\n⚠️ ANTHROPIC_API_KEY not set — skipping AI debug.")
        sys.exit(0)

    file_context = load_file_context(args.file)

    print(f"Running AI debug for failed job: {args.job}...", end=" ", flush=True)

    if args.dry_run:
        print("[dry-run]")
        suggestion = f"""## 🔍 Root Cause
[dry-run] Would analyze the {args.job} job failure here.

## 🛠 Fix
[dry-run] Would suggest a specific fix here.

## 📋 Steps
1. Apply the fix
2. Run the command below

## ⚡ Quick Command
```bash
make {args.job}
```"""
    else:
        try:
            prompt_text = DEBUG_PROMPT.format(
                job=args.job,
                error=error_output,
                file_context=file_context
            )
            suggestion = call_claude(prompt_text, api_key)
            print("✓")
        except RuntimeError as e:
            print("✗")
            write_job_summary(f"## 🤖 AI Debug Assistant\n❌ API error: {e}")
            sys.exit(0)  # Don't fail the pipeline if debug fails

    # Write to job summary
    summary = f"""## 🤖 AI Debug Assistant

**Failed job:** `{args.job}`

{suggestion}

---
*Suggested fix generated by Claude ({MODEL}). Review before applying.*"""

    write_job_summary(summary)
    print("Debug suggestion written to job summary.")


if __name__ == "__main__":
    main()