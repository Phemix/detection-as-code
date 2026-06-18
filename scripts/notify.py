#!/usr/bin/env python3
"""
notify.py — Webhook notification system for the Detection-as-Code pipeline.

Sends structured notifications to Slack (or any webhook endpoint) for:
  - CI pipeline events (deploy, test failures, stale rules, score warnings)
  - Security scan findings
  - [STUB] Splunk alert firing — wire when Splunk has real telemetry

Usage:
  python scripts/notify.py --event deploy     --status success --rules 4
  python scripts/notify.py --event test       --status failure --failed 2 --total 15
  python scripts/notify.py --event stale      --rules "DET-00001,DET-00003"
  python scripts/notify.py --event score      --rules "DET-00003" --scores "45"
  python scripts/notify.py --event security   --status warning --message "TruffleHog: potential secret in scripts/deploy_splunk.py"
  python scripts/notify.py --event pipeline   --status success --branch main --commit abc1234

Environment variables:
  WEBHOOK_URL     — Slack or generic webhook URL (required)
  WEBHOOK_TYPE    — 'slack' or 'generic' (default: slack)
  PIPELINE_URL    — Link to CI pipeline run (optional)
  REPO_NAME       — Repository name for context (optional)

# ── SPLUNK ALERT STUB ──────────────────────────────────────────────────────
# When Splunk has real telemetry, wire alert notifications like this:
#
#   python scripts/notify.py \
#     --event splunk_alert \
#     --rule-id DET-00001 \
#     --rule-title "LSASS Memory Dump via ProcDump" \
#     --severity critical \
#     --results 3 \
#     --splunk-url "https://splunk.example.com/search?q=..."
#
# Configure in Splunk: Settings → Searches → Edit Alert → Add Webhook Action
# Set webhook URL to a script endpoint or use Splunk's native webhook action.
# ──────────────────────────────────────────────────────────────────────────
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent

# ── Emoji and color maps ───────────────────────────────────────────────────

EVENT_EMOJI = {
    "deploy":        "🚀",
    "test":          "🧪",
    "stale":         "⏰",
    "score":         "📊",
    "security":      "🔐",
    "pipeline":      "⚙️",
    "splunk_alert":  "🚨",
}

STATUS_EMOJI = {
    "success": "✅",
    "failure": "❌",
    "warning": "⚠️",
    "info":    "ℹ️",
}

SEVERITY_COLOR = {
    "critical": "#da3633",
    "high":     "#d29922",
    "medium":   "#388bfd",
    "low":      "#6e7681",
    "success":  "#238636",
    "failure":  "#da3633",
    "warning":  "#d29922",
    "info":     "#388bfd",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def get_env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


# ── Slack message builders ─────────────────────────────────────────────────

def build_deploy_message(args) -> dict:
    status = args.status or "success"
    emoji = STATUS_EMOJI.get(status, "ℹ️")
    color = SEVERITY_COLOR.get(status, "#388bfd")
    rules = args.rules or "0"
    branch = args.branch or "main"
    commit = args.commit or ""
    pipeline_url = get_env("PIPELINE_URL")
    repo = get_env("REPO_NAME", "detection-as-code")

    title = f"{emoji} Detection Rules Deployed" if status == "success" else f"{emoji} Deployment Failed"
    text = f"`{rules}` rule(s) deployed to Splunk from `{branch}`"
    if commit:
        text += f" · commit `{commit[:7]}`"

    return slack_attachment(title, text, color, pipeline_url, repo)


def build_test_message(args) -> dict:
    failed = int(args.failed or 0)
    total = int(args.total or 0)
    passed = total - failed
    status = "failure" if failed > 0 else "success"
    emoji = STATUS_EMOJI.get(status, "ℹ️")
    color = SEVERITY_COLOR.get(status, "#388bfd")
    branch = args.branch or ""
    pipeline_url = get_env("PIPELINE_URL")
    repo = get_env("REPO_NAME", "detection-as-code")

    title = f"{emoji} Detection Rule Tests {'Failed' if failed > 0 else 'Passed'}"
    text = f"{passed}/{total} tests passed"
    if failed > 0:
        text += f" · *{failed} test(s) failed*"
    if branch:
        text += f" · branch `{branch}`"

    return slack_attachment(title, text, color, pipeline_url, repo)


def build_stale_message(args) -> dict:
    rules_str = args.rules or ""
    rule_list = [r.strip() for r in rules_str.split(",") if r.strip()]
    count = len(rule_list)
    color = SEVERITY_COLOR["warning"]
    pipeline_url = get_env("PIPELINE_URL")
    repo = get_env("REPO_NAME", "detection-as-code")

    title = f"⏰ Stale Rules Detected"
    text = f"{count} rule(s) have been in `experimental`/`test` status for 30+ days and may need promotion review:"
    if rule_list:
        text += "\n" + "\n".join(f"• `{r}`" for r in rule_list)
    text += "\n\nRun `make promote FILE=<path>` to start the promotion checklist."

    return slack_attachment(title, text, color, pipeline_url, repo)


def build_score_message(args) -> dict:
    rules_str = args.rules or ""
    scores_str = args.scores or ""
    rule_list = [r.strip() for r in rules_str.split(",") if r.strip()]
    score_list = [s.strip() for s in scores_str.split(",") if s.strip()]
    color = SEVERITY_COLOR["warning"]
    pipeline_url = get_env("PIPELINE_URL")
    repo = get_env("REPO_NAME", "detection-as-code")

    title = f"📊 Rules Below Quality Threshold"
    text = f"{len(rule_list)} rule(s) scored below 60/100:"
    for i, rule in enumerate(rule_list):
        score = score_list[i] if i < len(score_list) else "?"
        text += f"\n• `{rule}` — {score}/100"
    text += "\n\nRun `make score-verbose` to see the full breakdown."

    return slack_attachment(title, text, color, pipeline_url, repo)


def build_security_message(args) -> dict:
    status = args.status or "warning"
    message = args.message or "Security scan finding detected"
    color = SEVERITY_COLOR.get(status, SEVERITY_COLOR["warning"])
    pipeline_url = get_env("PIPELINE_URL")
    repo = get_env("REPO_NAME", "detection-as-code")

    emoji = STATUS_EMOJI.get(status, "⚠️")
    title = f"{emoji} Security Scan Finding"

    return slack_attachment(title, message, color, pipeline_url, repo)


def build_pipeline_message(args) -> dict:
    status = args.status or "success"
    emoji = STATUS_EMOJI.get(status, "ℹ️")
    color = SEVERITY_COLOR.get(status, "#388bfd")
    branch = args.branch or "main"
    commit = args.commit or ""
    pipeline_url = get_env("PIPELINE_URL")
    repo = get_env("REPO_NAME", "detection-as-code")

    title = f"{emoji} Pipeline {'Passed' if status == 'success' else 'Failed'}"
    text = f"Branch `{branch}`"
    if commit:
        text += f" · commit `{commit[:7]}`"

    return slack_attachment(title, text, color, pipeline_url, repo)


def build_splunk_alert_message(args) -> dict:
    """
    STUB — Wire this when Splunk has real telemetry.
    Called when a Splunk saved search fires and results > 0.
    """
    rule_id = args.rule_id or "UNKNOWN"
    rule_title = args.rule_title or "Unknown Rule"
    severity = args.severity or "medium"
    results = args.results or "1"
    splunk_url = args.splunk_url or ""
    color = SEVERITY_COLOR.get(severity, SEVERITY_COLOR["medium"])
    repo = get_env("REPO_NAME", "detection-as-code")

    severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(severity, "⚪")
    title = f"🚨 Alert Fired: {rule_title}"
    text = (
        f"{severity_emoji} *Severity:* {severity.upper()}\n"
        f"*Rule ID:* `{rule_id}`\n"
        f"*Results:* {results} event(s) matched\n"
        f"*Time:* {now_utc()}"
    )
    if splunk_url:
        text += f"\n<{splunk_url}|View in Splunk>"

    return slack_attachment(title, text, color, splunk_url, repo)


# ── Slack payload builder ──────────────────────────────────────────────────

def slack_attachment(title: str, text: str, color: str, url: str, repo: str) -> dict:
    """Build a Slack Block Kit message with attachment for color strip."""
    blocks = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{title}*\n{text}"}
        }
    ]

    footer_parts = [f"*{repo}*", now_utc()]
    if url:
        footer_parts.append(f"<{url}|View Pipeline>")

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": " · ".join(footer_parts)}]
    })

    return {
        "attachments": [{
            "color": color,
            "blocks": blocks,
            "fallback": title
        }]
    }


def build_generic_payload(args) -> dict:
    """Generic JSON payload for non-Slack webhooks (Teams, Discord, PagerDuty, etc.)"""
    event = args.event or "unknown"
    status = args.status or "info"
    return {
        "event": event,
        "status": status,
        "repository": get_env("REPO_NAME", "detection-as-code"),
        "branch": args.branch or "",
        "commit": args.commit or "",
        "timestamp": now_utc(),
        "rules": args.rules or "",
        "message": args.message or "",
        "pipeline_url": get_env("PIPELINE_URL", ""),
    }


# ── Send webhook ───────────────────────────────────────────────────────────

def send_webhook(payload: dict, webhook_url: str) -> bool:
    """Send payload to webhook URL. Returns True on success."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        print(f"Webhook HTTP error: {e.code} {e.reason}", file=sys.stderr)
        return False
    except urllib.error.URLError as e:
        print(f"Webhook connection error: {e.reason}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Webhook error: {e}", file=sys.stderr)
        return False


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Send webhook notifications for pipeline events")
    parser.add_argument("--event", required=True,
                        choices=["deploy", "test", "stale", "score", "security",
                                 "pipeline", "splunk_alert"],
                        help="Event type")
    parser.add_argument("--status",    help="Event status: success, failure, warning, info")
    parser.add_argument("--rules",     help="Comma-separated rule IDs or count")
    parser.add_argument("--scores",    help="Comma-separated scores (for score event)")
    parser.add_argument("--failed",    help="Number of failed tests (for test event)")
    parser.add_argument("--total",     help="Total number of tests (for test event)")
    parser.add_argument("--message",   help="Custom message text")
    parser.add_argument("--branch",    help="Git branch name")
    parser.add_argument("--commit",    help="Git commit SHA")
    parser.add_argument("--rule-id",   help="Rule ID (for splunk_alert)")
    parser.add_argument("--rule-title", help="Rule title (for splunk_alert)")
    parser.add_argument("--severity",  help="Alert severity (for splunk_alert)")
    parser.add_argument("--results",   help="Number of Splunk results (for splunk_alert)")
    parser.add_argument("--splunk-url", help="Splunk search URL (for splunk_alert)")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Print payload without sending")
    args = parser.parse_args()

    webhook_url = get_env("WEBHOOK_URL")
    webhook_type = get_env("WEBHOOK_TYPE", "slack")

    if not webhook_url and not args.dry_run:
        print("WEBHOOK_URL environment variable not set. Use --dry-run to preview.", file=sys.stderr)
        sys.exit(1)

    # Build payload
    builders = {
        "deploy":       build_deploy_message,
        "test":         build_test_message,
        "stale":        build_stale_message,
        "score":        build_score_message,
        "security":     build_security_message,
        "pipeline":     build_pipeline_message,
        "splunk_alert": build_splunk_alert_message,
    }

    if webhook_type == "generic":
        payload = build_generic_payload(args)
    else:
        payload = builders[args.event](args)

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        sys.exit(0)

    print(f"Sending {args.event} notification...", end=" ")
    ok = send_webhook(payload, webhook_url)
    if ok:
        print("✓ sent")
        sys.exit(0)
    else:
        print("✗ failed")
        sys.exit(1)


if __name__ == "__main__":
    main()