#!/usr/bin/env python3
"""
configure_alerts.py — Configure alert actions on deployed Splunk saved searches.
Wires rules to Splunk's built-in alert manager so they actually notify
when they fire, not just run silently on a schedule.

Alert actions configured per rule severity:
  critical → trigger immediately, log to alert manager, throttle 5min
  high     → trigger immediately, log to alert manager, throttle 15min
  medium   → trigger immediately, log to alert manager, throttle 1hr
  low      → log to alert manager only, throttle 4hr

Usage:
  python scripts/configure_alerts.py                  # configure all rules
  python scripts/configure_alerts.py --file rules/... # single rule
  python scripts/configure_alerts.py --dry-run        # show what would change
"""

import argparse
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
import ssl
import base64
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
CONFIG_FILE = ROOT / "sigma_config.yml"

ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

# Alert throttle windows by severity (seconds)
THROTTLE_BY_SEVERITY = {
    "critical": 300,    # 5 minutes
    "high": 900,        # 15 minutes
    "medium": 3600,     # 1 hour
    "low": 14400,       # 4 hours
    "informational": 86400  # 24 hours
}

# Number of results that must match to trigger alert
TRIGGER_COUNT_BY_SEVERITY = {
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 1,
    "informational": 1
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


def splunk_request(host, port, user, password, method, endpoint, data=None):
    url = f"https://{host}:{port}{endpoint}?output_mode=json"
    credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {
        "Authorization": f"Basic {credentials}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read().decode())
        except Exception:
            err_body = {"messages": [{"text": str(e)}]}
        return e.code, err_body


def configure_alert(rule, host, port, user, password, app, dry_run=False):
    """Configure alert actions on a deployed Splunk saved search."""

    title = rule.get("title") or rule.get("name", "Unknown")
    rule_id = str(rule.get("id", ""))
    level = (rule.get("level") or rule.get("severity", "medium")).lower()
    search_name = f"[DaC] {title} ({rule_id})"

    throttle = THROTTLE_BY_SEVERITY.get(level, 3600)
    trigger_count = TRIGGER_COUNT_BY_SEVERITY.get(level, 1)

    if dry_run:
        return True, (
            f"[dry-run] Would configure: '{search_name}'\n"
            f"          Severity: {level}  "
            f"Trigger: >{trigger_count} results  "
            f"Throttle: {throttle//60}min"
        )

    endpoint = f"/servicesNS/{user}/{app}/saved/searches/{urllib.parse.quote(search_name)}"

    data = {
        # Enable alerting
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": str(trigger_count - 1),
        "alert.severity": _map_severity(level),

        # Throttle — suppress duplicate alerts within window
        "alert.suppress": "1",
        "alert.suppress.period": f"{throttle}s",
        "alert.suppress.fields": "host",  # suppress per-host to reduce noise

        # Alert manager — log to Splunk's built-in triggered alerts
        "actions": "alert_manager",
        "action.alert_manager": "1",
        "action.alert_manager.param.title": search_name,
        "action.alert_manager.param.severity": level,

        # Keep as scheduled search with alerting enabled
        "is_scheduled": "1",
        "disabled": "0",
        "counttype": "number of events",
        "relation": "greater than",
        "quantity": str(trigger_count - 1),
    }

    status, response = splunk_request(host, port, user, password, "POST", endpoint, data)

    if status in (200, 201):
        return True, (
            f"Alert configured: '{search_name}'\n"
            f"       Trigger: >{trigger_count - 1} results  "
            f"Throttle: {throttle//60}min  "
            f"Severity: {level}"
        )
    else:
        messages = response.get("messages", [])
        err = messages[0].get("text", "Unknown error") if messages else str(response)

        # If alert_manager action not found, fall back to just logging
        if "alert_manager" in err.lower() or "unknown" in err.lower():
            return _configure_basic_alert(
                search_name, level, throttle, trigger_count,
                host, port, user, password, app, endpoint
            )

        return False, f"Failed ({status}): {err}"


def _configure_basic_alert(
    search_name, level, throttle, trigger_count,
    host, port, user, password, app, endpoint
):
    """
    Fallback alert configuration using Splunk's basic alert logging
    when alert_manager app is not installed.
    """
    data = {
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": str(trigger_count - 1),
        "alert.severity": _map_severity(level),
        "alert.suppress": "1",
        "alert.suppress.period": f"{throttle}s",
        "alert.suppress.fields": "host",
        "alert.track": "1",  # track in triggered alerts UI
        "is_scheduled": "1",
        "disabled": "0",
        "counttype": "number of events",
        "relation": "greater than",
        "quantity": str(trigger_count - 1),
    }

    status, response = splunk_request(
        host, port, user, password, "POST", endpoint, data
    )

    if status in (200, 201):
        return True, (
            f"Alert configured (basic): '{search_name}'\n"
            f"       Trigger: >{trigger_count - 1} results  "
            f"Throttle: {throttle//60}min  "
            f"View: Settings → Triggered Alerts"
        )
    else:
        messages = response.get("messages", [])
        err = messages[0].get("text", "Unknown error") if messages else str(response)
        return False, f"Failed ({status}): {err}"


def _map_severity(level: str) -> str:
    mapping = {
        "critical": "6", "high": "5", "medium": "3",
        "low": "2", "informational": "1"
    }
    return mapping.get(level.lower(), "3")


def collect_rules(config, single_file=None):
    if single_file:
        return [single_file.resolve()]
    paths = []
    for d in config.get("rule_dirs", []):
        rule_dir = ROOT / d
        if rule_dir.exists():
            paths.extend(sorted(rule_dir.glob("*.yml")))
    return paths


def main():
    parser = argparse.ArgumentParser(description="Configure alert actions on deployed Splunk rules")
    parser.add_argument("--host", default=os.getenv("SPLUNK_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SPLUNK_PORT", "8089")))
    parser.add_argument("--user", default=os.getenv("SPLUNK_USER", "admin"))
    parser.add_argument("--password", default=os.getenv("SPLUNK_PASSWORD", ""))
    parser.add_argument("--app", default=os.getenv("SPLUNK_APP", "search"))
    parser.add_argument("--file", type=Path, help="Configure alerts for a single rule")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be configured")
    args = parser.parse_args()

    if not args.password and not args.dry_run:
        print(f"{ANSI_RED}Error: SPLUNK_PASSWORD not set.{ANSI_RESET}")
        print("  export SPLUNK_PASSWORD=changeme123")
        sys.exit(1)

    config = load_config()
    paths = collect_rules(config, args.file)

    if not paths:
        print("No rule files found.")
        sys.exit(0)

    mode = " (dry-run)" if args.dry_run else ""
    print(f"\n{ANSI_BOLD}Alert Configuration{ANSI_RESET}{mode}  ({len(paths)} rules)\n")
    print(f"  Target: https://{args.host}:{args.port}  app={args.app}\n")
    print(f"  Severity thresholds:")
    print(f"    critical → trigger >0 results, throttle 5min")
    print(f"    high     → trigger >0 results, throttle 15min")
    print(f"    medium   → trigger >0 results, throttle 1hr")
    print(f"    low      → trigger >0 results, throttle 4hr\n")

    total_ok = total_fail = 0

    for path in paths:
        rule = load_rule(path)
        if not rule:
            print(f"  {ANSI_RED}✗{ANSI_RESET}  {path.name}  — failed to load")
            total_fail += 1
            continue

        ok, msg = configure_alert(
            rule, args.host, args.port, args.user,
            args.password, args.app, args.dry_run
        )

        if ok:
            print(f"  {ANSI_GREEN}✓{ANSI_RESET}  {path.name}")
            print(f"       {msg}")
            total_ok += 1
        else:
            print(f"  {ANSI_RED}✗{ANSI_RESET}  {path.name}")
            print(f"       {ANSI_RED}{msg}{ANSI_RESET}")
            total_fail += 1

    print(f"\n{'─'*55}")
    print(f"  Configured: {ANSI_GREEN}{total_ok}{ANSI_RESET}")
    print(f"  Failed:     {ANSI_RED}{total_fail}{ANSI_RESET}" if total_fail else f"  Failed:     {total_fail}")

    if total_fail > 0:
        print(f"\n{ANSI_RED}✗ Alert configuration completed with errors{ANSI_RESET}\n")
        sys.exit(1)
    else:
        print(f"\n{ANSI_GREEN}✓ Alert configuration complete{ANSI_RESET}\n")
        print(f"  View triggered alerts: http://{args.host}:8000/en-US/app/search/alerts\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
