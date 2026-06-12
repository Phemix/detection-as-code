#!/usr/bin/env python3
"""
deploy_splunk.py — Deploy compiled detection rules to Splunk via REST API.
Reads compiled SPL files from compiled/splunk/, pairs with source YAML
for schedule metadata, and creates/updates saved searches via the
Splunk REST API.

Usage:
  python scripts/deploy_splunk.py                          # deploy all rules
  python scripts/deploy_splunk.py --file rules/...        # deploy single rule
  python scripts/deploy_splunk.py --dry-run               # show what would deploy
  python scripts/deploy_splunk.py --delete                # remove all deployed rules

Environment variables (or pass as args):
  SPLUNK_HOST      Splunk host (default: localhost)
  SPLUNK_PORT      Splunk management port (default: 8089)
  SPLUNK_USER      Splunk username (default: admin)
  SPLUNK_PASSWORD  Splunk password (required)
  SPLUNK_APP       Splunk app context (default: search)
"""

import argparse
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
import ssl
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


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def load_rule(path: Path) -> dict | None:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def load_spl(spl_path: Path) -> str | None:
    try:
        return spl_path.read_text().strip()
    except Exception:
        return None


def strip_comments(spl: str) -> str:
    """
    Remove | comment lines from compiled SPL before deploying to Splunk.
    The comment header is useful for humans reading .spl files but
    Splunk does not recognize | comment as a valid search command
    in all configurations.
    """
    lines = spl.split('\n')
    clean = [line for line in lines if not line.strip().startswith('| comment')]
    clean = [line for line in clean if line.strip()]
    return '\n'.join(clean)


def get_schedule(rule: dict) -> tuple[str, str, str]:
    """Returns (cron, earliest_time, latest_time)"""
    schedule = rule.get("schedule", {})
    if not isinstance(schedule, dict):
        return "*/5 * * * *", "-10m", "now"
    cron = schedule.get("cron") or schedule.get("every", "*/5 * * * *")
    earliest = schedule.get("earliest_time", "-10m")
    latest = schedule.get("latest_time", "now")
    return cron, earliest, latest


def splunk_request(
    host: str,
    port: int,
    user: str,
    password: str,
    method: str,
    endpoint: str,
    data: dict | None = None
) -> tuple[int, dict]:
    """Make a request to the Splunk REST API."""
    url = f"https://{host}:{port}{endpoint}?output_mode=json"

    import base64
    credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {
        "Authorization": f"Basic {credentials}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=30) as resp:
            import json
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        import json
        try:
            err_body = json.loads(e.read().decode())
        except Exception:
            err_body = {"messages": [{"text": str(e)}]}
        return e.code, err_body


def search_exists(host, port, user, password, app, search_name) -> bool:
    """Check if a saved search already exists."""
    endpoint = f"/servicesNS/{user}/{app}/saved/searches/{urllib.parse.quote(search_name)}"
    status, _ = splunk_request(host, port, user, password, "GET", endpoint)
    return status == 200

def deploy_rule(
    rule: dict,
    spl_content: str,
    host: str,
    port: int,
    user: str,
    password: str,
    app: str,
    dry_run: bool = False
) -> tuple[bool, str]:
    """Deploy a single rule to Splunk as a saved search."""

    title = rule.get("title") or rule.get("name", "Unknown")
    rule_id = str(rule.get("id", ""))
    level = rule.get("level") or rule.get("severity", "unknown")
    cron, earliest, latest = get_schedule(rule)
    search_name = f"[DaC] {title} ({rule_id})"

    if dry_run:
        return True, (
            f"[dry-run] Would deploy: '{search_name}'\n"
            f"          Schedule: {cron}  earliest: {earliest}  latest: {latest}"
        )

    # Strip | comment lines before deploying
    spl_content = strip_comments(spl_content)

    # Build data dict first
    data = {
        "name": search_name,
        "search": spl_content,
        "cron_schedule": cron,
        "dispatch.earliest_time": earliest,
        "dispatch.latest_time": latest,
        "is_scheduled": "1",
        "disabled": "0",
        "description": rule.get("description", ""),
        "alert.severity": _map_severity(level),
        "request.ui_dispatch_app": app,
        "request.ui_dispatch_view": "search",
    }

    # Determine endpoint based on whether search already exists
    exists = search_exists(host, port, user, password, app, search_name)

    if exists:
        # Update existing search — POST to named endpoint, name not needed
        endpoint = f"/servicesNS/{user}/{app}/saved/searches/{urllib.parse.quote(search_name)}"
        data.pop("name", None)
    else:
        # Create new search
        endpoint = f"/servicesNS/{user}/{app}/saved/searches"

    status, response = splunk_request(host, port, user, password, "POST", endpoint, data)

    if status in (200, 201):
        action = "updated" if exists else "created"
        return True, f"Saved search {action}: '{search_name}'"
    else:
        messages = response.get("messages", [])
        err = messages[0].get("text", "Unknown error") if messages else str(response)
        return False, f"Failed ({status}): {err}"
    
def delete_rule(
    rule: dict,
    host: str,
    port: int,
    user: str,
    password: str,
    app: str,
    dry_run: bool = False
) -> tuple[bool, str]:
    """Delete a deployed rule from Splunk."""
    title = rule.get("title") or rule.get("name", "Unknown")
    rule_id = str(rule.get("id", ""))
    search_name = f"[DaC] {title} ({rule_id})"

    if dry_run:
        return True, f"[dry-run] Would delete: '{search_name}'"

    if not search_exists(host, port, user, password, app, search_name):
        return True, f"Not found (already deleted): '{search_name}'"

    endpoint = f"/servicesNS/{user}/{app}/saved/searches/{urllib.parse.quote(search_name)}"
    status, response = splunk_request(host, port, user, password, "DELETE", endpoint)

    if status == 200:
        return True, f"Deleted: '{search_name}'"
    else:
        messages = response.get("messages", [])
        err = messages[0].get("text", "Unknown error") if messages else str(response)
        return False, f"Failed ({status}): {err}"


def _map_severity(level: str) -> str:
    """Map rule level to Splunk alert severity number."""
    mapping = {
        "critical": "6",
        "high": "5",
        "medium": "3",
        "low": "2",
        "informational": "1"
    }
    return mapping.get(level.lower(), "3")


def collect_rule_pairs(config: dict, single_file: Path | None = None) -> list[tuple[Path, Path]]:
    """
    Returns list of (rule_yaml_path, compiled_spl_path) pairs.
    Only returns pairs where both files exist.
    """
    if single_file:
        single_file = single_file.resolve()
        rel = single_file.relative_to(ROOT / "rules")
        spl_path = ROOT / "compiled" / "splunk" / rel.with_suffix(".spl")
        if spl_path.exists():
            return [(single_file, spl_path)]
        else:
            print(f"{ANSI_RED}No compiled SPL found for {single_file.name}{ANSI_RESET}")
            print("Run 'make compile' first.")
            return []

    pairs = []
    for d in config.get("rule_dirs", []):
        rule_dir = ROOT / d
        if not rule_dir.exists():
            continue
        for rule_path in sorted(rule_dir.glob("*.yml")):
            rel = rule_path.relative_to(ROOT / "rules")
            spl_path = ROOT / "compiled" / "splunk" / rel.with_suffix(".spl")
            if spl_path.exists():
                pairs.append((rule_path, spl_path))
            else:
                print(f"{ANSI_YELLOW}⚠{ANSI_RESET}  No compiled SPL for {rule_path.name} — skipping. Run 'make compile' first.")
    return pairs


def main():
    parser = argparse.ArgumentParser(description="Deploy detection rules to Splunk")
    parser.add_argument("--host", default=os.getenv("SPLUNK_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SPLUNK_PORT", "8089")))
    parser.add_argument("--user", default=os.getenv("SPLUNK_USER", "admin"))
    parser.add_argument("--password", default=os.getenv("SPLUNK_PASSWORD", ""))
    parser.add_argument("--app", default=os.getenv("SPLUNK_APP", "search"))
    parser.add_argument("--file", type=Path, help="Deploy a single rule")
    parser.add_argument("--dry-run", action="store_true", help="Show what would deploy without deploying")
    parser.add_argument("--delete", action="store_true", help="Delete deployed rules instead of creating them")
    args = parser.parse_args()

    if not args.password and not args.dry_run:
        print(f"{ANSI_RED}Error: SPLUNK_PASSWORD not set.{ANSI_RESET}")
        print("Set it via environment variable or --password flag:")
        print("  export SPLUNK_PASSWORD=changeme123")
        print("  python scripts/deploy_splunk.py")
        sys.exit(1)

    config = load_config()
    pairs = collect_rule_pairs(config, args.file)

    if not pairs:
        print("No rules to deploy.")
        sys.exit(0)

    action = "Delete" if args.delete else "Deploy"
    mode = " (dry-run)" if args.dry_run else ""
    print(f"\n{ANSI_BOLD}Splunk {action} Pipeline{ANSI_RESET}{mode}  ({len(pairs)} rules)\n")
    print(f"  Target: https://{args.host}:{args.port}  app={args.app}\n")

    total_ok = total_fail = 0

    for rule_path, spl_path in pairs:
        rule = load_rule(rule_path)
        if not rule:
            print(f"  {ANSI_RED}✗{ANSI_RESET}  {rule_path.name}  — failed to load YAML")
            total_fail += 1
            continue

        spl_content = load_spl(spl_path)
        if not spl_content:
            print(f"  {ANSI_RED}✗{ANSI_RESET}  {rule_path.name}  — failed to load SPL")
            total_fail += 1
            continue

        if args.delete:
            ok, msg = delete_rule(rule, args.host, args.port, args.user, args.password, args.app, args.dry_run)
        else:
            ok, msg = deploy_rule(rule, spl_content, args.host, args.port, args.user, args.password, args.app, args.dry_run)

        if ok:
            print(f"  {ANSI_GREEN}✓{ANSI_RESET}  {rule_path.name}")
            print(f"       {msg}")
            total_ok += 1
        else:
            print(f"  {ANSI_RED}✗{ANSI_RESET}  {rule_path.name}")
            print(f"       {ANSI_RED}{msg}{ANSI_RESET}")
            total_fail += 1

    print(f"\n{'─'*55}")
    print(f"  {'Deployed' if not args.delete else 'Deleted'}:  {ANSI_GREEN}{total_ok}{ANSI_RESET}")
    print(f"  Failed:   {ANSI_RED}{total_fail}{ANSI_RESET}" if total_fail else f"  Failed:   {total_fail}")

    if total_fail > 0:
        print(f"\n{ANSI_RED}✗ Deployment completed with errors{ANSI_RESET}\n")
        sys.exit(1)
    else:
        print(f"\n{ANSI_GREEN}✓ Deployment complete{ANSI_RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
