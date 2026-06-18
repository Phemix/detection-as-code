"""
backends/splunk.py — Splunk SPL compilation backend.
Reads the 'search' field from a rule and wraps it with
metadata comments and normalized output fields.
"""

from pathlib import Path
import re


def extract_mitre(rule: dict) -> str:
    mitre_field = rule.get("mitre", [])
    if isinstance(mitre_field, list) and mitre_field:
        return ", ".join(str(t) for t in mitre_field)
    tags = rule.get("tags", [])
    techniques = []
    for tag in tags:
        m = re.search(r't(\d{4}(?:\.\d{3})?)', str(tag), re.IGNORECASE)
        if m:
            techniques.append(f"T{m.group(1).upper()}")
    return ", ".join(sorted(set(techniques))) or "unknown"


def get_search(rule: dict) -> str:
    search = rule.get("search", "")
    if search:
        return str(search).strip()
    detection = rule.get("detection", {})
    if isinstance(detection, dict):
        return str(detection.get("raw_query", "")).strip()
    return ""


def get_schedule_comment(rule: dict) -> str:
    schedule = rule.get("schedule")
    if not schedule or not isinstance(schedule, dict):
        return '| comment "Schedule: not defined"'
    cron = schedule.get("cron") or schedule.get("every", "not set")
    earliest = schedule.get("earliest_time", "not set")
    latest = schedule.get("latest_time", "not set")
    return (
        f'| comment "Schedule: {cron}  |  '
        f'earliest: {earliest}  latest: {latest}"'
    )


def compile(rule: dict, path: Path, output_dir: Path, dry_run: bool = False) -> tuple[bool, str]:
    """Compile a rule to Splunk SPL."""
    search = get_search(rule)
    if not search:
        return False, "No SPL found in 'search' or 'detection.raw_query'"

    title = rule.get("title") or rule.get("name", path.stem)
    rule_id = str(rule.get("id", ""))
    level = rule.get("level") or rule.get("severity", "unknown")
    rule_type = rule.get("type", "detection")
    author = rule.get("author", "unknown")
    date = str(rule.get("date") or rule.get("creation_date", "unknown"))
    modified = str(rule.get("modified") or rule.get("modification_date", date))
    mitre = extract_mitre(rule)
    schedule_comment = get_schedule_comment(rule)

    compiled = f"""\
| comment "────────────────────────────────────────────"
| comment "Rule:     {title}"
| comment "ID:       {rule_id}"
| comment "Type:     {rule_type}"
| comment "Severity: {level}"
| comment "MITRE:    {mitre}"
| comment "Author:   {author}"
| comment "Created:  {date}  Modified: {modified}"
{schedule_comment}
| comment "────────────────────────────────────────────"

{search}

| eval rule_name="{title}", severity="{level}", mitre="{mitre}", rule_id="{rule_id}"
| table _time, rule_name, severity, mitre, rule_id, host, user, process, src, dest
"""

    ROOT = path.parents[path.parts.index("rules") - 1] if "rules" in path.parts else path.parent.parent
    try:
        rel = path.relative_to(ROOT / "rules")
    except ValueError:
        rel = Path(path.name)

    out_path = output_dir / rel.with_suffix(".spl")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if dry_run:
        return True, f"[dry-run] Would write: {out_path}"

    out_path.write_text(compiled)
    return True, str(out_path)