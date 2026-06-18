"""
backends/sentinel.py — Microsoft Sentinel KQL compilation backend.
Reads the 'kql_search' field from a rule and wraps it with
metadata comments and normalized output fields.

Rules without a 'kql_search' field are skipped gracefully.
The default table is DeviceProcessEvents (Microsoft Defender for Endpoint).

Field mapping reference (Sysmon → MDE DeviceProcessEvents):
  Image               → FolderPath + FileName
  CommandLine         → ProcessCommandLine
  ParentImage         → InitiatingProcessFolderPath + InitiatingProcessFileName
  Computer            → DeviceName
  User                → AccountName
  EventID             → ActionType
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


def get_kql_search(rule: dict) -> str:
    """Return the KQL search block if present."""
    kql = rule.get("kql_search", "")
    if kql:
        return str(kql).strip()
    return ""


def get_schedule_comment(rule: dict) -> str:
    schedule = rule.get("schedule")
    if not schedule or not isinstance(schedule, dict):
        return "// Schedule: not defined"
    cron = schedule.get("cron") or schedule.get("every", "not set")
    earliest = schedule.get("earliest_time", "not set")
    latest = schedule.get("latest_time", "not set")
    return f"// Schedule: {cron}  |  earliest: {earliest}  latest: {latest}"


def compile(rule: dict, path: Path, output_dir: Path, dry_run: bool = False) -> tuple[bool, str]:
    """
    Compile a rule to Microsoft Sentinel KQL.
    Returns (False, skip_reason) if no kql_search field is present.
    """
    kql = get_kql_search(rule)
    if not kql:
        return False, "SKIP: no 'kql_search' field defined — skipping Sentinel compilation"

    title = rule.get("title") or rule.get("name", path.stem)
    rule_id = str(rule.get("id", ""))
    level = rule.get("level") or rule.get("severity", "unknown")
    rule_type = rule.get("type", "detection")
    author = rule.get("author", "unknown")
    date = str(rule.get("date") or rule.get("creation_date", "unknown"))
    modified = str(rule.get("modified") or rule.get("modification_date", date))
    mitre = extract_mitre(rule)
    schedule_comment = get_schedule_comment(rule)

    # Map severity to Sentinel alert severity
    severity_map = {
        "critical": "High",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Informational"
    }
    sentinel_severity = severity_map.get(str(level).lower(), "Medium")

    compiled = f"""\
// ────────────────────────────────────────────────
// Rule:     {title}
// ID:       {rule_id}
// Type:     {rule_type}
// Severity: {level} (Sentinel: {sentinel_severity})
// MITRE:    {mitre}
// Author:   {author}
// Created:  {date}  Modified: {modified}
{schedule_comment}
// ────────────────────────────────────────────────
// Target:   Microsoft Sentinel (DeviceProcessEvents / MDE)
// Deploy:   Sentinel Analytics Rules → Scheduled Query
// ────────────────────────────────────────────────

{kql}
| extend
    RuleName = "{title}",
    RuleId = "{rule_id}",
    Severity = "{sentinel_severity}",
    MitreTechnique = "{mitre}"
| project
    TimeGenerated,
    RuleName,
    RuleId,
    Severity,
    MitreTechnique,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    FolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath
"""

    ROOT = path.parents[path.parts.index("rules") - 1] if "rules" in path.parts else path.parent.parent
    try:
        rel = path.relative_to(ROOT / "rules")
    except ValueError:
        rel = Path(path.name)

    out_path = output_dir / rel.with_suffix(".kql")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if dry_run:
        return True, f"[dry-run] Would write: {out_path}"

    out_path.write_text(compiled)
    return True, str(out_path)