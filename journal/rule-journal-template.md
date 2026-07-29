<!--
Journal for a single detection rule. One file per rule ID, living at
journal/{rule_id}.md (e.g. journal/DET-00001.md). This is the durable
memory an AI reviewer or a new engineer reads to understand why a rule
looks the way it does — not just what it does.

Copy this template when a rule's journal is created, then keep the
Tuning History section append-only: add new entries, never edit or
delete old ones.
-->

# {rule_id} — {rule title}

## Origin

Why this rule was created: the gap, signal, threat intel lead, or hunt
finding that prompted it. Link the source (ticket, incident, report) if
one exists.

## Baseline Behavior

What normal/expected telemetry looks like for the data source(s) this
rule watches, and how that shaped the detection logic (thresholds,
exclusions, field choices).

## Tuning History

Append-only. One entry per change, newest last.

- `YYYY-MM-DD` — What changed and why. Link the PR.

## Known False Positives

- Scenario — how to distinguish it from real activity, and any
  remediation (allowlist, exclusion, owner to loop in).

## Review Status

- **Owner:**
- **Last reviewed:** `YYYY-MM-DD`
- **Next review due:** `YYYY-MM-DD`
- **Status:** experimental | test | stable | deprecated
