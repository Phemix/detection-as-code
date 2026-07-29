## Summary

<!-- What does this PR change and why? -->

## Rule Journal

<!--
Required for any PR touching rules/**. CI (check_journal_updated.py)
will fail this PR if a rule file changed without a matching update
under journal/{rule_id}.md.

For each rule touched, answer:
-->

- **Rule(s):** <!-- e.g. DET-00001 -->
- **What changed:**
- **Why:** <!-- new coverage gap, FP tuning, threat intel, false negative, etc. -->
- **Journal updated:** <!-- journal/{rule_id}.md — link the diff -->

## Testing

- [ ] `make validate` passes
- [ ] `make compile` passes
- [ ] Test cases added/updated under `tests/sample_logs/`
