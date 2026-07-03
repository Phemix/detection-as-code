# terraform/sentinel/analytic_rules.tf
# Deploys compiled KQL detections as Sentinel Scheduled Query Rules
#
# How it works:
#   1. Reads all .kql files from compiled/sentinel/ directory
#   2. Reads the corresponding .yml rule file for metadata
#   3. Creates a Sentinel Scheduled Query Rule for each detection
#
# To add a new rule:
#   1. Add kql_search: block to your YAML rule
#   2. Run: make compile-sentinel
#   3. Run: terraform plan (preview changes)
#   4. Run: terraform apply (deploy to Sentinel)

locals {
  # Path to compiled KQL files relative to this terraform directory
  compiled_sentinel_dir = "${path.module}/../../compiled/sentinel"

  # Severity mapping
  severity_map = {
    critical = "High"
    high     = "High"
    medium   = "Medium"
    low      = "Low"
  }
}

# ── LSASS Memory Dump via ProcDump (DET-00001) ────────────────────────────
resource "azurerm_sentinel_alert_rule_scheduled" "lsass_memory_dump_procdump" {
  name                       = "DET-00001-LSASS-Memory-Dump-via-ProcDump"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.dac.workspace_id
  display_name               = "LSASS Memory Dump via ProcDump or comsvcs.dll (DET-00001)"
  description                = "Detects memory dumping of LSASS process using ProcDump or comsvcs.dll MiniDump, common techniques for credential theft."
  severity                   = "High"
  enabled                    = true

  # KQL query — loaded from compiled/sentinel/
  query = file("${local.compiled_sentinel_dir}/credential_access/lsass_memory_dump_procdump.kql")

  # Run every 5 minutes, look back 10 minutes
  query_frequency = "PT5M"
  query_period    = "PT10M"

  # Alert when any results are returned
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  # MITRE ATT&CK mapping
  tactics    = ["CredentialAccess"]
  techniques = ["T1003"]

  # Alert grouping — group alerts by affected device
  alert_details_override {
    description_format = "LSASS memory dump detected on {{DeviceName}} by {{AccountName}}"
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents  = false
      entity_matching_method  = "Selected"
      by_entities       = ["Host"]
    }
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.dac]
}

# ── Template for adding new rules ──────────────────────────────────────────
# Copy this block and fill in the values when adding a new detection
#
# resource "azurerm_sentinel_alert_rule_scheduled" "rule_name" {
#   name                       = "DET-NNNNN-Short-Rule-Name"
#   log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.dac.workspace_id
#   display_name               = "Rule Title (DET-NNNNN)"
#   description                = "What this rule detects."
#   severity                   = "High"   # High, Medium, Low, Informational
#   enabled                    = true
#
#   query          = file("${local.compiled_sentinel_dir}/tactic/rule_file.kql")
#   query_frequency = "PT5M"    # How often to run: PT5M, PT1H, P1D
#   query_period    = "PT10M"   # How far back to look
#
#   trigger_operator  = "GreaterThan"
#   trigger_threshold = 0
#
#   tactics    = ["CredentialAccess"]   # MITRE tactic
#   techniques = ["T1003.001"]          # MITRE technique
#
#   incident_configuration {
#     create_incident = true
#     grouping {
#       enabled                = true
#       lookback_duration      = "PT1H"
#       reopen_closed_incidents = false
#       entity_matching_method = "Selected"
#       group_by_entities      = ["Host"]
#     }
#   }
#
#   depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.dac]
# }
