# terraform/sentinel/outputs.tf

output "resource_group_name" {
  description = "Resource group containing all Sentinel resources"
  value       = azurerm_resource_group.dac.name
}

output "workspace_id" {
  description = "Log Analytics workspace ID — needed for Sentinel API calls"
  value       = azurerm_log_analytics_workspace.dac.id
}

output "workspace_name" {
  description = "Log Analytics workspace name"
  value       = azurerm_log_analytics_workspace.dac.name
}

output "sentinel_workspace_id" {
  description = "Sentinel workspace onboarding ID"
  value       = azurerm_sentinel_log_analytics_workspace_onboarding.dac.id
}

output "analytic_rules" {
  description = "Deployed Sentinel analytic rule names"
  value = {
    lsass_memory_dump = azurerm_sentinel_alert_rule_scheduled.lsass_memory_dump_procdump.display_name
  }
}
