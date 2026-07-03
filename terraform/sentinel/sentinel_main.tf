# terraform/sentinel/main.tf
# Microsoft Sentinel deployment for Detection-as-Code pipeline
#
# Manages:
#   - Resource Group
#   - Log Analytics Workspace (Sentinel's data store)
#   - Microsoft Sentinel (enabled on the workspace)
#
# Analytic rules are managed in analytic_rules.tf
# Each compiled KQL file in compiled/sentinel/ becomes a Sentinel Scheduled Query Rule
#
# Usage:
#   cd terraform/sentinel
#   export ARM_SUBSCRIPTION_ID="d72ebff3-a191-455c-a656-30eaf62dacb2"
#   terraform init
#   terraform plan
#   terraform apply

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# ── Provider ───────────────────────────────────────────────────────────────
# Authenticates via Azure CLI — no credentials needed in code
# Run: az login before terraform plan/apply
provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# ── Resource Group ─────────────────────────────────────────────────────────
resource "azurerm_resource_group" "dac" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    project     = "detection-as-code"
    environment = var.environment
    managed_by  = "terraform"
  }
}

# ── Log Analytics Workspace ────────────────────────────────────────────────
# Sentinel sits on top of Log Analytics — this is the data store
resource "azurerm_log_analytics_workspace" "dac" {
  name                = var.workspace_name
  location            = azurerm_resource_group.dac.location
  resource_group_name = azurerm_resource_group.dac.name

  # Retention in days — 30 is free tier minimum
  retention_in_days = var.retention_days

  # PerGB2018 pricing tier — pay per GB ingested
  sku = "PerGB2018"

  tags = {
    project     = "detection-as-code"
    environment = var.environment
    managed_by  = "terraform"
  }
}

# ── Microsoft Sentinel ─────────────────────────────────────────────────────
# Enables Sentinel on the Log Analytics workspace
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "dac" {
  workspace_id = azurerm_log_analytics_workspace.dac.id
}
