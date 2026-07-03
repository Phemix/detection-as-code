# terraform/sentinel/variables.tf

variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
  default     = "d72ebff3-a191-455c-a656-30eaf62dacb2"
}

variable "resource_group_name" {
  description = "Resource group name for all Sentinel resources"
  type        = string
  default     = "rg-detection-as-code"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "workspace_name" {
  description = "Log Analytics workspace name"
  type        = string
  default     = "law-detection-as-code"
}

variable "retention_days" {
  description = "Log retention in days (30 minimum for free tier)"
  type        = number
  default     = 30
}

variable "environment" {
  description = "Environment tag (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "alert_severity_map" {
  description = "Maps rule level to Sentinel alert severity"
  type        = map(string)
  default = {
    critical = "High"
    high     = "High"
    medium   = "Medium"
    low      = "Low"
  }
}
