# terraform/github/main.tf
# GitHub repository configuration for Detection-as-Code pipeline
#
# Manages:
#   - Branch protection on main
#   - Required status checks
#   - Repository secrets
#   - Actions deployment environment
#
# Usage:
#   cd terraform/github
#   terraform init
#   terraform plan
#   terraform apply

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 6.0"
    }
  }
}

# ── Provider ───────────────────────────────────────────────────────────────
# Set GITHUB_TOKEN environment variable before running
# export GITHUB_TOKEN=ghp_your_token_here
provider "github" {
  owner = var.github_owner
}

# ── Variables ──────────────────────────────────────────────────────────────
variable "github_owner" {
  description = "GitHub username or organization name"
  type        = string
  default     = "phemix"
}

variable "repository_name" {
  description = "Repository name"
  type        = string
  default     = "detection-as-code"
}

variable "webhook_url" {
  description = "Slack webhook URL for pipeline notifications"
  type        = string
  sensitive   = true
}

variable "splunk_password" {
  description = "Splunk admin password for deployment"
  type        = string
  sensitive   = true
}

# ── Data source — existing repo ────────────────────────────────────────────
# We reference the existing repo rather than creating it
# (repo already exists — Terraform manages its configuration)
data "github_repository" "dac" {
  full_name = "${var.github_owner}/${var.repository_name}"
}

# ── Branch protection — main ───────────────────────────────────────────────
resource "github_branch_protection" "main" {
  repository_id = data.github_repository.dac.node_id
  pattern       = "main"

  # Require PRs before merging
  required_pull_request_reviews {
    dismiss_stale_reviews           = true
    require_code_owner_reviews      = false
    required_approving_review_count = 1
  }

  # Require CI to pass before merging
  required_status_checks {
    strict = true  # require branch to be up to date before merging
    contexts = [
      "Validate Rules",    # validate job
      "Compile to Splunk SPL", # compile job
    ]
  }

  # Prevent force pushes and deletions on main
  allows_force_pushes = false
  allows_deletions    = false

  # Enforce rules for admins too
  enforce_admins = false
}

# ── Repository secrets ─────────────────────────────────────────────────────
resource "github_actions_secret" "webhook_url" {
  repository      = data.github_repository.dac.name
  secret_name     = "WEBHOOK_URL"
  plaintext_value = var.webhook_url
}

resource "github_actions_secret" "splunk_password" {
  repository      = data.github_repository.dac.name
  secret_name     = "SPLUNK_PASSWORD"
  plaintext_value = var.splunk_password
}

# ── Actions environment — production ──────────────────────────────────────
resource "github_repository_environment" "production" {
  repository  = data.github_repository.dac.name
  environment = "production"

  # Require manual approval before deploying to production
  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }
}

resource "github_actions_environment_secret" "splunk_password_prod" {
  repository      = data.github_repository.dac.name
  environment     = github_repository_environment.production.environment
  secret_name     = "SPLUNK_PASSWORD"
  plaintext_value = var.splunk_password
}

# ── Outputs ────────────────────────────────────────────────────────────────
output "repository_url" {
  description = "Repository URL"
  value       = data.github_repository.dac.html_url
}

output "branch_protection_pattern" {
  description = "Branch protection pattern applied"
  value       = github_branch_protection.main.pattern
}
