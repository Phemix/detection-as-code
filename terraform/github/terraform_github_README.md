# Terraform — GitHub Repository Configuration

Manages the GitHub repository configuration for the Detection-as-Code pipeline using infrastructure as code.

## What This Manages

- **Branch protection** on `main` — requires PR review and CI to pass before merging
- **Required status checks** — `Validate Rules` and `Compile to Splunk SPL` must pass
- **Repository secrets** — `WEBHOOK_URL` and `SPLUNK_PASSWORD` managed as code
- **Actions environment** — `production` environment with branch protection policy

## Prerequisites

- Terraform >= 1.5.0
- GitHub personal access token with `repo` and `admin:repo_hook` scopes

## Usage

```bash
cd terraform/github

# Set credentials
export GITHUB_TOKEN=ghp_your_token_here
export TF_VAR_webhook_url="https://hooks.slack.com/services/..."
export TF_VAR_splunk_password="your_splunk_password"

# Initialize
terraform init

# Preview changes
terraform plan

# Apply
terraform apply
```

## State

Terraform state is stored locally by default. For team use, configure a remote backend (S3, Azure Blob, Terraform Cloud).

## Adding Sentinel (next step)

See `terraform/sentinel/` for Microsoft Sentinel analytic rule deployment.
