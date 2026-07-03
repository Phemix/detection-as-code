# Terraform — Microsoft Sentinel Deployment

Deploys compiled KQL detections as Sentinel Scheduled Query Rules using infrastructure as code.

## What This Creates

- **Resource Group** — `rg-detection-as-code`
- **Log Analytics Workspace** — `law-detection-as-code` (Sentinel's data store)
- **Microsoft Sentinel** — enabled on the workspace
- **Analytic Rules** — one per compiled KQL file in `compiled/sentinel/`

## How Detection Deployment Works

```
Author rule YAML with kql_search: block
    ↓
make compile-sentinel
    ↓ writes compiled/sentinel/tactic/rule.kql
terraform plan
    ↓ shows what Sentinel rules will change
terraform apply
    ↓ deploys rules to Sentinel as Scheduled Query Rules
```

## Prerequisites

- Terraform >= 1.5.0
- Azure CLI authenticated (`az login`)
- Azure subscription with Sentinel available

## Usage

```bash
cd terraform/sentinel

# Authenticate
az login

# Set subscription
export ARM_SUBSCRIPTION_ID="d72ebff3-a191-455c-a656-30eaf62dacb2"

# Initialize providers
terraform init

# Preview changes
terraform plan

# Deploy
terraform apply
```

## Adding a New Detection

1. Add `kql_search:` block to your rule YAML
2. Run `make compile-sentinel` to generate the KQL file
3. Copy the rule template from `analytic_rules.tf` and fill in values
4. Run `terraform plan` to preview
5. Run `terraform apply` to deploy

## Destroying Resources

```bash
terraform destroy
```

This will delete all Sentinel resources including the workspace and all data.
