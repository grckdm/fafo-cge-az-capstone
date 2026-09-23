variable "subscription_id" {
  description = "Azure subscription ID this stage targets."
  type        = string
}

variable "state_resource_group" {
  description = "Resource group holding the Terraform state storage account (from bootstrap/backend.hcl)."
  type        = string
  default     = "rg-fafo-tfstate"
}

variable "state_storage_account" {
  description = "Terraform state storage account name (from bootstrap/backend.hcl) — read at apply time, never hardcoded."
  type        = string
}

variable "location" {
  description = "Azure region for the evidence plane. Independent of stage 01's location variable — evidence residency is its own decision, not inherited by accident."
  type        = string
  default     = "eastus2"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "functions_location" {
  description = "Region for the collector Function App's consumption plan. Free-tier subscriptions frequently have zero Y1 quota in the primary region — probe before deploying (see docs/DEPLOY.md)."
  type        = string
  default     = "centralus"
}

variable "immutability_period_days" {
  description = "WORM retention window on the reports container. FAFO Inc.'s evidence-retention posture: long enough to survive a quarterly audit cycle with room to spare."
  type        = number
  default     = 120
}
