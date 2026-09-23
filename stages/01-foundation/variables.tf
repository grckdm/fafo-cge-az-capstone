variable "subscription_id" {
  description = "Azure subscription ID this stage targets. Explicit rather than ambient, so a stray ARM_SUBSCRIPTION_ID in the shell can't silently redirect an apply."
  type        = string
}

variable "location" {
  description = "Azure region for foundation resources."
  type        = string
  default     = "eastus2"
}

variable "environment" {
  description = "Environment name used in tags and resource names."
  type        = string
  default     = "dev"
}

variable "owner_email" {
  description = "Owner tag applied to governed resource groups; report generators resolve finding owners from it."
  type        = string
}

variable "baseline_defender_plans" {
  description = "Defender for Cloud plans this baseline requires at Standard tier, keyed by plan name, valued by subplan (empty string for plans with none). Scoped to the two resource types our custom policies already govern — Key Vault and Storage — so discovery and policy enforcement point at the same attack surface."
  type        = map(string)
  default = {
    KeyVaults       = ""
    StorageAccounts = "DefenderForStorageV2"
  }
}

variable "min_tls_version_policy_effect" {
  description = "Effect for the require-min-tls-1.2 policy (Audit while onboarding, Deny once clean)."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.min_tls_version_policy_effect)
    error_message = "min_tls_version_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "kv_public_network_policy_effect" {
  description = "Effect for the deny-keyvault-public-network policy. FAFO Inc.'s credit/debt data model means secrets access is never a network-open question."
  type        = string
  default     = "Deny"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.kv_public_network_policy_effect)
    error_message = "kv_public_network_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "naming_convention_policy_effect" {
  description = "Effect for the enforce-naming-convention policy."
  type        = string
  default     = "Deny"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.naming_convention_policy_effect)
    error_message = "naming_convention_policy_effect must be Audit, Deny, or Disabled."
  }
}
