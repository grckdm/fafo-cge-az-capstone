variable "subscription_id" {
  type = string
}

variable "state_resource_group" {
  type    = string
  default = "rg-fafo-tfstate"
}

variable "state_storage_account" {
  type = string
}

variable "location" {
  type    = string
  default = "eastus2"
}

variable "remediation_mode" {
  description = <<-EOT
    The escalation ladder, one variable, each rung a reviewed PR:
      audit    -> observe only; count what would change, touch nothing
      dry-run  -> Modify effect deployed, assignment enforce=false; you create
                  the remediation task by hand — the human approval gate
      enforce  -> Modify effect, enforce=true, fully automatic
  EOT
  type        = string
  default     = "dry-run"
  validation {
    condition     = contains(["audit", "dry-run", "enforce"], var.remediation_mode)
    error_message = "remediation_mode must be audit, dry-run, or enforce."
  }
}
