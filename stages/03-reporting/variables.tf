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

variable "environment" {
  type    = string
  default = "dev"
}

variable "functions_location" {
  description = "Same region as stage 02's collector — keep the two Function Apps in the same Y1 quota pool rather than probing twice."
  type        = string
  default     = "centralus"
}
