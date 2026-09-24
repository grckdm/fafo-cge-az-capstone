terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }

  backend "azurerm" {
    resource_group_name = "rg-fafo-tfstate"
    container_name      = "tfstate"
    key                 = "02-evidence-store.tfstate"
    use_azuread_auth    = true
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
  # Required to CREATE a storage account with shared_access_key_enabled = false:
  # without this, the provider's own post-create readiness polling defaults to
  # key-based auth against the account it just created — which that account now
  # refuses by design — and the apply fails with KeyBasedAuthenticationNotPermitted.
  storage_use_azuread = true
}

# Cross-stage composition through remote state outputs — never a cross-stage
# resource reference. Stage 02 reads stage 01's outputs; it cannot mutate stage
# 01's resources, only read where things landed.
data "terraform_remote_state" "foundation" {
  backend = "azurerm"
  config = {
    resource_group_name  = var.state_resource_group
    storage_account_name = var.state_storage_account
    container_name       = "tfstate"
    key                  = "01-foundation.tfstate"
    use_azuread_auth     = true
  }
}
