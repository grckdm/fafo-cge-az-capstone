terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    # azurerm can WRITE Defender plan pricing but has no matching data source —
    # azapi fills the read side. This is the discovery-first pattern: interrogate
    # the live tier before any resource decides whether to change it.
    azapi = {
      source  = "azure/azapi"
      version = "~> 2.0"
    }
  }

  # resource_group_name and container_name are fixed for good — bootstrap-state.sh
  # never re-parameterizes them. Only storage_account_name (subscription-specific
  # hash suffix) comes from -backend-config at init time, locally or in CI.
  backend "azurerm" {
    resource_group_name = "rg-fafo-tfstate"
    container_name      = "tfstate"
    key                 = "01-foundation.tfstate"
    use_azuread_auth    = true
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

provider "azapi" {
  subscription_id = var.subscription_id
}

data "azurerm_subscription" "current" {}
data "azurerm_client_config" "current" {}
