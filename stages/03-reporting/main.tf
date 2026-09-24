locals {
  evidence_rg      = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  cosmos_account   = data.terraform_remote_state.evidence_store.outputs.cosmos_account_name
  cosmos_endpoint  = data.terraform_remote_state.evidence_store.outputs.cosmos_endpoint
  cosmos_id        = data.terraform_remote_state.evidence_store.outputs.cosmos_account_id
  evidence_storage = data.terraform_remote_state.evidence_store.outputs.evidence_storage_account
}

data "azurerm_storage_account" "evidence" {
  name                = local.evidence_storage
  resource_group_name = local.evidence_rg
}

# --- Reporter's own runtime storage — separate from both the collector's and
#     from the evidence account itself. Three storage accounts, three purposes,
#     zero shared blast radius between them. ---

resource "azurerm_storage_account" "reporter_runtime" {
  name                     = "stfaforpt${var.environment}${substr(sha256(local.cosmos_id), 0, 6)}"
  resource_group_name      = local.evidence_rg
  location                 = var.functions_location
  account_tier             = "Standard"
  account_replication_type = "ZRS"
  min_tls_version          = "TLS1_2"

  allow_nested_items_to_be_public = false

  blob_properties {
    delete_retention_policy {
      days = 30
    }
  }

  tags = {
    env     = var.environment
    purpose = "function-runtime-internal"
    company = "fafo"
  }
}

resource "azurerm_service_plan" "reporter" {
  name                = "asp-fafo-reporter-${var.environment}"
  resource_group_name = local.evidence_rg
  location            = var.functions_location
  os_type             = "Linux"
  sku_name            = "Y1"
}

resource "azurerm_linux_function_app" "reporter" {
  name                = "func-fafo-reporter-${var.environment}"
  resource_group_name = local.evidence_rg
  location            = var.functions_location

  storage_account_name       = azurerm_storage_account.reporter_runtime.name
  storage_account_access_key = azurerm_storage_account.reporter_runtime.primary_access_key
  service_plan_id            = azurerm_service_plan.reporter.id
  https_only                 = true

  site_config {
    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = {
    COSMOS_ENDPOINT          = local.cosmos_endpoint
    EVIDENCE_STORAGE_ACCOUNT = local.evidence_storage
    REPORTS_CONTAINER        = data.terraform_remote_state.evidence_store.outputs.reports_container
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    env     = var.environment
    purpose = "grc-report-generator"
    company = "fafo"
  }
}

# --- SoD boundary: the reporter can READ Cosmos and WRITE blobs. It cannot
#     write Cosmos (cannot author evidence, only consume it) and holds no
#     Policy/Security read role (cannot pull live platform state — every
#     number in its reports traces back to a stored, collector-written
#     document, never a fresh API call). ---

resource "azurerm_cosmosdb_sql_role_assignment" "reporter_cosmos_read" {
  resource_group_name = local.evidence_rg
  account_name        = local.cosmos_account
  role_definition_id  = "${local.cosmos_id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"
  principal_id        = azurerm_linux_function_app.reporter.identity[0].principal_id
  scope               = local.cosmos_id
}

resource "azurerm_role_assignment" "reporter_blob_write" {
  scope                = data.azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_linux_function_app.reporter.identity[0].principal_id
}
