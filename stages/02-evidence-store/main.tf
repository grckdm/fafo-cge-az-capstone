locals {
  mg_id = data.terraform_remote_state.foundation.outputs.management_group_id
}

# --- Evidence store: Cosmos DB (serverless — findings volume at capstone scale
#     never approaches provisioned-throughput territory) ---

resource "azurerm_cosmosdb_account" "fafo" {
  name                = "cosmos-fafo-grc-${var.environment}"
  location            = var.location
  resource_group_name = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = var.location
    failover_priority = 0
  }

  # Local (key-based) auth off — every reader/writer authenticates as an Azure AD
  # identity with an explicit SQL role assignment below. No connection string to leak.
  local_authentication_enabled = false
}

resource "azurerm_cosmosdb_sql_database" "fafo" {
  name                = "fafogrc"
  resource_group_name = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  account_name        = azurerm_cosmosdb_account.fafo.name
}

# Compliance state per resource, per policy, per collection run — the primary
# evidence container. Partitioned on policyDefinitionName: findings for a given
# control land together, which is exactly how reports query them.
resource "azurerm_cosmosdb_sql_container" "findings" {
  name                = "findings"
  resource_group_name = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  account_name        = azurerm_cosmosdb_account.fafo.name
  database_name       = azurerm_cosmosdb_sql_database.fafo.name
  partition_key_paths = ["/policyDefinitionName"]
}

# FAFO Inc.'s own control catalog — one document per policy, written once by the
# seed script, read by report generators. Not per-report duplication.
resource "azurerm_cosmosdb_sql_container" "controls" {
  name                = "controls"
  resource_group_name = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  account_name        = azurerm_cosmosdb_account.fafo.name
  database_name       = azurerm_cosmosdb_sql_database.fafo.name
  partition_key_paths = ["/id"]
}

# Control -> NIST CSF 2.0 category -> HIPAA Security Rule safeguard crosswalk,
# as data. CSF 2.0 is the primary mapping; HIPAA is an additive second layer
# chained off the same category. Collect-once: written by the seed script,
# never regenerated per report run.
resource "azurerm_cosmosdb_sql_container" "mappings" {
  name                = "mappings"
  resource_group_name = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  account_name        = azurerm_cosmosdb_account.fafo.name
  database_name       = azurerm_cosmosdb_sql_database.fafo.name
  partition_key_paths = ["/id"]
}

# --- WORM report storage — the immutable output half of the evidence plane ---

resource "azurerm_storage_account" "evidence" {
  name                     = "stfafoevid${var.environment}${substr(sha256(azurerm_cosmosdb_account.fafo.id), 0, 6)}"
  resource_group_name      = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false # Tier 0: report writes authenticate as the reporter identity only

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
  }

  tags = {
    env     = var.environment
    purpose = "grc-evidence-worm"
    company = "fafo"
  }
}

resource "azurerm_storage_container" "reports" {
  name                  = "reports"
  storage_account_id    = azurerm_storage_account.evidence.id
  container_access_type = "private"
}

# Unlocked by design: locked WORM cannot be shortened or removed by anyone,
# including course/capstone teardown. Unlocked still rejects every delete and
# overwrite attempt for the retention window — the property under test — while
# leaving `terraform destroy` a path that works.
resource "azurerm_storage_container_immutability_policy" "reports_worm" {
  storage_container_resource_manager_id = azurerm_storage_container.reports.id
  immutability_period_in_days           = var.immutability_period_days
}

# --- Function runtime storage — separate account, NOT the evidence store.
#     Azure Functions' internal bookkeeping (locks, triggers, host state) needs
#     shared-key access; keeping it off the evidence account is what lets the
#     evidence account itself run fully keyless. Documented exception, isolated
#     to a single-purpose resource. ---

resource "azurerm_storage_account" "func_runtime" {
  name                     = "stfafofunc${var.environment}${substr(sha256(azurerm_cosmosdb_account.fafo.id), 0, 6)}"
  resource_group_name      = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  location                 = var.functions_location
  account_tier             = "Standard"
  account_replication_type = "LRS"
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

# --- Collector Function App ---

resource "azurerm_service_plan" "collector" {
  name                = "asp-fafo-collector-${var.environment}"
  resource_group_name = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  location            = var.functions_location
  os_type             = "Linux"
  sku_name            = "Y1"
}

resource "azurerm_linux_function_app" "collector" {
  name                = "func-fafo-collector-${var.environment}"
  resource_group_name = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  location            = var.functions_location

  storage_account_name       = azurerm_storage_account.func_runtime.name
  storage_account_access_key = azurerm_storage_account.func_runtime.primary_access_key
  service_plan_id            = azurerm_service_plan.collector.id
  https_only                 = true

  site_config {
    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = {
    COSMOS_ENDPOINT = azurerm_cosmosdb_account.fafo.endpoint
    MG_SCOPE        = local.mg_id
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    env     = var.environment
    purpose = "grc-evidence-collector"
    company = "fafo"
  }
}

# --- Least-privilege identity for the collector ---
# Reader on the sandbox management group: enough to list policy compliance
# states there, nothing that can change a resource.
resource "azurerm_role_assignment" "collector_policy_reader" {
  scope                = local.mg_id
  role_definition_name = "Reader"
  principal_id         = azurerm_linux_function_app.collector.identity[0].principal_id
}

# Cosmos DB Built-in Data Contributor — write access, but ONLY to this Cosmos
# account, and only via Azure AD (local_authentication_disabled above forces
# every writer through this exact role assignment; there is no other door in).
resource "azurerm_cosmosdb_sql_role_assignment" "collector_cosmos_write" {
  resource_group_name = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  account_name        = azurerm_cosmosdb_account.fafo.name
  role_definition_id  = "${azurerm_cosmosdb_account.fafo.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = azurerm_linux_function_app.collector.identity[0].principal_id
  scope               = azurerm_cosmosdb_account.fafo.id
}

# The deployer (you) also needs Cosmos write — to run the one-time seed script
# that writes the controls/mappings crosswalk.
resource "azurerm_cosmosdb_sql_role_assignment" "deployer_cosmos_write" {
  resource_group_name = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  account_name        = azurerm_cosmosdb_account.fafo.name
  role_definition_id  = "${azurerm_cosmosdb_account.fafo.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = var.deployer_principal_id
  scope               = azurerm_cosmosdb_account.fafo.id
}

# The deployer also needs blob write on the evidence storage account, to
# smoke-test the WORM proof (upload + failed-delete) documented in docs/.
resource "azurerm_role_assignment" "deployer_blob_write" {
  scope                = azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = var.deployer_principal_id
}
