# --- The governed hierarchy ---
# mg-fafo is the root for every FAFO Inc. cloud program; mg-fafo-sandbox is this
# capstone's blast-radius boundary. Production business units would nest as siblings
# under mg-fafo, never under the sandbox.

resource "azurerm_management_group" "fafo" {
  name         = "mg-fafo"
  display_name = "FAFO Inc. Cloud Governance"
}

resource "azurerm_management_group" "sandbox" {
  name                       = "mg-fafo-sandbox"
  display_name               = "FAFO Inc. GRC Sandbox"
  parent_management_group_id = azurerm_management_group.fafo.id

  subscription_ids = [data.azurerm_subscription.current.subscription_id]
}

# --- The sandbox resource group ---

resource "azurerm_resource_group" "sandbox" {
  name     = "rg-fafo-sandbox-${var.environment}"
  location = var.location
  tags = {
    env     = var.environment
    owner   = var.owner_email
    purpose = "cge-az-capstone"
    company = "fafo"
  }
}

# --- Log Analytics workspace — the destination for every diagnostic setting and the
#     KQL drift tripwire this pipeline relies on ---

resource "azurerm_log_analytics_workspace" "fafo" {
  name                = "law-fafo-sandbox"
  location            = var.location
  resource_group_name = azurerm_resource_group.sandbox.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags = {
    env     = var.environment
    purpose = "cge-az-capstone"
    company = "fafo"
  }
}

# Routes the SUBSCRIPTION's Activity Log to the workspace — without this, the
# AzureActivity table never receives a row and drift-detection's KQL tripwire
# (stages/../.github/workflows/drift-detection.yml) queries an empty table
# forever. Only captures events from this point forward; anything that
# happened before this resource existed was never seen by design.
resource "azurerm_monitor_diagnostic_setting" "activity_log_to_law" {
  name                       = "fafo-activity-to-law"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.fafo.id

  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Policy"
  }
  enabled_log {
    category = "Alert"
  }
}

# --- Evidence resource group — stage 02 fills this with the Cosmos + WORM store ---

resource "azurerm_resource_group" "evidence" {
  name     = "rg-fafo-evidence-${var.environment}"
  location = var.location
  tags = {
    env     = var.environment
    owner   = var.owner_email
    purpose = "grc-evidence-plane"
    company = "fafo"
  }
}

# --- Remediation identity — the single, narrowly-scoped principal every enforcement
#     policy in stage 04 executes as. Created here, not in stage 04, so it exists
#     before any policy assignment that references it, and so its role grants stay
#     auditable in one place regardless of which stage is currently deployed. ---

resource "azurerm_user_assigned_identity" "remediation" {
  name                = "id-fafo-remediation-${var.environment}"
  resource_group_name = azurerm_resource_group.sandbox.name
  location            = var.location
  tags = {
    env     = var.environment
    purpose = "policy-remediation"
    company = "fafo"
  }
}

# Read access to its own scope's diagnostic/monitoring state — the narrowest built-in
# role that lets the identity's DINE remediation confirm what it just deployed.
resource "azurerm_role_assignment" "remediation_reader" {
  scope                = azurerm_management_group.sandbox.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.remediation.principal_id
}
