# Four original controls, each mapped to a distinct NIST CSF 2.0 function (see
# docs/CONTROLS.md for the full crosswalk). Each is Custom/Indexed and scoped to
# mg-fafo-sandbox — this capstone's blast-radius boundary, never mg-fafo itself.

# --- ID.AM (Identify — Asset Management): every governed resource is discoverable
#     by its type prefix. An un-prefixed resource is, by definition, not inventoried. ---

resource "azurerm_policy_definition" "naming_convention" {
  name                = "fafo-enforce-naming-convention"
  display_name        = "FAFO Inc.: resource names must carry the fafo type prefix"
  description         = "Denies storage accounts, key vaults, app services, and Cosmos accounts whose name doesn't start with their required prefix (stfafo-, kv-fafo-, app-fafo-, cosmos-fafo-). Asset inventory starts with a name you can grep for."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  policy_rule = jsonencode({
    if = {
      anyOf = [
        { allOf = [
          { field = "type", equals = "Microsoft.Storage/storageAccounts" },
          { field = "name", notLike = "stfafo*" }
        ] },
        { allOf = [
          { field = "type", equals = "Microsoft.KeyVault/vaults" },
          { field = "name", notLike = "kv-fafo-*" }
        ] },
        { allOf = [
          { field = "type", equals = "Microsoft.Web/sites" },
          { field = "name", notLike = "app-fafo-*" }
        ] },
        { allOf = [
          { field = "type", equals = "Microsoft.DocumentDB/databaseAccounts" },
          { field = "name", notLike = "cosmos-fafo-*" }
        ] }
      ]
    }
    then = {
      effect = "[parameters('effect')]"
    }
  })

  parameters = jsonencode({
    effect = {
      type = "String"
      metadata = {
        displayName = "Effect"
      }
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Deny"
    }
  })
}

# --- PR.PS (Protect — Platform Security): a Key Vault reachable from the public
#     internet is a hardening gap regardless of what secrets it holds. FAFO Inc.'s
#     health-records data model makes this non-negotiable, not situational. ---

resource "azurerm_policy_definition" "deny_kv_public_network" {
  name                = "fafo-deny-kv-public-network"
  display_name        = "FAFO Inc.: Key Vaults must not allow public network access"
  description         = "Denies creation or update of a Key Vault where publicNetworkAccess is not Disabled."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.KeyVault/vaults" },
        { field = "Microsoft.KeyVault/vaults/publicNetworkAccess", notEquals = "Disabled" }
      ]
    }
    then = {
      effect = "[parameters('effect')]"
    }
  })

  parameters = jsonencode({
    effect = {
      type = "String"
      metadata = {
        displayName = "Effect"
      }
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Deny"
    }
  })
}

# --- PR.DS (Protect — Data Security): data in transit to any app service must use
#     TLS 1.2 at minimum. ---

resource "azurerm_policy_definition" "require_min_tls" {
  name         = "fafo-require-min-tls-12"
  display_name = "FAFO Inc.: App Services must require TLS 1.2 minimum"
  description  = "Audits or denies App Service 'web' config resources whose minimum TLS version is below 1.2."
  policy_type  = "Custom"
  # "All" (not "Indexed"): Microsoft.Web/sites/config is a child resource and
  # doesn't support tags/location, so Indexed mode would silently skip it.
  mode                = "All"
  management_group_id = azurerm_management_group.sandbox.id

  # Targets Microsoft.Web/sites/config directly rather than aliasing in from
  # Microsoft.Web/sites — that alias (Microsoft.Web/sites/config/web.minTlsVersion)
  # resolves against BOTH resource types, and Azure's policy compiler rejects
  # the definition with MultiTargetPolicyNotApplicable because the "type equals
  # Microsoft.Web/sites" guard can never be satisfied by the config child
  # resource the alias actually belongs to. Targeting the child type directly
  # removes the ambiguity.
  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.Web/sites/config" },
        { field = "name", equals = "web" },
        { field = "Microsoft.Web/sites/config/minTlsVersion", less = "1.2" }
      ]
    }
    then = {
      effect = "[parameters('effect')]"
    }
  })

  parameters = jsonencode({
    effect = {
      type = "String"
      metadata = {
        displayName = "Effect"
      }
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
  })
}

# --- DE.CM (Detect — Continuous Monitoring): every Key Vault's audit events must
#     reach the Log Analytics workspace. DeployIfNotExists so onboarding a vault
#     without diagnostics gets fixed, not just flagged. ---

resource "azurerm_policy_definition" "kv_diagnostics_dine" {
  name                = "fafo-dine-kv-diagnostics"
  display_name        = "FAFO Inc.: deploy Key Vault diagnostic settings if missing"
  description         = "If a Key Vault has no diagnostic setting sending AuditEvent logs to law-fafo-sandbox, deploys one."
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  policy_rule = jsonencode({
    if = {
      field  = "type"
      equals = "Microsoft.KeyVault/vaults"
    }
    then = {
      effect = "[parameters('effect')]"
      details = {
        type = "Microsoft.Insights/diagnosticSettings"
        existenceCondition = {
          allOf = [
            { field = "Microsoft.Insights/diagnosticSettings/logs[*].category", equals = "AuditEvent" },
            { field = "Microsoft.Insights/diagnosticSettings/logs[*].enabled", equals = "true" }
          ]
        }
        roleDefinitionIds = [
          # Monitoring Contributor — the narrowest built-in that can write diagnostic settings
          "/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa"
        ]
        deployment = {
          properties = {
            mode = "incremental"
            parameters = {
              vaultName   = { value = "[field('name')]" }
              workspaceId = { value = "[parameters('workspaceId')]" }
            }
            template = {
              "$schema"      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              parameters = {
                vaultName   = { type = "string" }
                workspaceId = { type = "string" }
              }
              resources = [
                {
                  type       = "Microsoft.KeyVault/vaults/providers/diagnosticSettings"
                  apiVersion = "2021-05-01-preview"
                  name       = "[concat(parameters('vaultName'), '/Microsoft.Insights/fafo-kv-to-law')]"
                  properties = {
                    workspaceId = "[parameters('workspaceId')]"
                    logs = [
                      { category = "AuditEvent", enabled = true }
                    ]
                  }
                }
              ]
            }
          }
        }
      }
    }
  })

  parameters = jsonencode({
    effect = {
      type = "String"
      metadata = {
        displayName = "Effect"
      }
      allowedValues = ["DeployIfNotExists", "AuditIfNotExists", "Disabled"]
      defaultValue  = "DeployIfNotExists"
    }
    workspaceId = {
      type = "String"
      metadata = {
        displayName = "Log Analytics workspace resource ID"
      }
    }
  })
}

# --- The initiative bundling all four, one assignment, one identity ---

resource "azurerm_policy_set_definition" "fafo_baseline" {
  name                = "fafo-grc-baseline"
  display_name        = "FAFO Inc. GRC Baseline"
  policy_type         = "Custom"
  management_group_id = azurerm_management_group.sandbox.id

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.naming_convention.id
    reference_id         = "namingConvention"
    parameter_values = jsonencode({
      effect = { value = "[parameters('namingEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.deny_kv_public_network.id
    reference_id         = "kvPublicNetwork"
    parameter_values = jsonencode({
      effect = { value = "[parameters('kvNetworkEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.require_min_tls.id
    reference_id         = "minTls"
    parameter_values = jsonencode({
      effect = { value = "[parameters('tlsEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.kv_diagnostics_dine.id
    reference_id         = "kvDiagnostics"
    parameter_values = jsonencode({
      effect      = { value = "DeployIfNotExists" }
      workspaceId = { value = "[parameters('workspaceId')]" }
    })
  }

  parameters = jsonencode({
    namingEffect    = { type = "String", defaultValue = "Deny" }
    kvNetworkEffect = { type = "String", defaultValue = "Deny" }
    tlsEffect       = { type = "String", defaultValue = "Audit" }
    workspaceId     = { type = "String" }
  })
}

resource "azurerm_management_group_policy_assignment" "fafo_baseline" {
  name                 = "fafo-grc-baseline"
  display_name         = "FAFO Inc. GRC Baseline"
  policy_definition_id = azurerm_policy_set_definition.fafo_baseline.id
  management_group_id  = azurerm_management_group.sandbox.id
  location             = var.location

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.remediation.id]
  }

  parameters = jsonencode({
    namingEffect    = { value = var.naming_convention_policy_effect }
    kvNetworkEffect = { value = var.kv_public_network_policy_effect }
    tlsEffect       = { value = var.min_tls_version_policy_effect }
    workspaceId     = { value = azurerm_log_analytics_workspace.fafo.id }
  })
}

# The remediation identity earns Monitoring Contributor only at assignment scope —
# narrow enough to deploy a diagnostic setting, nowhere near enough to do anything else.
resource "azurerm_role_assignment" "remediation_monitoring" {
  scope                = azurerm_management_group.sandbox.id
  role_definition_name = "Monitoring Contributor"
  principal_id         = azurerm_user_assigned_identity.remediation.principal_id
}
