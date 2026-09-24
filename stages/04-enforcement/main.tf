locals {
  mg_id           = data.terraform_remote_state.foundation.outputs.management_group_id
  remediation_id  = data.terraform_remote_state.foundation.outputs.remediation_identity_id
  remediation_pid = data.terraform_remote_state.foundation.outputs.remediation_identity_principal_id

  effect           = var.remediation_mode == "audit" ? "Audit" : "Modify"
  enforcement_mode = var.remediation_mode == "enforce" ? "Default" : "DoNotEnforce"
}

# Blast radius: sets minTlsVersion to '1.2' on existing App Service 'web'
# config resources that are below it. Cannot delete anything, cannot touch any
# other property, cannot reach any resource type but Microsoft.Web/sites/config.
# Rollback: set remediation_mode back to "audit" and apply — the Modify effect
# stops firing; nothing it already fixed reverts on its own (by design: a
# rollback of the CONTROL is not a rollback of resources already made safer).
#
# Targets Microsoft.Web/sites/config directly (matching stages/01-foundation's
# fafo-require-min-tls-12) rather than aliasing in from Microsoft.Web/sites —
# that alias resolves against both resource types and Azure's policy compiler
# rejects the definition outright (MultiTargetPolicyNotApplicable) if the "if"
# clause's type guard can never be satisfied by the resource type the alias
# actually belongs to.
resource "azurerm_policy_definition" "fix_min_tls" {
  name                = "fafo-fix-min-tls-12"
  display_name        = "FAFO Inc.: remediate App Service TLS below 1.2 (${var.remediation_mode})"
  policy_type         = "Custom"
  mode                = "All"
  management_group_id = local.mg_id

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.Web/sites/config" },
        { field = "name", equals = "web" },
        { field = "Microsoft.Web/sites/config/minTlsVersion", less = "1.2" }
      ]
    }
    "then" = {
      effect = local.effect
      details = local.effect == "Audit" ? null : {
        roleDefinitionIds = [
          # Website Contributor — the narrowest built-in that can write App Service config
          "/providers/Microsoft.Authorization/roleDefinitions/de139f84-1756-47ae-9be6-808fbbe84772"
        ]
        conflictEffect = "audit"
        operations = [
          { operation = "addOrReplace", field = "Microsoft.Web/sites/config/minTlsVersion", value = "1.2" }
        ]
      }
    }
  })
}

resource "azurerm_management_group_policy_assignment" "fix_min_tls" {
  name                 = "fafo-fix-min-tls-12"
  display_name         = "FAFO Inc.: remediate App Service TLS (${var.remediation_mode})"
  policy_definition_id = azurerm_policy_definition.fix_min_tls.id
  management_group_id  = local.mg_id
  location             = var.location
  enforce              = local.enforcement_mode == "Default"

  identity {
    type         = "UserAssigned"
    identity_ids = [local.remediation_id]
  }
}

# The remediation identity earns write access to App Service config ONLY when
# remediation can actually run — an audit-only ladder rung holds no write role
# at all, so there is nothing for the identity to do even if misconfigured.
resource "azurerm_role_assignment" "remediation_website_contributor" {
  count                = var.remediation_mode == "audit" ? 0 : 1
  scope                = local.mg_id
  role_definition_name = "Website Contributor"
  principal_id         = local.remediation_pid
}

output "remediation_mode" {
  value = var.remediation_mode
}
