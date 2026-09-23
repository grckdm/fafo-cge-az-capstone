# ---------------------------------------------------------------------------
# DISCOVERY: read the live Defender for Cloud pricing tier for every plan in
# var.baseline_defender_plans BEFORE any resource below decides to change it.
# Run `terraform plan` a hundred times against a subscription where nothing
# changed and this section produces zero diffs — it only reads.
# ---------------------------------------------------------------------------

data "azapi_resource" "defender_pricing" {
  for_each = var.baseline_defender_plans

  type                   = "Microsoft.Security/pricings@2024-01-01"
  parent_id              = data.azurerm_subscription.current.id
  name                   = each.key
  response_export_values = ["properties.pricingTier"]
}

locals {
  # What's actually on, right now, independent of what this stage wants.
  current_defender_tier = {
    for plan, d in data.azapi_resource.defender_pricing :
    plan => d.output.properties.pricingTier
  }

  # The gap: baseline plans not already Standard. An INVENTORY output, not a
  # resource key — keying the activation resource on live tier would make
  # Terraform destroy the plan it just enabled on the very next run
  # (read-your-own-writes). Keep the for_each on the static variable map below.
  defender_activation_needed = {
    for plan, tier in local.current_defender_tier : plan => tier
    if tier != "Standard"
  }
}

# ---------------------------------------------------------------------------
# ACTIVATION: converge every baseline plan to Standard. Idempotent — a plan
# already Standard (enabled by hand, or by a previous apply) stays exactly as
# it is, now under change management. `terraform destroy` flips these back to
# Free, which is exactly what sandbox teardown wants.
# ---------------------------------------------------------------------------

resource "azurerm_security_center_subscription_pricing" "baseline" {
  for_each = var.baseline_defender_plans

  tier          = "Standard"
  resource_type = each.key
  subplan       = each.value != "" ? each.value : null
}
