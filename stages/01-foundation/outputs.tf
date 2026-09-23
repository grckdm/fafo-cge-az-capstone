output "management_group_id" {
  description = "mg-fafo-sandbox ID — later stages assign policy here, never re-create it."
  value       = azurerm_management_group.sandbox.id
}

output "sandbox_resource_group_name" {
  value = azurerm_resource_group.sandbox.name
}

output "evidence_resource_group_name" {
  value = azurerm_resource_group.evidence.name
}

output "evidence_resource_group_id" {
  value = azurerm_resource_group.evidence.id
}

output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.fafo.id
}

output "remediation_identity_id" {
  description = "Consumed by stage 04's policy assignment identity block."
  value       = azurerm_user_assigned_identity.remediation.id
}

output "remediation_identity_principal_id" {
  value = azurerm_user_assigned_identity.remediation.principal_id
}

output "location" {
  value = var.location
}

output "current_defender_tiers" {
  description = "Live-read tier of every baseline Defender plan at the moment this plan ran — the discovery half of discovery-first."
  value       = local.current_defender_tier
}

output "defender_activation_needed" {
  description = "Baseline plans that were NOT already Standard when this plan ran. Empty means the subscription's Defender posture already matched the baseline before this stage touched anything."
  value       = local.defender_activation_needed
}
