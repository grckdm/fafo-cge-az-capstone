# Deliberately non-compliant resource, for a one-time CI gate demonstration PR.
# Violates: naming convention (bad prefix), public blob access, shared key access.
# This file is removed before the PR is closed — never merged to main.
resource "azurerm_storage_account" "gate_test_bad" {
  name                             = "badnametest12345"
  resource_group_name              = azurerm_resource_group.sandbox.name
  location                         = var.location
  account_tier                     = "Standard"
  account_replication_type         = "LRS"
  allow_nested_items_to_be_public  = true
  shared_access_key_enabled        = true
}
