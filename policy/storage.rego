# Gate rule: FAFO Inc.'s own storage must meet FAFO Inc.'s own hygiene bar before it
# ever reaches the pipeline that enforces the same bar on everything else.
package main

import rego.v1

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.change.after.allow_nested_items_to_be_public == true
	msg := sprintf("%s: storage accounts must not allow public blob access", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.change.after.shared_access_key_enabled == true
	not contains(rc.name, "runtime")
	msg := sprintf("%s: shared key access must be disabled (identity-only) — Function runtime storage accounts (name contains 'runtime') are the documented exception", [rc.address])
}
