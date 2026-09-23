# Gate rule that dogfoods stage 01's own naming-convention policy: if a resource
# would fail fafo-enforce-naming-convention once deployed, conftest should say
# so before the apply, not leave it for Azure Policy to catch after the fact.
package main

import rego.v1

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	name := rc.change.after.name
	not startswith(name, "stfafo")
	msg := sprintf("%s: storage account name %q must start with 'stfafo' (FAFO Inc. naming convention, mirrors stages/01-foundation/policies.tf)", [rc.address, name])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_cosmosdb_account"
	name := rc.change.after.name
	not startswith(name, "cosmos-fafo-")
	msg := sprintf("%s: Cosmos account name %q must start with 'cosmos-fafo-'", [rc.address, name])
}
