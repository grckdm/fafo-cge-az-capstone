# Gate rules for identity and role design: no broad role ever granted, and no
# remediation-capable policy assignment ever deployed without the identity that
# makes remediation actually run (a silent no-op is worse than an honest error).
package main

import rego.v1

broad_roles := {"Owner", "Contributor"}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_role_assignment"
	rc.change.after.role_definition_name in broad_roles
	msg := sprintf("%s: role assignments must not grant %q — every identity in this pipeline gets the narrowest built-in role its job requires", [rc.address, rc.change.after.role_definition_name])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_management_group_policy_assignment"
	# object.get with a null default normalizes "key absent" and "key explicitly
	# null" to the same value — plain `not rc.change.after.identity` does NOT
	# catch an explicit JSON null, since Rego's `not` only fires on `false` or
	# undefined, never on a defined-but-null value.
	object.get(rc.change.after, "identity", null) == null
	msg := sprintf("%s: policy assignments must carry an identity block — Modify/DeployIfNotExists effects silently no-op without one", [rc.address])
}
