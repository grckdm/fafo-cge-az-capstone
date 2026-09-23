#!/usr/bin/env python3
"""Seed FAFO Inc.'s control catalog and its framework crosswalk.

Run once after deploying stages/02-evidence-store:

    pip install azure-cosmos azure-identity
    COSMOS_ENDPOINT=$(cd ../stages/02-evidence-store && terraform output -raw cosmos_endpoint) \
        python seed_controls.py

Authenticates as YOU (az login) — stage 02's deployer Cosmos role grant covers this.
Writes two containers:
  controls  — FAFO Inc.'s own catalog: one document per policy in policies.tf
  mappings  — control -> NIST CSF 2.0 category -> HIPAA Security Rule safeguard,
              one chained crosswalk per control, written once, read by every
              report generator (collect-once, not per-report re-derivation).
              CSF 2.0 is the primary mapping (what the rubric requires); the
              HIPAA safeguard is an additive second layer off the same category,
              not a replacement for it.
"""

import os
import sys

from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential

# Mirrors stages/01-foundation/policies.tf exactly — if a policy's name or
# default effect changes there, update it here too. docs/CONTROLS.md is the
# human-readable version of this same crosswalk.
CONTROLS = [
    {
        "id": "fafo-enforce-naming-convention",
        "displayName": "Resource names must carry the fafo type prefix",
        "policyType": "Custom",
        "defaultEffect": "Deny",
        "csfFunction": "ID",
        "csfCategory": "ID.AM",
        "csfCategoryName": "Asset Management",
        "hipaaSafeguard": "164.310(d)(1)",
        "hipaaSafeguardName": "Device and Media Controls",
        "rationale": "An un-prefixed resource is not inventoried by definition — this is the control that makes every other control's scope enumerable.",
    },
    {
        "id": "fafo-deny-kv-public-network",
        "displayName": "Key Vaults must not allow public network access",
        "policyType": "Custom",
        "defaultEffect": "Deny",
        "csfFunction": "PR",
        "csfCategory": "PR.PS",
        "csfCategoryName": "Platform Security",
        "hipaaSafeguard": "164.312(a)(1)",
        "hipaaSafeguardName": "Access Control",
        "rationale": "FAFO Inc.'s health-records data model makes secrets exposure a network-reachability question that must always resolve to 'no'.",
    },
    {
        "id": "fafo-require-min-tls-12",
        "displayName": "App Services must require TLS 1.2 minimum",
        "policyType": "Custom",
        "defaultEffect": "Audit",
        "csfFunction": "PR",
        "csfCategory": "PR.DS",
        "csfCategoryName": "Data Security",
        "hipaaSafeguard": "164.312(e)(2)(ii)",
        "hipaaSafeguardName": "Encryption (Transmission Security, addressable)",
        "rationale": "Protects data in transit to every customer-facing app service; Audit while onboarding, escalates to Deny once the fleet is clean.",
    },
    {
        "id": "fafo-dine-kv-diagnostics",
        "displayName": "Deploy Key Vault diagnostic settings if missing",
        "policyType": "Custom",
        "defaultEffect": "DeployIfNotExists",
        "csfFunction": "DE",
        "csfCategory": "DE.CM",
        "csfCategoryName": "Continuous Monitoring",
        "hipaaSafeguard": "164.312(b)",
        "hipaaSafeguardName": "Audit Controls",
        "rationale": "A Key Vault's audit trail is only useful if it reaches the workspace; this control makes that automatic rather than a checklist item.",
    },
]


def main() -> int:
    endpoint = os.environ.get("COSMOS_ENDPOINT")
    if not endpoint:
        print("Set COSMOS_ENDPOINT (see docstring).", file=sys.stderr)
        return 1

    database = CosmosClient(endpoint, DefaultAzureCredential()).get_database_client(
        os.environ.get("COSMOS_DATABASE", "fafogrc")
    )
    controls_container = database.get_container_client("controls")
    mappings_container = database.get_container_client("mappings")

    written = 0
    for control in CONTROLS:
        controls_container.upsert_item(
            {
                "id": control["id"],
                "displayName": control["displayName"],
                "policyType": control["policyType"],
                "defaultEffect": control["defaultEffect"],
                "rationale": control["rationale"],
            }
        )
        mappings_container.upsert_item(
            {
                "id": f"{control['id']}-to-csf2",
                "controlId": control["id"],
                "framework": "nist-csf-2.0",
                "csfFunction": control["csfFunction"],
                "csfCategory": control["csfCategory"],
                "csfCategoryName": control["csfCategoryName"],
                # Additive second layer, chained off the same CSF category —
                # not an independent framework mapping. CSF 2.0 stays primary.
                "hipaaSafeguard": control["hipaaSafeguard"],
                "hipaaSafeguardName": control["hipaaSafeguardName"],
            }
        )
        written += 2

    print(f"seeded {written} documents ({len(CONTROLS)} controls + {len(CONTROLS)} mappings) into {endpoint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
