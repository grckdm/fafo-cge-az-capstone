# FAFO Inc. GRC Pipeline — Control Catalog & Framework Crosswalk

This is the map from code to control. Every policy, the collector, both report
generators, and every CI gate rule are listed here with the NIST CSF 2.0
category they serve. Keep this file current with `stages/*/policies.tf`,
`functions/*/function_app.py`, and `policy/*.rego` — if one changes, this does
too, in the same PR.

CSF 2.0 is the primary crosswalk. Each control also carries a HIPAA Security
Rule safeguard as an additive second layer (FAFO Inc.'s consumer-credit data
model overlaps meaningfully with regulated personal data handling, even though
this capstone targets CSF 2.0, not a HIPAA audit) — it supplements the CSF
mapping, it doesn't replace it.

## Policy controls (stages/01-foundation/policies.tf, stages/04-enforcement/main.tf)

| Control ID | Resource type | Default effect | CSF 2.0 category | HIPAA safeguard | What it does |
|---|---|---|---|---|---|
| `fafo-enforce-naming-convention` | Storage, Key Vault, App Service, Cosmos DB | Deny | **ID.AM** — Asset Management | §164.310(d)(1) Device and Media Controls | Denies any of these resource types not carrying its required name prefix (`stfafo-`, `kv-fafo-`, `app-fafo-`, `cosmos-fafo-`). Asset inventory starts with a name you can grep for. |
| `fafo-deny-kv-public-network` | Key Vault | Deny | **PR.PS** — Platform Security | §164.312(a)(1) Access Control | Denies a Key Vault unless `publicNetworkAccess` is `Disabled`. |
| `fafo-require-min-tls-12` | App Service | Audit | **PR.DS** — Data Security | §164.312(e)(2)(ii) Encryption (Transmission Security, addressable) | Flags App Services below TLS 1.2. New control, starts in Audit; `fafo-fix-min-tls-12` below is its escalation path. |
| `fafo-dine-kv-diagnostics` | Key Vault | DeployIfNotExists | **DE.CM** — Continuous Monitoring | §164.312(b) Audit Controls | Deploys a diagnostic setting sending `AuditEvent` logs to `law-fafo-sandbox` if one doesn't already exist. |
| `fafo-fix-min-tls-12` (stage 04) | App Service | Modify, ladder-controlled | **PR.DS** — Data Security *(same safeguard as its parent control above — this is the remediation mechanism for `fafo-require-min-tls-12`, not a separate control)* | | Sets `minTlsVersion` to `1.2` on non-compliant App Services once `remediation_mode` passes `audit`. |

### Blast-radius notes (every write-capable policy)

**`fafo-dine-kv-diagnostics`**
- **What changes:** adds one `Microsoft.Insights/diagnosticSettings` sub-resource per Key Vault, named `fafo-kv-to-law`. Additive only — never modifies or removes anything already on the vault.
- **What could break:** a vault already at Azure's 5-diagnostic-setting cap would fail this deployment (audit-log-only failure, vault itself unaffected). Not expected at capstone scale.
- **Rollback:** set the initiative's `kvNetworkEffect`/DINE effect to `Disabled` and re-apply, or `terraform destroy` stage 01's policy assignment. Diagnostic settings already deployed are left in place — rollback stops future remediation, it does not undo a monitoring improvement already made.

**`fafo-fix-min-tls-12`**
- **What changes:** rewrites `Microsoft.Web/sites/config/web.minTlsVersion` to `1.2` on any App Service found below it.
- **What could break:** any client or integration that only speaks TLS 1.0/1.1 loses connectivity to that app immediately. This is the control working as intended, but it is a real, user-facing compatibility break — not a rollback-free operation from the client's perspective.
- **Rollback:** set `remediation_mode` back to `"audit"` and apply — stops further remediation instantly (the role grant that lets the identity write App Service config is only created when `remediation_mode != "audit"`, so reverting removes the *capability*, not just the assignment's enforce flag). Already-remediated apps stay at TLS 1.2; they are not reverted. An app that legitimately needs a lower minimum temporarily should get a scoped Azure Policy exemption, not a global mode rollback.

## Evidence collector (functions/collect_controls/function_app.py)

| Component | CSF 2.0 category | HIPAA safeguard | What it does |
|---|---|---|---|
| `collect_now` / `collect_nightly` | **DE.CM** — Continuous Monitoring | §164.312(b) Audit Controls | Pulls Azure Policy compliance states for every control above from `mg-fafo-sandbox`, upserts one document per (policy, resource) pair into the `findings` container, deterministic ID (SHA-256 of policy+resource), stamped with `runId` and `collectedAt`. This IS the continuous-monitoring mechanism the DE.CM category calls for — it's not a separate concept from control #4 above, it's the general-purpose version of it. |

## Report generators (functions/reports/function_app.py)

| Report | CSF 2.0 category | What it does |
|---|---|---|
| Statement of Applicability (`soa_now` / `soa_weekly`) | **GV.OV** — Oversight | Every control in the catalog, its applicability, and its current compliance rollup from the latest collection run. Read from Cosmos only — never calls a live Azure API. |
| Audit Summary (`audit_now` / `audit_daily`) | **DE.AE** — Adverse Event Analysis | The latest run's non-compliant resources, each joined against its CSF category via the `mappings` container. Same store-only read discipline as the SoA. |

Both write dated JSON + Markdown pairs to the WORM `reports` container with
`overwrite=False` — a same-day re-run finds the day's artifact already there
(the immutability policy would refuse the overwrite regardless of the flag).
The failed-delete proof for this container: upload any test blob, then attempt
`az storage blob delete` on it — the delete fails with `BlobImmutableDueToPolicy`
for the full retention window (120 days by default), for every identity
including Owner.

## CI gate rules (policy/*.rego)

| File | CSF 2.0 category | What it checks |
|---|---|---|
| `storage.rego` | **PR.DS** — Data Security | No storage account in a plan may allow public blob access or shared-key access (except Function runtime storage, the documented exception). |
| `identity.rego` | **PR.AA** — Identity Management, Authentication, and Access Control | No role assignment may grant Owner or Contributor; every management-group policy assignment must carry an identity block. |
| `naming.rego` | **ID.AM** — Asset Management | Dogfoods `fafo-enforce-naming-convention` at plan time — storage and Cosmos account names must match the required prefix before Azure Policy ever sees them. |

Verified against `policy/examples/good-plan.json` (0 failures) and
`policy/examples/bad-plan.json` (6 failures, one per rule instance) — both
fixtures are checked in CI's `policy-self-test` job on every run, so a rule
regression fails the pipeline even if no real Terraform plan changed.

## Stage flow and identity boundaries

```
01-foundation  →  02-evidence-store  →  03-reporting
      ↓                                       ↑
      └───────────────  04-enforcement  ──────┘
```

Composition is through `terraform_remote_state` outputs only — no stage
reaches into another stage's resources directly. Four identities, each
single-purpose:

| Identity | Created in | Roles held | Cannot do |
|---|---|---|---|
| `id-fafo-remediation-dev` | 01 | Reader @ mg; Monitoring Contributor @ mg (01); Website Contributor @ mg, only when `remediation_mode != audit` (04) | Cannot touch any resource type outside its two policies' `roleDefinitionIds`; never Owner/Contributor |
| Collector Function App (system-assigned) | 02 | Reader @ mg (policy states); Cosmos DB Built-in Data Contributor | Cannot write reports, cannot read anything outside its Cosmos account |
| Reporter Function App (system-assigned) | 03 | Cosmos DB Built-in Data Reader (read-only); Storage Blob Data Contributor (evidence storage) | Cannot write to Cosmos — cannot author evidence, only consume it; holds no Policy/Security read role — cannot pull live platform state, every number it prints traces back to a stored document |
| Deployer (you) | n/a | Storage Blob Data Contributor (state RG, evidence storage); Cosmos DB Built-in Data Contributor (seed script only) | Not used by any running pipeline component — human-only, for bootstrap and the WORM proof |

The collector/reporter split is the load-bearing separation-of-duties boundary
in this design: the identity that can put evidence into the store is
structurally incapable of writing the reports that read it back out.
