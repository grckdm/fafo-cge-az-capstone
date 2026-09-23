# FAFO Inc. — GRC Engineering Pipeline (CGE-AZ Capstone)

FAFO Inc. operates across nearly every global consumer sector — technology,
banking, utilities, media — and controls roughly 70% of the global consumer
credit and debt industry. That scale means two things for this repo: the
blast radius of a misconfigured Key Vault or an unencrypted transit path isn't
hypothetical, and an assessor asking "prove it" needs an answer that traces to
a stored record, not a screenshot.

This repo is FAFO Inc.'s answer: a pipeline that governs its own sandbox
Azure subscription as code, collects evidence of its own compliance posture on
a schedule, generates reports that read only from that evidence, gates its own
changes in CI, and demonstrates a full detect → remediate → verify loop with a
human approval gate in the middle.

It was built as the capstone for the CGE-AZ (Certified GRC Engineer — Azure
Specialty) certification: an original design following the course's pipeline
pattern, not a copy of the course's reference solution.

## Architecture

```
stages/01-foundation      management group hierarchy, sandbox + evidence RGs,
                           Log Analytics workspace, remediation identity,
                           discovery-first Defender activation, 4 policies

stages/02-evidence-store   Cosmos DB (findings/controls/mappings), WORM report
                           storage, collector Function App

stages/03-reporting        reporter Function App (Statement of Applicability +
                           Audit Summary), reads Cosmos only

stages/04-enforcement      escalation-ladder remediation policy (audit / dry-run
                           / enforce), reuses stage 01's remediation identity
```

Full control-by-control mapping to NIST CSF 2.0 (plus a HIPAA Security Rule
crosswalk) is in [`docs/CONTROLS.md`](docs/CONTROLS.md) — that's the
authoritative list, kept current with the code.

## Prerequisites

- An Azure subscription where you can create management groups (a personal/free
  subscription works; most corporate tenants restrict this)
- `az` CLI, logged in (`az login`)
- Terraform >= 1.9
- Python 3.11+ with `pip`
- `conftest` (for the local CI gate check)
- A way to zip a directory without nesting it (Git Bash on Windows ships no
  `zip` — use 7-Zip's `7z a archive.zip .` from inside the function folder, or WSL)
- A GitHub account, if you want the CI workflows live (optional but scored)

## Deploy from an empty subscription

All commands assume you're at the repo root unless noted.

### 1. Bootstrap remote state

```bash
./bootstrap/bootstrap-state.sh
export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
```

Creates `rg-fafo-tfstate`, a versioned/keyless storage account, the `tfstate`
container, and grants you `Storage Blob Data Contributor` (state access is a
data-plane operation — subscription Owner does not include it). Writes
`bootstrap/backend.hcl`.

### 2. Foundation

```bash
cd stages/01-foundation
terraform init -backend-config=../../bootstrap/backend.hcl
export TF_VAR_subscription_id=$ARM_SUBSCRIPTION_ID
export TF_VAR_owner_email=you@example.com
terraform plan   # read it — discovery.tf shows the Defender activation gap first
terraform apply
```

### 3. Evidence store

```bash
cd ../02-evidence-store
terraform init -backend-config=../../bootstrap/backend.hcl
export TF_VAR_subscription_id=$ARM_SUBSCRIPTION_ID
export TF_VAR_state_storage_account=$(grep storage_account_name ../../bootstrap/backend.hcl | cut -d'"' -f2)
terraform plan   # count: Cosmos + 3 containers, WORM container, 2 runtime storage accounts, collector app, 2 role grants
terraform apply  # Cosmos takes several minutes
```

Deploy the collector code:

```bash
cd ../../functions/collect_controls
7z a /tmp/collector.zip .   # or: zip -r /tmp/collector.zip .
az functionapp deployment source config-zip \
  --name $(cd ../../stages/02-evidence-store && terraform output -raw collector_function_app) \
  --resource-group rg-fafo-evidence-dev --src /tmp/collector.zip --build-remote true --timeout 600
```

Seed the control catalog and CSF/HIPAA crosswalk (collect-once, not per-report):

```bash
cd ../../seed
pip install azure-cosmos azure-identity
COSMOS_ENDPOINT=$(cd ../stages/02-evidence-store && terraform output -raw cosmos_endpoint) \
  python seed_controls.py
```

### 4. Reporting

```bash
cd ../stages/03-reporting
terraform init -backend-config=../../bootstrap/backend.hcl
export TF_VAR_subscription_id=$ARM_SUBSCRIPTION_ID
export TF_VAR_state_storage_account=$(grep storage_account_name ../../bootstrap/backend.hcl | cut -d'"' -f2)
terraform apply
```

Deploy the report generators the same way as the collector:

```bash
cd ../../functions/reports
7z a /tmp/reports.zip .
az functionapp deployment source config-zip \
  --name $(cd ../../stages/03-reporting && terraform output -raw reporting_function_app) \
  --resource-group rg-fafo-evidence-dev --src /tmp/reports.zip --build-remote true --timeout 600
```

### 5. Enforcement

```bash
cd ../../stages/04-enforcement
terraform init -backend-config=../../bootstrap/backend.hcl
export TF_VAR_subscription_id=$ARM_SUBSCRIPTION_ID
export TF_VAR_state_storage_account=$(grep storage_account_name ../../bootstrap/backend.hcl | cut -d'"' -f2)
terraform apply   # remediation_mode defaults to "dry-run" — nothing auto-remediates yet
```

### 6. Arm CI (optional but scored)

```bash
./bootstrap/arm-ci.sh <your-github-owner>
```

Add the five printed variables under **Settings → Secrets and variables →
Actions → Variables**, enable `compliance-gate` and `drift-detection` in the
Actions tab, and protect `main` requiring the `compliance-gate` check.

## Verify

- `az rest` against `Microsoft.PolicyInsights/policyStates/latest/queryResults`
  at the `mg-fafo-sandbox` scope returns compliance states for all 4 policies
- Trigger the collector's `collect_now` HTTP endpoint — response shows a
  non-zero `documents` count once Azure's policy engine has evaluated at least
  once (can take a few minutes on a brand-new assignment)
- Trigger `soa_now` and `audit_now` — both land dated JSON+Markdown pairs in
  the `reports` WORM container
- Pick a number from the Audit Summary, reproduce it with a Cosmos query
  filtered on that `runId` — same number
- Upload a test blob to `reports`, try to delete it — `BlobImmutableDueToPolicy`
- `conftest test policy/examples/bad-plan.json -p policy/` fails with 6 named violations

## Why these choices

**Region defaults (`centralus` for Functions):** Azure's Y1 consumption plan
quota is regional, and free-tier subscriptions frequently have zero quota in
`eastus`/`eastus2`. Probe your own subscription (`az functionapp list-consumption-locations`
or attempt a plan in your target region) before assuming `centralus` works for you.

**`remediation_mode` defaults to `dry-run`, not `enforce`:** a fresh
Modify/DeployIfNotExists policy should never auto-write to production-shaped
resources on its first day. Dry-run deploys the policy (so compliance data
starts accumulating) but requires a human to create the remediation task —
moving to `enforce` is a reviewed one-line variable change, not a rewrite.

**Collector and reporter are separate identities, not one "pipeline" identity:**
the identity that writes evidence should be structurally unable to also write
the reports graded against that evidence. This is the same reason auditors and
preparers are different people — enforced here by Azure RBAC scope, not by
policy.

**Cosmos is fully keyless (`local_authentication_enabled = false`):** every
reader or writer authenticates as an Azure AD identity with an explicit SQL
role assignment. There is no connection string anywhere in this repo to leak,
rotate, or accidentally commit.

**The WORM immutability policy ships unlocked, not locked:** locked
immutability can never be shortened or removed by anyone, including at
course-end teardown. Unlocked still makes every delete/overwrite attempt fail
for the full retention window — the property actually under test — while
leaving `terraform destroy` a working exit path.

**Discovery-first Defender activation targets Key Vault and Storage plans, not
the full baseline:** those are the two resource types this repo's own custom
policies already govern. Discovery and enforcement point at the same attack
surface on purpose, rather than activating an unrelated set of Defender plans
for their own sake.

## Teardown

Reverse stage order — each stage's resources depend on the ones before it:

```bash
cd stages/04-enforcement && terraform destroy
cd ../03-reporting        && terraform destroy
cd ../02-evidence-store   && terraform destroy
cd ../01-foundation       && terraform destroy
```

Then, if you armed CI: `az ad app delete --id <AZURE_CLIENT_ID>` to remove the
OIDC app registration. The WORM policy is unlocked specifically so `destroy`
on stage 02 works without manual intervention.
