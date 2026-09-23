#!/usr/bin/env bash
# One-time setup for FAFO Inc.'s Terraform remote state.
#
# State storage can't be managed by the Terraform it backs (chicken-and-egg), so this
# is a plain script, run once before the first `terraform init` in any stage.
#
# Creates: a dedicated resource group, a versioned + keyless storage account, the
# tfstate container, and grants the caller Storage Blob Data Contributor (state access
# is a data-plane operation; subscription Owner/Contributor does not include it).
set -euo pipefail

LOCATION="${LOCATION:-eastus2}"
RG_STATE="rg-fafo-tfstate"
CONTAINER="tfstate"

SUB_ID=$(az account show --query id -o tsv)
# Deterministic, idempotent suffix so re-runs target the same account without a
# name-collision lottery. sha256 rather than a raw substring of the sub ID, mostly
# so the account name doesn't visibly encode the subscription ID.
SUFFIX=$(echo -n "$SUB_ID" | sha256sum | cut -c1-10)
SA_NAME="stfafotfstate${SUFFIX}"

echo ">> Resource group: $RG_STATE"
az group create --name "$RG_STATE" --location "$LOCATION" \
  --tags env=shared owner=platform-eng purpose=terraform-state company=fafo --output none

echo ">> Checking storage account name availability: $SA_NAME"
AVAILABLE=$(az storage account check-name-availability --name "$SA_NAME" --query nameAvailable -o tsv)
if [ "$AVAILABLE" = "true" ]; then
  echo ">> Creating storage account: $SA_NAME"
  az storage account create \
    --name "$SA_NAME" \
    --resource-group "$RG_STATE" \
    --location "$LOCATION" \
    --sku Standard_LRS \
    --kind StorageV2 \
    --min-tls-version TLS1_2 \
    --allow-blob-public-access false \
    --tags env=shared owner=platform-eng purpose=terraform-state company=fafo \
    --output none
else
  echo ">> $SA_NAME already exists (idempotent re-run) — skipping create"
fi

echo ">> Enabling blob versioning — every state write becomes a recoverable version"
az storage account blob-service-properties update \
  --account-name "$SA_NAME" \
  --resource-group "$RG_STATE" \
  --enable-versioning true \
  --output none

echo ">> Container: $CONTAINER"
az storage container create \
  --name "$CONTAINER" \
  --account-name "$SA_NAME" \
  --auth-mode login \
  --output none

echo ">> Granting caller Storage Blob Data Contributor on $RG_STATE"
CALLER_ID=$(az ad signed-in-user show --query id -o tsv)
az role assignment create \
  --assignee-object-id "$CALLER_ID" \
  --assignee-principal-type User \
  --role "Storage Blob Data Contributor" \
  --scope "/subscriptions/$SUB_ID/resourceGroups/$RG_STATE" \
  --output none 2>/dev/null || echo "   (already granted)"
echo "   Note: a fresh role grant can take a minute or two to propagate before 'terraform init' works."

BACKEND_FILE="$(dirname "$0")/backend.hcl"
# resource_group_name and container_name are hardcoded in every stage's own
# backend block (they never vary); only the hashed storage account name does.
# Terraform errors if a backend argument is set BOTH in the block and via
# -backend-config, so this file must carry storage_account_name alone.
cat > "$BACKEND_FILE" <<EOF
storage_account_name = "$SA_NAME"
EOF

cat <<EOF

Bootstrap complete. Backend config: $BACKEND_FILE

Next, from any stage directory:

  export ARM_SUBSCRIPTION_ID=$SUB_ID
  terraform init -backend-config=../../bootstrap/backend.hcl
EOF
