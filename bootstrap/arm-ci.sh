#!/usr/bin/env bash
# Arm the compliance-gate and drift-detection workflows against FAFO Inc.'s
# subscription via OIDC — no stored credential, ever.
#
# Federated ONLY to this exact repo (repo:<owner>/<repo>:pull_request and
# :ref:refs/heads/main). That scoping IS the security boundary: possessing the
# printed client/tenant/subscription IDs grants nothing without a token
# exchange whose subject matches one of these two federations. A workflow
# running in a different repo — including a fork of this one — cannot produce
# a matching token no matter what the workflow file says.
set -euo pipefail

GH_OWNER="${1:?usage: ./arm-ci.sh <github-owner> [repo]}"
REPO="${2:-fafo-cge-az-capstone}"
SUB_ID=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

echo ">> App registration: github-${REPO}"
APP_ID=$(az ad app create --display-name "github-${REPO}" --query appId -o tsv)
APP_OBJ=$(az ad app show --id "$APP_ID" --query id -o tsv)
az ad sp create --id "$APP_ID" --output none 2>/dev/null || true
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)

echo ">> Federated credentials for repo:${GH_OWNER}/${REPO} (pull_request + main)"
for sub in "repo:${GH_OWNER}/${REPO}:pull_request|pr" "repo:${GH_OWNER}/${REPO}:ref:refs/heads/main|main"; do
  SUBJECT="${sub%|*}"; NAME="${sub#*|}"
  az ad app federated-credential create --id "$APP_OBJ" --parameters "{
    \"name\": \"${REPO}-${NAME}\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"${SUBJECT}\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" --output none 2>/dev/null || echo "   (${REPO}-${NAME} already exists)"
done

echo ">> Roles: Contributor at mg-fafo (plan/apply across every stage) +"
echo "   Storage Blob Data Contributor on the state resource group"
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "Contributor" --scope "/providers/Microsoft.Management/managementGroups/mg-fafo" --output none 2>/dev/null || true
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Contributor" \
  --scope "/subscriptions/$SUB_ID/resourceGroups/rg-fafo-tfstate" --output none 2>/dev/null || true

STATE_SA=$(grep storage_account_name "$(dirname "$0")/backend.hcl" 2>/dev/null | tr -d ' "' | cut -d= -f2 || echo "<from bootstrap/backend.hcl>")

cat <<EOF

Done. Add these five repository VARIABLES (Settings -> Secrets and variables
-> Actions -> Variables -> New repository variable) — variables, not secrets,
because OIDC leaves nothing secret to store:

  AZURE_CLIENT_ID        $APP_ID
  AZURE_TENANT_ID        $TENANT_ID
  AZURE_SUBSCRIPTION_ID  $SUB_ID
  STATE_STORAGE_ACCOUNT  $STATE_SA
  OWNER_EMAIL            <your email>

Then enable compliance-gate and drift-detection in the Actions tab, and protect
main requiring the compliance-gate check.
EOF
