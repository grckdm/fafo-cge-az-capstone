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

# See bootstrap-state.sh for why: Git Bash on Windows mangles any argument
# starting with '/' into a Windows path, corrupting every --scope below.
export MSYS_NO_PATHCONV=1

GH_OWNER="${1:?usage: ./arm-ci.sh <github-owner> [repo]}"
REPO="${2:-fafo-cge-az-capstone}"
SUB_ID=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

# GitHub's OIDC token `sub` claim embeds the repo's STABLE numeric owner/repo
# IDs alongside the current names (repo:owner@ownerId/repo@repoId:...), not
# just the plain names — this is what actually gets presented at token-exchange
# time, and it's what changed the subject after this repo was renamed. Fetch
# the real IDs via the GitHub API rather than assuming the plain-name form
# works; a federated credential subject must match Azure AD's check exactly,
# no wildcards.
echo ">> Resolving GitHub owner/repo IDs for the OIDC subject"
OWNER_ID=$(gh api "users/${GH_OWNER}" --jq .id 2>/dev/null || gh api "orgs/${GH_OWNER}" --jq .id)
REPO_ID=$(gh api "repos/${GH_OWNER}/${REPO}" --jq .id)
REPO_SLUG="${GH_OWNER}@${OWNER_ID}/${REPO}@${REPO_ID}"

echo ">> App registration: github-${REPO}"
APP_ID=$(az ad app create --display-name "github-${REPO}" --query appId -o tsv)
APP_OBJ=$(az ad app show --id "$APP_ID" --query id -o tsv)
az ad sp create --id "$APP_ID" --output none 2>/dev/null || true
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)

echo ">> Federated credentials for repo:${REPO_SLUG} (pull_request + main)"
for sub in "repo:${REPO_SLUG}:pull_request|pr" "repo:${REPO_SLUG}:ref:refs/heads/main|main"; do
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
