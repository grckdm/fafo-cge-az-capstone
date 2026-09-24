"""FAFO Inc. GRC evidence collector.

Pulls Azure Policy compliance states for the mg-fafo-sandbox management group
(the four controls in stages/01-foundation/policies.tf) and upserts them into
the Cosmos `findings` container. Two triggers, one collection routine:

  collect_now      HTTP, function-key auth  — on-demand runs, testing
  collect_nightly  Timer, 01:00 UTC daily   — the run history the rubric wants
                                               to see accumulate over time

Authenticates via the Function App's system-assigned identity (DefaultAzureCredential
resolves to it automatically inside Azure; no connection string, no API key).
"""

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone

import azure.functions as func
import requests
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential

app = func.FunctionApp()

COSMOS_ENDPOINT = os.environ["COSMOS_ENDPOINT"]
COSMOS_DATABASE = os.environ.get("COSMOS_DATABASE", "fafogrc")
MG_SCOPE = os.environ["MG_SCOPE"]  # /providers/Microsoft.Management/managementGroups/mg-fafo-sandbox
POLICY_API_VERSION = "2019-10-01"

_credential = DefaultAzureCredential()


def _cosmos_container():
    client = CosmosClient(COSMOS_ENDPOINT, _credential)
    return client.get_database_client(COSMOS_DATABASE).get_container_client("findings")


def _arm_token() -> str:
    return _credential.get_token("https://management.azure.com/.default").token


def _fetch_policy_states() -> list[dict]:
    """POST the latest policyStates queryResults for the sandbox management
    group, filtered to OUR OWN initiative. Without the $filter, this endpoint
    returns compliance states for EVERY policy assignment effective at this
    scope — including Azure's built-in benchmark initiative that's assigned to
    every subscription by default, which would dilute the findings container
    with ~50 unrelated GUID-named policies that have no entry in the
    controls/mappings crosswalk. Paginates on @odata.nextLink until exhausted."""
    url = (
        f"https://management.azure.com{MG_SCOPE}"
        f"/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
    )
    # requests handles percent-encoding of the space/quote characters in the
    # $filter value when passed via params — building this into the f-string
    # URL directly risks an improperly-encoded request.
    params = {"api-version": POLICY_API_VERSION, "$filter": "PolicyAssignmentName eq 'fafo-grc-baseline'"}
    headers = {"Authorization": f"Bearer {_arm_token()}"}
    results: list[dict] = []
    while url:
        resp = requests.post(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        body = resp.json()
        results.extend(body.get("value", []))
        # @odata.nextLink is a complete, already-encoded URL from Azure —
        # params must not be reapplied on subsequent requests.
        url = body.get("@odata.nextLink")
        params = None
    return results


def _document_id(policy_definition_name: str, resource_id: str) -> str:
    """Deterministic ID from (policy, resource): the same pair always upserts
    the same document. A resource flipping compliant->noncompliant->compliant
    updates one row's history, not three rows."""
    raw = f"{policy_definition_name}|{resource_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _run_collection() -> dict:
    run_id = str(uuid.uuid4())
    collected_at = datetime.now(timezone.utc).isoformat()

    states = _fetch_policy_states()
    container = _cosmos_container()

    written = 0
    for state in states:
        policy_definition_name = state.get("policyDefinitionName", "unknown")
        resource_id = state.get("resourceId", "unknown")
        doc = {
            "id": _document_id(policy_definition_name, resource_id),
            "policyDefinitionName": policy_definition_name,
            "policyAssignmentName": state.get("policyAssignmentName"),
            "resourceId": resource_id,
            "resourceType": state.get("resourceType"),
            "complianceState": state.get("complianceState"),
            "policyEvaluationTimestamp": state.get("timestamp"),
            "runId": run_id,
            "collectedAt": collected_at,
        }
        container.upsert_item(doc)
        written += 1

    return {"runId": run_id, "collectedAt": collected_at, "documents": written}


@app.function_name(name="collect_now")
@app.route(route="collect", auth_level=func.AuthLevel.FUNCTION)
def collect_now(req: func.HttpRequest) -> func.HttpResponse:
    result = _run_collection()
    logging.info("collect_now: run %s wrote %d documents", result["runId"], result["documents"])
    return func.HttpResponse(json.dumps(result), mimetype="application/json")


@app.function_name(name="collect_nightly")
@app.timer_trigger(schedule="0 0 1 * * *", arg_name="timer", run_on_startup=False)
def collect_nightly(timer: func.TimerRequest) -> None:
    result = _run_collection()
    logging.info("collect_nightly: run %s wrote %d documents", result["runId"], result["documents"])
