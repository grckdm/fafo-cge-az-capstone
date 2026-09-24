"""FAFO Inc. report generators — Statement of Applicability and Audit Summary.

Both read ONLY from the Cosmos evidence store (findings/controls/mappings) —
neither ever calls a live Azure API. Every number either report prints is
reproducible by re-running the same Cosmos query, which is the whole point:
the store is the source of truth, the reports are a view onto it.

  soa_now / soa_weekly         Statement of Applicability, machine + human
  audit_now / audit_daily      Audit summary of the latest run's findings

Reports land on dated paths under the WORM `reports` container with
overwrite=False: a same-day re-run finds the day's artifact already there
(and the immutability policy would refuse the overwrite regardless).
"""

import json
import logging
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

import azure.functions as func
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceExistsError

app = func.FunctionApp()

COSMOS_ENDPOINT = os.environ["COSMOS_ENDPOINT"]
COSMOS_DATABASE = os.environ.get("COSMOS_DATABASE", "fafogrc")
EVIDENCE_STORAGE_ACCOUNT = os.environ["EVIDENCE_STORAGE_ACCOUNT"]
REPORTS_CONTAINER = os.environ.get("REPORTS_CONTAINER", "reports")

_credential = DefaultAzureCredential()


def _database():
    return CosmosClient(COSMOS_ENDPOINT, _credential).get_database_client(COSMOS_DATABASE)


def _blob_container():
    account_url = f"https://{EVIDENCE_STORAGE_ACCOUNT}.blob.core.windows.net"
    return BlobServiceClient(account_url, credential=_credential).get_container_client(REPORTS_CONTAINER)


def _latest_run() -> tuple[str | None, str | None]:
    """The collector always does a full sweep, so every document currently in
    `findings` was last touched by the same run — the most recent one. Pull
    its runId/collectedAt as the report's header."""
    container = _database().get_container_client("findings")
    rows = list(
        container.query_items(
            query="SELECT TOP 1 c.runId, c.collectedAt FROM c ORDER BY c.collectedAt DESC",
            enable_cross_partition_query=True,
        )
    )
    if not rows:
        return None, None
    return rows[0]["runId"], rows[0]["collectedAt"]


def _findings_for_run(run_id: str | None) -> list[dict]:
    container = _database().get_container_client("findings")
    if run_id is None:
        return []
    return list(
        container.query_items(
            query="SELECT * FROM c WHERE c.runId = @runId",
            parameters=[{"name": "@runId", "value": run_id}],
            enable_cross_partition_query=True,
        )
    )


def _controls_and_mappings() -> tuple[list[dict], dict[str, dict]]:
    db = _database()
    controls = list(db.get_container_client("controls").read_all_items())
    mapping_rows = list(db.get_container_client("mappings").read_all_items())
    mapping_by_control = {m["controlId"]: m for m in mapping_rows}
    return controls, mapping_by_control


def _upload_pair(prefix: str, date: datetime, json_body: dict, md_body: str) -> dict:
    """Write {prefix}/YYYY/MM/{prefix}-YYYY-MM-DD.{json,md} with overwrite=False.
    A same-day re-run raising ResourceExistsError is the store doing its job,
    not a bug — caller turns that into a clean 'already generated today' result."""
    stamp = date.strftime("%Y-%m-%d")
    base = f"{prefix}/{date.year}/{date.month:02d}/{prefix}-{stamp}"
    json_path = f"{base}.json"
    md_path = f"{base}.md"

    container = _blob_container()
    try:
        container.upload_blob(json_path, json.dumps(json_body, indent=2), overwrite=False)
        container.upload_blob(md_path, md_body, overwrite=False)
    except ResourceExistsError:
        return {"json": json_path, "md": md_path, "alreadyGeneratedToday": True}
    return {"json": json_path, "md": md_path, "alreadyGeneratedToday": False}


def _run_soa() -> dict:
    run_id, collected_at = _latest_run()
    findings = _findings_for_run(run_id)
    controls, mappings = _controls_and_mappings()

    by_control: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        by_control[f["policyDefinitionName"]][f.get("complianceState", "Unknown")] += 1

    rows = []
    for control in controls:
        counts = by_control.get(control["id"], Counter())
        mapping = mappings.get(control["id"], {})
        rows.append(
            {
                "controlId": control["id"],
                "displayName": control["displayName"],
                "defaultEffect": control["defaultEffect"],
                "csfCategory": mapping.get("csfCategory"),
                "csfCategoryName": mapping.get("csfCategoryName"),
                "applicable": True,
                "totalResourcesEvaluated": sum(counts.values()),
                "compliant": counts.get("Compliant", 0),
                "nonCompliant": counts.get("NonCompliant", 0),
            }
        )

    now = datetime.now(timezone.utc)
    md_lines = [
        "# FAFO Inc. Statement of Applicability",
        "",
        f"- **Source run:** `{run_id}`" if run_id else "- **Source run:** none yet (evidence store is empty)",
        f"- **Collected at:** {collected_at}" if collected_at else "",
        "",
        "| Control | CSF Category | Effect | Evaluated | Compliant | Non-Compliant |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        md_lines.append(
            f"| {r['displayName']} | {r['csfCategory']} | {r['defaultEffect']} "
            f"| {r['totalResourcesEvaluated']} | {r['compliant']} | {r['nonCompliant']} |"
        )

    upload = _upload_pair(
        "soa",
        now,
        {"runId": run_id, "collectedAt": collected_at, "controls": rows},
        "\n".join(md_lines),
    )
    return {"controls": len(rows), "runId": run_id, **upload}


def _run_audit_summary() -> dict:
    run_id, collected_at = _latest_run()
    findings = _findings_for_run(run_id)
    _, mappings = _controls_and_mappings()

    by_state = Counter(f.get("complianceState", "Unknown") for f in findings)
    non_compliant = [
        {
            "resourceId": f["resourceId"],
            "policyDefinitionName": f["policyDefinitionName"],
            "csfCategory": mappings.get(f["policyDefinitionName"], {}).get("csfCategory"),
        }
        for f in findings
        if f.get("complianceState") == "NonCompliant"
    ]

    now = datetime.now(timezone.utc)
    md_lines = [
        "# FAFO Inc. Audit Summary",
        "",
        f"- **Source run:** `{run_id}`" if run_id else "- **Source run:** none yet (evidence store is empty)",
        f"- **Collected at:** {collected_at}" if collected_at else "",
        f"- **Total findings:** {len(findings)}",
        f"- **Non-compliant:** {by_state.get('NonCompliant', 0)}",
        "",
        "## Non-compliant resources",
        "",
    ]
    for nc in non_compliant:
        md_lines.append(f"- `{nc['resourceId']}` — {nc['policyDefinitionName']} ({nc['csfCategory']})")

    upload = _upload_pair(
        "audit-summary",
        now,
        {
            "runId": run_id,
            "collectedAt": collected_at,
            "totalFindings": len(findings),
            "byState": dict(by_state),
            "nonCompliant": non_compliant,
        },
        "\n".join(md_lines),
    )
    return {"findings": len(findings), "nonCompliant": len(non_compliant), "runId": run_id, **upload}


@app.function_name(name="soa_now")
@app.route(route="soa", auth_level=func.AuthLevel.FUNCTION)
def soa_now(req: func.HttpRequest) -> func.HttpResponse:
    result = _run_soa()
    logging.info("soa_now: %s", result)
    return func.HttpResponse(json.dumps(result), mimetype="application/json")


@app.function_name(name="soa_weekly")
@app.timer_trigger(schedule="0 0 1 * * 3", arg_name="timer", run_on_startup=False)
def soa_weekly(timer: func.TimerRequest) -> None:
    result = _run_soa()
    logging.info("soa_weekly: %s", result)


@app.function_name(name="audit_now")
@app.route(route="audit", auth_level=func.AuthLevel.FUNCTION)
def audit_now(req: func.HttpRequest) -> func.HttpResponse:
    result = _run_audit_summary()
    logging.info("audit_now: %s", result)
    return func.HttpResponse(json.dumps(result), mimetype="application/json")


@app.function_name(name="audit_daily")
@app.timer_trigger(schedule="0 0 1 * * *", arg_name="timer", run_on_startup=False)
def audit_daily(timer: func.TimerRequest) -> None:
    result = _run_audit_summary()
    logging.info("audit_daily: %s", result)
