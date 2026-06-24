"""
Route 53 change-propagation helper.

Route 53 change batches are transactional: a ChangeResourceRecordSets call
either succeeds for all records in the batch or fails for none. After a
successful API call, Route 53 returns a ChangeInfo object with an Id and an
initial Status of "PENDING". The change propagates to all Route 53 DNS
servers worldwide (typically within 60 seconds), at which point Status
transitions to "INSYNC".

This module provides:
  • wait_for_insync()  — blocks until the change reaches INSYNC or times out.
  • batch_changes()    — groups ChangeResourceRecordSets requests into a single
                         transactional batch so partial updates cannot occur.
"""
from __future__ import annotations

import time
from typing import Any

import boto3
from botocore.exceptions import ClientError


# ── Public API ────────────────────────────────────────────────────────────────

def wait_for_insync(
    change_id: str,
    *,
    poll_interval: int = 10,
    timeout: int = 300,
    client: Any = None,
) -> bool:
    """
    Poll Route 53 GetChange until the change status is INSYNC.

    Parameters
    ──────────
    change_id      : The Id returned by ChangeResourceRecordSets
                     (with or without the "/change/" prefix).
    poll_interval  : Seconds between polls (default 10).
    timeout        : Maximum seconds to wait before raising TimeoutError
                     (default 300 = 5 minutes).
    client         : Optional pre-built boto3 Route 53 client (useful in
                     tests with mocked clients).

    Returns True on INSYNC, raises TimeoutError if the deadline passes.
    """
    r53 = client or boto3.client("route53")
    normalized_id = _normalize_change_id(change_id)
    deadline = time.monotonic() + timeout

    while True:
        try:
            response = r53.get_change(Id=normalized_id)
        except ClientError as exc:
            raise RuntimeError(
                f"GetChange API call failed for {normalized_id}: {exc}"
            ) from exc

        status = response["ChangeInfo"]["Status"]
        if status == "INSYNC":
            return True

        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Change {normalized_id} still in status '{status}' after "
                f"{timeout}s. DNS propagation may still be in progress."
            )

        time.sleep(poll_interval)


def batch_changes(
    hosted_zone_id: str,
    changes: list[dict[str, Any]],
    comment: str = "",
    *,
    client: Any = None,
) -> str:
    """
    Submit a list of record changes as a single transactional batch.

    Route 53 change batches are all-or-none: either every change in the list
    succeeds or none of them are applied. This prevents partial updates that
    would leave DNS in an inconsistent state.

    Parameters
    ──────────
    hosted_zone_id : The hosted zone to modify (bare ID, not ARN).
    changes        : List of Change dicts matching the Route 53 API shape:
                     [{"Action": "CREATE"|"DELETE"|"UPSERT",
                       "ResourceRecordSet": {...}}]
    comment        : Optional human-readable comment stored in the change batch.
    client         : Optional pre-built boto3 Route 53 client.

    Returns the ChangeInfo Id, which can be passed to wait_for_insync().
    """
    if not changes:
        raise ValueError("changes list must not be empty.")

    r53 = client or boto3.client("route53")

    try:
        response = r53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                "Comment": comment,
                "Changes": changes,
            },
        )
    except ClientError as exc:
        raise RuntimeError(
            f"ChangeResourceRecordSets failed for zone {hosted_zone_id}: {exc}"
        ) from exc

    return response["ChangeInfo"]["Id"]


def upsert_record(
    hosted_zone_id: str,
    name: str,
    record_type: str,
    values: list[str],
    ttl: int = 300,
    *,
    comment: str = "",
    wait: bool = True,
    client: Any = None,
) -> str:
    """
    Convenience wrapper: upsert a single record set and optionally wait for
    propagation.

    Returns the change Id.
    """
    change = {
        "Action": "UPSERT",
        "ResourceRecordSet": {
            "Name": name,
            "Type": record_type,
            "TTL": ttl,
            "ResourceRecords": [{"Value": v} for v in values],
        },
    }
    change_id = batch_changes(hosted_zone_id, [change], comment=comment, client=client)

    if wait:
        wait_for_insync(change_id, client=client)

    return change_id


# ── Internal helpers ──────────────────────────────────────────────────────────

def _normalize_change_id(change_id: str) -> str:
    """Ensure the change ID has the /change/ prefix the API expects."""
    if not change_id.startswith("/change/"):
        return f"/change/{change_id.lstrip('/')}"
    return change_id
