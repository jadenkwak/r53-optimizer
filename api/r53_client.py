"""
Thin boto3 wrapper for Route 53, with demo-mode and explicit-credentials support.
"""
from __future__ import annotations

from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from api.demo_data import DEMO_RECORDS, DEMO_ZONES


def _bare_id(zone_id: str) -> str:
    return zone_id.split("/")[-1]


class Credentials:
    """Explicit AWS credentials supplied by the user via the auth form."""
    def __init__(self, access_key_id: str, secret_access_key: str, region: str) -> None:
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.region = region

    def boto_session(self) -> boto3.Session:
        return boto3.Session(
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key,
            region_name=self.region,
        )

    def validate(self) -> tuple[bool, str, dict]:
        """
        Call sts:GetCallerIdentity to verify the credentials are valid.
        Returns (ok, error_message, identity_dict).
        """
        try:
            sts = self.boto_session().client("sts")
            identity = sts.get_caller_identity()
            return True, "", {
                "account_id": identity["Account"],
                "arn": identity["Arn"],
                "user_id": identity["UserId"],
            }
        except NoCredentialsError:
            return False, "No credentials provided.", {}
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg  = e.response["Error"]["Message"]
            if code == "InvalidClientTokenId":
                return False, "Access Key ID is invalid.", {}
            if code == "SignatureDoesNotMatch":
                return False, "Secret Access Key is incorrect.", {}
            if code in ("AccessDenied", "AuthFailure"):
                return False, f"Access denied: {msg}", {}
            return False, f"AWS error ({code}): {msg}", {}
        except Exception as e:
            return False, str(e), {}


class R53Client:
    """
    Unified client. Priority:
      1. Explicit Credentials object → live AWS with those creds
      2. demo=True → demo fixture data
      3. demo=False → live AWS with ambient credentials (env / ~/.aws)
    """

    def __init__(
        self,
        credentials: Credentials | None = None,
        demo: bool = False,
    ) -> None:
        self._demo = demo and credentials is None
        if not self._demo:
            session = credentials.boto_session() if credentials else boto3.Session()
            self._r53 = session.client("route53")

    @property
    def is_demo(self) -> bool:
        return self._demo

    # ── Hosted zones ──────────────────────────────────────────────────────

    def list_hosted_zones(self) -> list[dict[str, Any]]:
        if self._demo:
            return DEMO_ZONES
        zones: list[dict[str, Any]] = []
        paginator = self._r53.get_paginator("list_hosted_zones")
        for page in paginator.paginate():
            zones.extend(page["HostedZones"])
        return zones

    def get_hosted_zone(self, zone_id: str) -> dict[str, Any]:
        if self._demo:
            bare = _bare_id(zone_id)
            match = next((z for z in DEMO_ZONES if _bare_id(z["Id"]) == bare), None)
            if not match:
                raise KeyError(f"Demo zone {zone_id} not found")
            return match
        return self._r53.get_hosted_zone(Id=_bare_id(zone_id))["HostedZone"]

    # ── Record sets ───────────────────────────────────────────────────────

    def list_records(self, zone_id: str) -> list[dict[str, Any]]:
        if self._demo:
            return DEMO_RECORDS.get(_bare_id(zone_id), [])
        bare = _bare_id(zone_id)
        records: list[dict[str, Any]] = []
        paginator = self._r53.get_paginator("list_resource_record_sets")
        for page in paginator.paginate(HostedZoneId=bare):
            records.extend(page["ResourceRecordSets"])
        return records

    # ── Health checks ─────────────────────────────────────────────────────

    def list_health_checks(self) -> list[dict[str, Any]]:
        if self._demo:
            return []
        checks: list[dict[str, Any]] = []
        paginator = self._r53.get_paginator("list_health_checks")
        for page in paginator.paginate():
            checks.extend(page["HealthChecks"])
        return checks

    # ── Change tracking ───────────────────────────────────────────────────

    def get_change(self, change_id: str) -> dict[str, Any]:
        if self._demo:
            return {"Id": change_id, "Status": "INSYNC"}
        return self._r53.get_change(Id=change_id)["ChangeInfo"]
