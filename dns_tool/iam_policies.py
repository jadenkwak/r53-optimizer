"""
Least-privilege IAM policy generators for Route 53.

Route 53 condition keys used
────────────────────────────
route53:ChangeResourceRecordSetsNormalizedRecordNames
    Scopes a principal to specific DNS names (wildcards supported).
    Must be paired with ForAllValues:StringLike / ForAllValues:StringNotLike
    because a single ChangeResourceRecordSets call can include MULTIPLE
    record names — ForAnyValue would allow a bad actor to include a protected
    name alongside permitted names and still have the call succeed.

route53:ChangeResourceRecordSetsActions
    Further restricts which change actions (CREATE, DELETE, UPSERT) are
    allowed, adding defence-in-depth.

route53:ChangeResourceRecordSetsRecordTypes
    Restricts which DNS record types can be modified.

Protected-suffix pattern
────────────────────────
The "deny" variant uses ForAllValues:StringNotLike on the same condition
key. If ANY record name in the batch matches the protected suffix, the
entire change batch is denied — consistent with the transactional nature
of Route 53 change batches and the principle of least astonishment.
"""
from __future__ import annotations

import aws_cdk as cdk
import aws_cdk.aws_iam as iam
from constructs import Construct


# Actions a DNS operator needs — read-only operations are always included.
_WRITE_ACTIONS = [
    "route53:ChangeResourceRecordSets",
]

_READ_ACTIONS = [
    "route53:GetHostedZone",
    "route53:ListResourceRecordSets",
    "route53:GetChange",
    "route53:ListHostedZones",
    "route53:GetHostedZoneCount",
]

_HEALTH_CHECK_READ_ACTIONS = [
    "route53:GetHealthCheck",
    "route53:ListHealthChecks",
    "route53:GetHealthCheckStatus",
    "route53:GetHealthCheckLastFailureReason",
]


def _hosted_zone_arn(hosted_zone_id: str) -> str:
    """Route 53 ARN format: arn:aws:route53:::hostedzone/<id>"""
    # Strip any leading /hostedzone/ prefix callers might supply
    bare_id = hosted_zone_id.split("/")[-1]
    return f"arn:aws:route53:::hostedzone/{bare_id}"


class DnsIamPolicies(Construct):
    """
    Factory construct for generating scoped Route 53 IAM policies.

    Attach the returned ManagedPolicy objects to roles/groups/users.
    """

    def __init__(self, scope: Construct, construct_id: str) -> None:
        super().__init__(scope, construct_id)

    # ── Allow-suffix policy ───────────────────────────────────────────────

    def allow_suffix_policy(
        self,
        *,
        policy_name: str,
        hosted_zone_id: str,
        allowed_suffix: str,
        allowed_record_types: list[str] | None = None,
        allowed_actions: list[str] | None = None,
    ) -> iam.ManagedPolicy:
        """
        Grant write access ONLY to records whose normalised name ends with
        *.<allowed_suffix> (or exactly <allowed_suffix>).

        ForAllValues:StringLike — the condition must be true for EVERY record
        name in the batch; a batch containing any out-of-scope name is denied.
        """
        record_types = allowed_record_types or ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV"]
        change_actions = allowed_actions or ["CREATE", "UPSERT", "DELETE"]
        zone_arn = _hosted_zone_arn(hosted_zone_id)

        write_statement = iam.PolicyStatement(
            sid="AllowScopedRecordChanges",
            effect=iam.Effect.ALLOW,
            actions=_WRITE_ACTIONS,
            resources=[zone_arn],
            conditions={
                # Scope to records within the allowed suffix (wildcard match)
                "ForAllValues:StringLike": {
                    "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
                        allowed_suffix,
                        f"*.{allowed_suffix}",
                    ]
                },
                # Only the listed change actions are permitted
                "ForAllValues:StringLike": {
                    "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
                        allowed_suffix,
                        f"*.{allowed_suffix}",
                    ],
                    "route53:ChangeResourceRecordSetsActions": change_actions,
                    "route53:ChangeResourceRecordSetsRecordTypes": record_types,
                },
            },
        )

        read_statement = iam.PolicyStatement(
            sid="AllowDnsReadAccess",
            effect=iam.Effect.ALLOW,
            actions=_READ_ACTIONS + _HEALTH_CHECK_READ_ACTIONS,
            resources=["*"],
        )

        return iam.ManagedPolicy(
            self,
            policy_name,
            managed_policy_name=policy_name,
            description=(
                f"Allow Route 53 record management for *.{allowed_suffix} "
                f"in zone {hosted_zone_id}"
            ),
            statements=[write_statement, read_statement],
        )

    # ── Deny-suffix (protected-suffix) policy ─────────────────────────────

    def deny_suffix_policy(
        self,
        *,
        policy_name: str,
        hosted_zone_id: str,
        protected_suffix: str,
    ) -> iam.ManagedPolicy:
        """
        Deny writes to records whose normalised name ends with
        *.<protected_suffix>, while allowing all other writes in the zone.

        This models the "no-touch infrastructure DNS" guardrail common in
        platform teams: operators can manage app records but cannot alter
        infra records (e.g. *.infra.example.com).

        ForAllValues:StringNotLike — if ANY record in the batch matches the
        protected suffix, the entire batch is denied.
        """
        zone_arn = _hosted_zone_arn(hosted_zone_id)

        # Explicit DENY for the protected suffix — cannot be overridden by any Allow
        deny_statement = iam.PolicyStatement(
            sid="DenyProtectedSuffixChanges",
            effect=iam.Effect.DENY,
            actions=_WRITE_ACTIONS,
            resources=[zone_arn],
            conditions={
                "ForAnyValue:StringLike": {
                    "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
                        protected_suffix,
                        f"*.{protected_suffix}",
                    ]
                }
            },
        )

        # Allow all other writes in the zone
        allow_statement = iam.PolicyStatement(
            sid="AllowNonProtectedRecordChanges",
            effect=iam.Effect.ALLOW,
            actions=_WRITE_ACTIONS,
            resources=[zone_arn],
        )

        read_statement = iam.PolicyStatement(
            sid="AllowDnsReadAccess",
            effect=iam.Effect.ALLOW,
            actions=_READ_ACTIONS + _HEALTH_CHECK_READ_ACTIONS,
            resources=["*"],
        )

        return iam.ManagedPolicy(
            self,
            policy_name,
            managed_policy_name=policy_name,
            description=(
                f"Deny Route 53 writes to *.{protected_suffix}; "
                f"allow all other records in zone {hosted_zone_id}"
            ),
            statements=[deny_statement, allow_statement, read_statement],
        )

    # ── Read-only policy ──────────────────────────────────────────────────

    def read_only_policy(
        self,
        *,
        policy_name: str,
        hosted_zone_id: str | None = None,
    ) -> iam.ManagedPolicy:
        """
        Grant read-only access to Route 53 — useful for auditing pipelines
        and monitoring tools that never need to change records.
        """
        resources = (
            [_hosted_zone_arn(hosted_zone_id)] if hosted_zone_id else ["*"]
        )

        return iam.ManagedPolicy(
            self,
            policy_name,
            managed_policy_name=policy_name,
            description="Read-only access to Route 53 hosted zones and health checks",
            statements=[
                iam.PolicyStatement(
                    sid="Route53ReadOnly",
                    effect=iam.Effect.ALLOW,
                    actions=_READ_ACTIONS + _HEALTH_CHECK_READ_ACTIONS,
                    resources=["*"],
                )
            ],
        )
