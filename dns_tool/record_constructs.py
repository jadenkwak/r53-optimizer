"""
Record constructs — alias-first, zone-apex safe.

Design rules enforced here:
  1. Prefer ALIAS over CNAME for all AWS-resource targets.
  2. Never create a CNAME at the zone apex (RFC 1034 §3.6.2 prohibits it).
  3. Alias records pointing to AWS resources must NOT carry an explicit TTL;
     Route 53 uses the resource's own TTL.
  4. Alias records pointing to another record in the same hosted zone inherit
     that record's TTL automatically.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

import aws_cdk as cdk
import aws_cdk.aws_cloudfront as cloudfront
import aws_cdk.aws_elasticloadbalancingv2 as elbv2
import aws_cdk.aws_route53 as route53
import aws_cdk.aws_route53_targets as targets
import aws_cdk.aws_s3 as s3
from constructs import Construct


class RecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    PTR = "PTR"
    SOA = "SOA"
    SPF = "SPF"
    SRV = "SRV"
    TXT = "TXT"


def _is_apex(zone: route53.IHostedZone, record_name: str) -> bool:
    """Return True when record_name resolves to the zone apex."""
    bare_zone = zone.zone_name.rstrip(".")
    bare_name = record_name.rstrip(".")
    return bare_name in ("", bare_zone)


class AliasTarget:
    """
    Factory that wraps the route53-targets library into a single entry point.

    Using a factory keeps callers from having to import route53_targets directly
    and makes the "alias-first" design explicit in the public API.
    """

    @staticmethod
    def from_load_balancer(
        alb: elbv2.ILoadBalancer,
    ) -> route53.IAliasRecordTarget:
        return targets.LoadBalancerTarget(alb)

    @staticmethod
    def from_cloudfront(
        distribution: cloudfront.IDistribution,
    ) -> route53.IAliasRecordTarget:
        return targets.CloudFrontTarget(distribution)

    @staticmethod
    def from_s3_bucket_website(
        bucket: s3.IBucket,
    ) -> route53.IAliasRecordTarget:
        return targets.BucketWebsiteTarget(bucket)

    @staticmethod
    def from_zone_record(
        record: route53.IRecordSet,
    ) -> route53.IAliasRecordTarget:
        """Point an alias at another record in the same hosted zone."""
        return targets.Route53RecordTarget(record)


class AliasRecord(Construct):
    """
    Creates an A (or AAAA) ALIAS record.

    Safe at the zone apex: Route 53 alias records are allowed at the apex;
    CNAMEs are not. This construct enforces that aliases are used whenever
    an AWS-resource target is supplied.

    TTL is intentionally omitted — Route 53 controls it for alias records.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        zone: route53.IHostedZone,
        record_name: str,
        alias_target: route53.IAliasRecordTarget,
        record_type: RecordType = RecordType.A,
        comment: str = "",
    ) -> None:
        super().__init__(scope, construct_id)

        if record_type not in (RecordType.A, RecordType.AAAA):
            raise ValueError(
                f"Alias records must be type A or AAAA, not {record_type}. "
                "Use SimpleRecord for other types."
            )

        self._record = route53.ARecord(
            self,
            "Record",
            zone=zone,
            record_name=record_name or None,  # None → zone apex in CDK
            target=route53.RecordTarget.from_alias(alias_target),
            comment=comment,
        )

    @property
    def record(self) -> route53.ARecord:
        return self._record


class CnameRecord(Construct):
    """
    Creates a CNAME record with explicit zone-apex guard.

    Raises ValueError at synthesis time if called at the zone apex —
    a DNS server MUST NOT return a CNAME for the apex (RFC 1034 §3.6.2),
    and Route 53 rejects it at the API level anyway.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        zone: route53.IHostedZone,
        record_name: str,
        domain_name: str,
        ttl: cdk.Duration = cdk.Duration.minutes(5),
        comment: str = "",
    ) -> None:
        super().__init__(scope, construct_id)

        if _is_apex(zone, record_name):
            raise ValueError(
                f"Cannot create a CNAME at the zone apex '{zone.zone_name}'. "
                "Use AliasRecord instead — Route 53 alias records are zone-apex safe."
            )

        self._record = route53.CnameRecord(
            self,
            "Record",
            zone=zone,
            record_name=record_name,
            domain_name=domain_name,
            ttl=ttl,
            comment=comment,
        )

    @property
    def record(self) -> route53.CnameRecord:
        return self._record


class SimpleRecord(Construct):
    """
    Creates a non-alias record set for types that don't support aliases
    (MX, TXT, NS, SRV, etc.) or when a raw IP value is intentional.

    CNAME at the zone apex is blocked here too — use AliasRecord instead.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        zone: route53.IHostedZone,
        record_name: str,
        record_type: RecordType,
        values: list[str],
        ttl: cdk.Duration = cdk.Duration.minutes(5),
        comment: str = "",
    ) -> None:
        super().__init__(scope, construct_id)

        if record_type == RecordType.CNAME and _is_apex(zone, record_name):
            raise ValueError(
                f"Cannot create a CNAME at the zone apex '{zone.zone_name}'. "
                "Use AliasRecord for AWS-resource targets at the apex."
            )

        self._record = route53.RecordSet(
            self,
            "Record",
            zone=zone,
            record_name=record_name or zone.zone_name,
            record_type=route53.RecordType[record_type.value],
            target=route53.RecordTarget.from_values(*values),
            ttl=ttl,
            comment=comment,
        )

    @property
    def record(self) -> route53.RecordSet:
        return self._record
