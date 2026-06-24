"""
Rules: alias vs. CNAME optimisation and zone-apex CNAME detection.
"""
from __future__ import annotations

from typing import Any

from api.analyzer.models import Finding, Severity

# Known AWS endpoint suffixes that can be replaced with alias records
_AWS_ALIAS_PATTERNS = [
    "elb.amazonaws.com",
    "cloudfront.net",
    "s3-website",
    "execute-api",
    "apigateway.amazonaws.com",
    "awsglobalaccelerator.com",
    "amazonaws.com",  # broad catch-all last
]


def _is_aws_endpoint(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(pattern in d for pattern in _AWS_ALIAS_PATTERNS[:-1])  # skip broad catch-all


def _is_apex(record_name: str, zone_name: str) -> bool:
    bare_zone = zone_name.rstrip(".")
    bare_record = record_name.rstrip(".")
    return bare_record in ("", bare_zone)


def check_cname_to_aws_endpoint(
    record: dict[str, Any], zone_name: str
) -> Finding | None:
    """
    CNAME pointing to an AWS endpoint can be replaced with an alias record.
    Alias records eliminate the extra DNS hop, reduce latency, and are free
    for intra-AWS lookups.
    """
    if record.get("Type") != "CNAME":
        return None

    values = [r["Value"] for r in record.get("ResourceRecords", [])]
    aws_targets = [v for v in values if _is_aws_endpoint(v)]
    if not aws_targets:
        return None

    name = record["Name"]
    return Finding(
        rule_id="CNAME_TO_AWS_ENDPOINT",
        severity=Severity.WARNING,
        record_name=name,
        record_type="CNAME",
        title="CNAME to AWS endpoint — use ALIAS instead",
        description=(
            f"The CNAME record '{name}' points to an AWS endpoint "
            f"({aws_targets[0].rstrip('.')}). CNAMEs require an extra DNS "
            "resolution step, adding latency and per-query cost."
        ),
        recommendation=(
            "Replace this CNAME with an A/AAAA ALIAS record. Alias records "
            "resolve directly inside Route 53 with no extra query, incur no "
            "per-query charge for lookups to AWS resources, and work at the "
            "zone apex where CNAMEs are forbidden."
        ),
        details={"targets": aws_targets},
    )


def check_apex_cname(record: dict[str, Any], zone_name: str) -> Finding | None:
    """
    A CNAME at the zone apex is forbidden by RFC 1034 §3.6.2 and will break
    email delivery (MX lookup fails) and any other records at the apex.
    Route 53 rejects this at the API level, but it can appear when zones
    are migrated from other DNS providers.
    """
    if record.get("Type") != "CNAME":
        return None
    if not _is_apex(record["Name"], zone_name):
        return None

    return Finding(
        rule_id="APEX_CNAME",
        severity=Severity.CRITICAL,
        record_name=record["Name"],
        record_type="CNAME",
        title="CNAME at zone apex (RFC violation)",
        description=(
            "A CNAME record exists at the zone apex. RFC 1034 §3.6.2 forbids "
            "CNAMEs at the apex because they conflict with SOA and NS records "
            "that must exist there. This will break email delivery and any "
            "other apex records."
        ),
        recommendation=(
            "Delete the CNAME and create an A/AAAA ALIAS record pointing to "
            "the same target. Route 53 alias records are apex-safe and do not "
            "conflict with SOA/NS records."
        ),
    )
