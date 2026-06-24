"""
Rules: TTL hygiene.
"""
from __future__ import annotations

from typing import Any

from api.analyzer.models import Finding, Severity

# Route 53 does not emit TTL for alias records — they inherit the target's TTL.
_SKIP_TYPES = {"SOA"}  # SOA TTL is managed by Route 53 itself

_HIGH_TTL_THRESHOLD = 86_400      # 1 day
_LOW_TTL_THRESHOLD = 60           # 1 minute
_CRITICAL_LOW_TTL = 10            # below 10 s is unusual even for fast failover


def _has_ttl(record: dict[str, Any]) -> bool:
    return "TTL" in record


def check_high_ttl(record: dict[str, Any]) -> Finding | None:
    """
    Very high TTLs mean DNS clients cache the record for a long time.
    When you need to change the record (failover, migration, outage response),
    the old value continues to be served to clients until the TTL expires.
    """
    if record.get("Type") in _SKIP_TYPES:
        return None
    if not _has_ttl(record):
        return None

    ttl = int(record["TTL"])
    if ttl <= _HIGH_TTL_THRESHOLD:
        return None

    hours = ttl // 3600
    return Finding(
        rule_id="HIGH_TTL",
        severity=Severity.INFO,
        record_name=record["Name"],
        record_type=record["Type"],
        title=f"High TTL ({hours}h) slows change propagation",
        description=(
            f"The {record['Type']} record '{record['Name']}' has a TTL of "
            f"{ttl}s ({hours} hours). DNS resolvers cache this record for that "
            "duration. If you need to reroute traffic quickly (e.g., during an "
            "outage), you must wait up to this long for the change to take effect."
        ),
        recommendation=(
            "For records that may need rapid changes, consider a TTL of "
            "300–3600 s. Only use TTLs > 86400 s for very stable records "
            "(e.g., NS delegation for a subdomain you never plan to move)."
        ),
        details={"ttl": ttl},
    )


def check_low_ttl(record: dict[str, Any]) -> Finding | None:
    """
    Very low TTLs cause DNS resolvers to query Route 53 extremely frequently,
    increasing query costs. Unless this is an intentional pre-change TTL
    reduction, it should be raised after the change is stable.
    """
    if record.get("Type") in _SKIP_TYPES:
        return None
    if not _has_ttl(record):
        return None

    # Low TTL is expected for failover / latency / weighted / multivalue records
    routing_indicators = ("Failover", "Region", "Weight", "MultiValueAnswer", "GeoLocation")
    if any(record.get(k) for k in routing_indicators):
        return None

    ttl = int(record["TTL"])
    if ttl >= _LOW_TTL_THRESHOLD:
        return None

    severity = Severity.WARNING if ttl < _CRITICAL_LOW_TTL else Severity.INFO
    return Finding(
        rule_id="LOW_TTL",
        severity=severity,
        record_name=record["Name"],
        record_type=record["Type"],
        title=f"Very low TTL ({ttl}s) increases Route 53 query costs",
        description=(
            f"The {record['Type']} record '{record['Name']}' has a TTL of "
            f"{ttl}s. Each DNS resolver must re-query Route 53 every {ttl} "
            "seconds, generating a high volume of billable queries. Route 53 "
            "charges $0.40–$0.60 per million queries."
        ),
        recommendation=(
            "If this TTL was lowered before a planned change, raise it back to "
            "300 s or higher after the change propagates. For routing-policy "
            "records (failover, latency), a TTL of 60 s is appropriate to "
            "balance failover speed and cost."
        ),
        details={"ttl": ttl},
    )
