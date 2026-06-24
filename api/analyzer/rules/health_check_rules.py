"""
Rules: health check presence and configuration.
"""
from __future__ import annotations

from typing import Any

from api.analyzer.models import Finding, Severity


def check_failover_missing_health_check(record: dict[str, Any]) -> Finding | None:
    """
    Failover PRIMARY records without a health check will ALWAYS be returned
    as healthy — Route 53 never fails over to the secondary, defeating the
    entire purpose of the failover routing policy.
    """
    if record.get("Failover") != "PRIMARY":
        return None
    if record.get("HealthCheckId"):
        return None

    return Finding(
        rule_id="FAILOVER_NO_HEALTH_CHECK",
        severity=Severity.CRITICAL,
        record_name=record["Name"],
        record_type=record["Type"],
        title="Failover PRIMARY record has no health check",
        description=(
            f"The failover PRIMARY record '{record['Name']}' has no associated "
            "Route 53 health check. Without a health check, Route 53 considers "
            "this endpoint permanently healthy and will never fail over to the "
            "secondary — your failover configuration provides zero protection."
        ),
        recommendation=(
            "Create an HTTPS health check targeting the endpoint's FQDN and "
            "health-check path, then associate it with this record via "
            "HealthCheckId. Use a 30 s interval and failure threshold of 3 for "
            "standard failover; 10 s / 3 for fast failover (additional cost)."
        ),
        details={"set_identifier": record.get("SetIdentifier", "")},
    )


def check_multivalue_missing_health_check(record: dict[str, Any]) -> Finding | None:
    """
    MultiValue Answer routing REQUIRES a health check on every record.
    Without it, Route 53 includes the record in answers even when the
    endpoint is down, undermining the availability benefit.
    """
    if not record.get("MultiValueAnswer"):
        return None
    if record.get("HealthCheckId"):
        return None

    return Finding(
        rule_id="MULTIVALUE_NO_HEALTH_CHECK",
        severity=Severity.CRITICAL,
        record_name=record["Name"],
        record_type=record["Type"],
        title="MultiValue Answer record has no health check",
        description=(
            f"The MultiValue Answer record '{record['Name']}' has no health "
            "check. Route 53 will return this record in answers regardless of "
            "endpoint health, meaning clients will receive a dead IP when this "
            "endpoint goes down."
        ),
        recommendation=(
            "Associate a health check with every MultiValue Answer record. "
            "Route 53 will then exclude unhealthy endpoints from responses, "
            "giving clients only live IPs (up to 8 per response)."
        ),
    )


def check_latency_missing_health_check(record: dict[str, Any]) -> Finding | None:
    """
    Latency-based routing without health checks means Route 53 can route
    traffic to an unhealthy region — clients receive errors while healthy
    regions sit idle.
    """
    if not record.get("Region"):
        return None
    if record.get("HealthCheckId"):
        return None
    # Only flag if it doesn't look like a failover record (those have their own rule)
    if record.get("Failover"):
        return None

    return Finding(
        rule_id="LATENCY_NO_HEALTH_CHECK",
        severity=Severity.WARNING,
        record_name=record["Name"],
        record_type=record["Type"],
        title="Latency routing record has no health check",
        description=(
            f"The latency-based record '{record['Name']}' in region "
            f"'{record.get('Region', '?')}' has no health check. Route 53 will "
            "continue routing traffic to this region even if the endpoint is "
            "unhealthy, causing client errors."
        ),
        recommendation=(
            "Add a health check to each latency-based record. Route 53 will "
            "then fall back to the next-lowest-latency healthy region "
            "automatically when the primary region goes down."
        ),
        details={"region": record.get("Region", "")},
    )


def check_weighted_missing_health_check(record: dict[str, Any]) -> Finding | None:
    """
    Weighted records without health checks send traffic to endpoints
    proportionally regardless of health — weighted routing becomes a
    traffic-split-only feature with no resilience.
    """
    weight = record.get("Weight")
    if weight is None:
        return None
    if record.get("HealthCheckId"):
        return None

    return Finding(
        rule_id="WEIGHTED_NO_HEALTH_CHECK",
        severity=Severity.WARNING,
        record_name=record["Name"],
        record_type=record["Type"],
        title="Weighted routing record has no health check",
        description=(
            f"The weighted record '{record['Name']}' (weight {weight}) has no "
            "health check. Traffic will be sent to this endpoint proportionally "
            "even when it is unhealthy."
        ),
        recommendation=(
            "Add a health check to each weighted record. When an endpoint "
            "becomes unhealthy, Route 53 redistributes its weight share among "
            "remaining healthy records automatically."
        ),
        details={"weight": weight},
    )
