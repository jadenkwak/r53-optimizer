"""
Analysis engine — orchestrates all rules against a set of Route 53 records.
"""
from __future__ import annotations

from typing import Any

from api.analyzer.models import Finding, ZoneAnalysis
from api.analyzer.rules import (
    alias_rules,
    health_check_rules,
    routing_rules,
    security_rules,
    ttl_rules,
)


def analyze_zone(
    zone: dict[str, Any],
    records: list[dict[str, Any]],
) -> ZoneAnalysis:
    """
    Run all rules against the records of a single hosted zone and return
    a ZoneAnalysis with every finding sorted by severity.
    """
    zone_id: str = zone["Id"].split("/")[-1]
    zone_name: str = zone["Name"]
    is_private: bool = zone.get("Config", {}).get("PrivateZone", False)

    findings: list[Finding] = []

    # ── Zone-level rules (operate on the full record list) ─────────────────
    caa_finding = security_rules.check_missing_caa(records, zone_name)
    if caa_finding:
        findings.append(caa_finding)

    spf_finding = security_rules.check_missing_spf(records, zone_name)
    if spf_finding:
        findings.append(spf_finding)

    dmarc_finding = security_rules.check_missing_dmarc(records, zone_name)
    if dmarc_finding:
        findings.append(dmarc_finding)

    findings.extend(routing_rules.check_single_a_record_no_redundancy(records, zone_name))
    findings.extend(routing_rules.check_latency_single_region(records))
    findings.extend(routing_rules.check_duplicate_ip_records(records))

    # ── Per-record rules ───────────────────────────────────────────────────
    for record in records:
        # Alias rules
        f = alias_rules.check_apex_cname(record, zone_name)
        if f:
            findings.append(f)

        f = alias_rules.check_cname_to_aws_endpoint(record, zone_name)
        if f:
            findings.append(f)

        # Health check rules
        f = health_check_rules.check_failover_missing_health_check(record)
        if f:
            findings.append(f)

        f = health_check_rules.check_multivalue_missing_health_check(record)
        if f:
            findings.append(f)

        f = health_check_rules.check_latency_missing_health_check(record)
        if f:
            findings.append(f)

        f = health_check_rules.check_weighted_missing_health_check(record)
        if f:
            findings.append(f)

        # TTL rules
        f = ttl_rules.check_high_ttl(record)
        if f:
            findings.append(f)

        f = ttl_rules.check_low_ttl(record)
        if f:
            findings.append(f)

        # Routing rules (per-record)
        f = routing_rules.check_weighted_zero(record)
        if f:
            findings.append(f)

        # Security rules (per-record)
        f = security_rules.check_wildcard_record(record)
        if f:
            findings.append(f)

    return ZoneAnalysis(
        zone_id=zone_id,
        zone_name=zone_name,
        is_private=is_private,
        record_count=len(records),
        findings=findings,
    )
