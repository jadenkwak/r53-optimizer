"""
Rules: routing policy optimisation and redundancy checks.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from api.analyzer.models import Finding, Severity


def check_single_a_record_no_redundancy(
    records: list[dict[str, Any]], zone_name: str
) -> list[Finding]:
    """
    A single A/AAAA record at the apex or www with no routing policy means
    there is a single point of failure — if the endpoint goes down, the domain
    becomes unreachable with no automatic recovery.
    """
    findings: list[Finding] = []
    bare_zone = zone_name.rstrip(".")

    candidate_names = {bare_zone + ".", f"www.{bare_zone}."}

    for record in records:
        if record.get("Type") not in ("A", "AAAA"):
            continue
        if record.get("Name") not in candidate_names:
            continue
        # Skip alias records (they likely point to a load balancer already)
        if record.get("AliasTarget"):
            continue
        # Skip records that are part of a routing policy
        if any(record.get(k) for k in ("Failover", "Region", "Weight", "MultiValueAnswer")):
            continue

        findings.append(
            Finding(
                rule_id="SINGLE_POINT_OF_FAILURE",
                severity=Severity.INFO,
                record_name=record["Name"],
                record_type=record["Type"],
                title="Single A record — no redundancy or failover",
                description=(
                    f"'{record['Name']}' resolves to a single IP address with "
                    "no routing policy. If this endpoint becomes unavailable, "
                    "DNS continues returning the same dead IP with no automatic "
                    "failover until you manually update the record."
                ),
                recommendation=(
                    "Consider using MultiValue Answer routing with a health "
                    "check (for multiple IPs), or point to an Application Load "
                    "Balancer via an alias record (ALB handles health checks and "
                    "target redundancy). For multi-region, use latency-based or "
                    "failover routing with health checks."
                ),
                details={"values": [r["Value"] for r in record.get("ResourceRecords", [])]},
            )
        )
    return findings


def check_weighted_zero(record: dict[str, Any]) -> Finding | None:
    """
    A weighted record with weight 0 receives no traffic but still exists in
    the zone, consuming a record slot and potentially confusing operators who
    assume all listed records are active.
    """
    weight = record.get("Weight")
    if weight is None:
        return None
    if int(weight) != 0:
        return None

    return Finding(
        rule_id="WEIGHTED_ZERO",
        severity=Severity.INFO,
        record_name=record["Name"],
        record_type=record["Type"],
        title="Weighted record with weight 0 receives no traffic",
        description=(
            f"The weighted record '{record['Name']}' has weight 0 — Route 53 "
            "never routes traffic to it. This is sometimes used intentionally "
            "to 'park' a record during maintenance, but if left permanently it "
            "becomes dead configuration that misleads operators."
        ),
        recommendation=(
            "If this record is parked intentionally, add a comment to the "
            "record set explaining when it should be re-enabled. If it is no "
            "longer needed, delete it to keep the zone clean."
        ),
        details={"weight": weight, "set_identifier": record.get("SetIdentifier", "")},
    )


def check_latency_single_region(
    records: list[dict[str, Any]]
) -> list[Finding]:
    """
    Latency-based routing with only one region per record name provides no
    latency benefit — Route 53 always routes to the single region regardless
    of where the client is. This is equivalent to simple routing with extra
    complexity.
    """
    findings: list[Finding] = []

    # Group latency records by name
    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in records:
        if r.get("Region"):
            by_name[r["Name"]].append(r)

    for name, group in by_name.items():
        regions = {r.get("Region") for r in group}
        if len(regions) < 2:
            findings.append(
                Finding(
                    rule_id="LATENCY_SINGLE_REGION",
                    severity=Severity.INFO,
                    record_name=name,
                    record_type=group[0]["Type"],
                    title="Latency routing with only one region — no benefit",
                    description=(
                        f"'{name}' uses latency-based routing but only has "
                        f"records in a single region ({list(regions)[0]}). "
                        "Latency routing only provides value when records exist "
                        "in multiple regions so Route 53 can pick the closest one."
                    ),
                    recommendation=(
                        "Either add records in additional regions to make latency "
                        "routing meaningful, or switch to simple routing to reduce "
                        "complexity. Latency routing incurs the same per-query "
                        "cost as simple routing."
                    ),
                    details={"regions": list(regions)},
                )
            )
    return findings


def check_duplicate_ip_records(
    records: list[dict[str, Any]]
) -> list[Finding]:
    """
    Multiple A records pointing to the same IP address are redundant.
    Route 53 will return the same IP multiple times in a response, providing
    no redundancy benefit while consuming record slots.
    """
    findings: list[Finding] = []

    for record in records:
        if record.get("Type") not in ("A", "AAAA"):
            continue
        values = [r["Value"] for r in record.get("ResourceRecords", [])]
        if len(values) != len(set(values)):
            dupes = [v for v in values if values.count(v) > 1]
            findings.append(
                Finding(
                    rule_id="DUPLICATE_IP",
                    severity=Severity.WARNING,
                    record_name=record["Name"],
                    record_type=record["Type"],
                    title="Duplicate IP addresses in record set",
                    description=(
                        f"The record '{record['Name']}' contains duplicate IP "
                        f"values ({', '.join(set(dupes))}). Route 53 returns "
                        "all values in the response, so clients receive the same "
                        "IP multiple times — providing no additional redundancy."
                    ),
                    recommendation=(
                        "Remove the duplicate IP values, leaving only unique "
                        "addresses. If you intended to add a new endpoint, "
                        "use a different IP address."
                    ),
                    details={"duplicate_values": list(set(dupes))},
                )
            )
    return findings
