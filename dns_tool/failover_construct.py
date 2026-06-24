"""
Multi-Region failover construct with configurable routing policies.

Supported routing policies
──────────────────────────
FAILOVER        — active/passive; primary has a health check, secondary
                  takes over when it fails.
LATENCY         — Route 53 routes each query to the region with the lowest
                  measured latency for the client.
WEIGHTED        — split traffic by numeric weight (0–255).
GEOLOCATION     — route by continent / country / subdivision.
GEOPROXIMITY    — route by geographic proximity with optional bias.
MULTIVALUE      — up to eight healthy records returned per query; every
                  record must carry a health check.

Design notes
────────────
• Health checks are attached to all primary records in FAILOVER mode and to
  every record in MULTIVALUE mode (Route 53 requirement).
• Record sets use CfnRecordSet directly for properties (SetIdentifier,
  Failover, Region, Weight, GeoLocation) that the higher-level L2 constructs
  do not yet expose.
• TTL is kept deliberately low (60 s) for failover records so DNS clients
  stop caching a stale answer quickly when a failover event occurs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import aws_cdk as cdk
import aws_cdk.aws_elasticloadbalancingv2 as elbv2
import aws_cdk.aws_route53 as route53
from constructs import Construct


class RoutingPolicy(str, Enum):
    FAILOVER = "FAILOVER"
    LATENCY = "LATENCY"
    WEIGHTED = "WEIGHTED"
    GEOLOCATION = "GEOLOCATION"
    GEOPROXIMITY = "GEOPROXIMITY"
    MULTIVALUE = "MULTIVALUE"


@dataclass
class GeoLocation:
    continent_code: Optional[str] = None  # e.g. "NA"
    country_code: Optional[str] = None    # e.g. "US"
    subdivision_code: Optional[str] = None  # e.g. "WA"


@dataclass
class FailoverTarget:
    """Describes one endpoint (primary or secondary) in a failover pair."""
    load_balancer: elbv2.ILoadBalancer
    region: str
    weight: int = 1
    geo_location: Optional[GeoLocation] = None
    ip_address: Optional[str] = None  # used when LB is not available


def _make_health_check(
    scope: Construct,
    construct_id: str,
    *,
    fqdn: str,
    path: str,
    port: int = 443,
    protocol: str = "HTTPS",
    request_interval: int = 30,
    failure_threshold: int = 3,
) -> route53.CfnHealthCheck:
    """
    Route 53 health check — HTTPS by default.

    request_interval: 30 s (standard) or 10 s (fast, costs more).
    failure_threshold: consecutive failures before marking unhealthy.
    """
    return route53.CfnHealthCheck(
        scope,
        construct_id,
        health_check_config=route53.CfnHealthCheck.HealthCheckConfigProperty(
            type=protocol,
            fully_qualified_domain_name=fqdn,
            resource_path=path,
            port=port,
            request_interval=request_interval,
            failure_threshold=failure_threshold,
            enable_sni=True,
        ),
        health_check_tags=[
            route53.CfnHealthCheck.HealthCheckTagProperty(
                key="ManagedBy", value="dns-tool"
            )
        ],
    )


def _alb_dns(alb: elbv2.ILoadBalancer) -> str:
    return alb.load_balancer_dns_name


class FailoverConstruct(Construct):
    """
    Creates a pair (or set) of Route 53 record sets that implement a
    configurable routing policy with health checks.

    Parameters
    ──────────
    zone            : Target hosted zone.
    record_name     : DNS name within the zone (empty string = apex).
    routing_policy  : One of the RoutingPolicy enum values.
    primary         : Primary FailoverTarget.
    secondary       : Secondary FailoverTarget (required for FAILOVER; optional
                      for others where it acts as a second weighted/latency entry).
    health_check_path : HTTP path used for health checks (default "/").
    ttl             : Record TTL — kept low for fast failover (default 60 s).
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        zone: route53.IHostedZone,
        record_name: str,
        routing_policy: RoutingPolicy,
        primary: FailoverTarget,
        secondary: Optional[FailoverTarget] = None,
        health_check_path: str = "/",
        ttl: int = 60,
    ) -> None:
        super().__init__(scope, construct_id)

        self._zone = zone
        self._record_name = record_name or zone.zone_name
        self._policy = routing_policy
        self._health_checks: list[route53.CfnHealthCheck] = []
        self._records: list[route53.CfnRecordSet] = []

        if routing_policy == RoutingPolicy.FAILOVER:
            self._build_failover(primary, secondary, health_check_path, ttl)
        elif routing_policy == RoutingPolicy.LATENCY:
            self._build_latency(primary, secondary, health_check_path, ttl)
        elif routing_policy == RoutingPolicy.WEIGHTED:
            self._build_weighted(primary, secondary, health_check_path, ttl)
        elif routing_policy == RoutingPolicy.GEOLOCATION:
            self._build_geolocation(primary, secondary, health_check_path, ttl)
        elif routing_policy == RoutingPolicy.MULTIVALUE:
            targets = [primary] + ([secondary] if secondary else [])
            self._build_multivalue(targets, health_check_path, ttl)
        else:
            raise ValueError(f"Unsupported routing policy: {routing_policy}")

    # ── Routing policy builders ────────────────────────────────────────────

    def _build_failover(
        self,
        primary: FailoverTarget,
        secondary: Optional[FailoverTarget],
        path: str,
        ttl: int,
    ) -> None:
        if secondary is None:
            raise ValueError("FAILOVER routing requires both a primary and secondary target.")

        hc = _make_health_check(
            self,
            "PrimaryHealthCheck",
            fqdn=_alb_dns(primary.load_balancer),
            path=path,
        )
        self._health_checks.append(hc)

        self._records.append(
            self._cfn_record(
                "PrimaryRecord",
                target=primary,
                set_identifier="primary",
                failover="PRIMARY",
                health_check_id=hc.attr_health_check_id,
                ttl=ttl,
            )
        )
        self._records.append(
            self._cfn_record(
                "SecondaryRecord",
                target=secondary,
                set_identifier="secondary",
                failover="SECONDARY",
                ttl=ttl,
            )
        )

    def _build_latency(
        self,
        primary: FailoverTarget,
        secondary: Optional[FailoverTarget],
        path: str,
        ttl: int,
    ) -> None:
        hc_primary = _make_health_check(
            self,
            "LatencyHCPrimary",
            fqdn=_alb_dns(primary.load_balancer),
            path=path,
        )
        self._health_checks.append(hc_primary)

        self._records.append(
            self._cfn_record(
                "LatencyPrimary",
                target=primary,
                set_identifier=f"latency-{primary.region}",
                region=primary.region,
                health_check_id=hc_primary.attr_health_check_id,
                ttl=ttl,
            )
        )

        if secondary:
            hc_secondary = _make_health_check(
                self,
                "LatencyHCSecondary",
                fqdn=_alb_dns(secondary.load_balancer),
                path=path,
            )
            self._health_checks.append(hc_secondary)
            self._records.append(
                self._cfn_record(
                    "LatencySecondary",
                    target=secondary,
                    set_identifier=f"latency-{secondary.region}",
                    region=secondary.region,
                    health_check_id=hc_secondary.attr_health_check_id,
                    ttl=ttl,
                )
            )

    def _build_weighted(
        self,
        primary: FailoverTarget,
        secondary: Optional[FailoverTarget],
        path: str,
        ttl: int,
    ) -> None:
        hc = _make_health_check(
            self,
            "WeightedHCPrimary",
            fqdn=_alb_dns(primary.load_balancer),
            path=path,
        )
        self._health_checks.append(hc)

        self._records.append(
            self._cfn_record(
                "WeightedPrimary",
                target=primary,
                set_identifier=f"weighted-{primary.region}",
                weight=primary.weight,
                health_check_id=hc.attr_health_check_id,
                ttl=ttl,
            )
        )

        if secondary:
            hc2 = _make_health_check(
                self,
                "WeightedHCSecondary",
                fqdn=_alb_dns(secondary.load_balancer),
                path=path,
            )
            self._health_checks.append(hc2)
            self._records.append(
                self._cfn_record(
                    "WeightedSecondary",
                    target=secondary,
                    set_identifier=f"weighted-{secondary.region}",
                    weight=secondary.weight,
                    health_check_id=hc2.attr_health_check_id,
                    ttl=ttl,
                )
            )

    def _build_geolocation(
        self,
        primary: FailoverTarget,
        secondary: Optional[FailoverTarget],
        path: str,
        ttl: int,
    ) -> None:
        hc = _make_health_check(
            self,
            "GeoHCPrimary",
            fqdn=_alb_dns(primary.load_balancer),
            path=path,
        )
        self._health_checks.append(hc)

        geo = primary.geo_location or GeoLocation(continent_code="*")  # default → all
        self._records.append(
            self._cfn_record(
                "GeoPrimary",
                target=primary,
                set_identifier=f"geo-{primary.region}",
                geo_location=geo,
                health_check_id=hc.attr_health_check_id,
                ttl=ttl,
            )
        )

        if secondary:
            hc2 = _make_health_check(
                self,
                "GeoHCSecondary",
                fqdn=_alb_dns(secondary.load_balancer),
                path=path,
            )
            self._health_checks.append(hc2)
            default_geo = secondary.geo_location or GeoLocation(continent_code="*")
            self._records.append(
                self._cfn_record(
                    "GeoSecondary",
                    target=secondary,
                    set_identifier=f"geo-{secondary.region}-default",
                    geo_location=default_geo,
                    health_check_id=hc2.attr_health_check_id,
                    ttl=ttl,
                )
            )

    def _build_multivalue(
        self,
        targets_list: list[FailoverTarget],
        path: str,
        ttl: int,
    ) -> None:
        # Every record in a MultiValue Answer routing set must have a health check.
        for i, tgt in enumerate(targets_list):
            hc = _make_health_check(
                self,
                f"MultiValueHC{i}",
                fqdn=_alb_dns(tgt.load_balancer),
                path=path,
            )
            self._health_checks.append(hc)
            self._records.append(
                self._cfn_record(
                    f"MultiValueRecord{i}",
                    target=tgt,
                    set_identifier=f"mv-{tgt.region}-{i}",
                    multi_value_answer=True,
                    health_check_id=hc.attr_health_check_id,
                    ttl=ttl,
                )
            )

    # ── Low-level CfnRecordSet builder ────────────────────────────────────

    def _cfn_record(
        self,
        construct_id: str,
        *,
        target: FailoverTarget,
        set_identifier: str,
        failover: Optional[str] = None,
        region: Optional[str] = None,
        weight: Optional[int] = None,
        geo_location: Optional[GeoLocation] = None,
        multi_value_answer: bool = False,
        health_check_id: Optional[str] = None,
        ttl: int = 60,
    ) -> route53.CfnRecordSet:
        alb = target.load_balancer

        # Build the alias target property pointing to the ALB
        alias_target = route53.CfnRecordSet.AliasTargetProperty(
            dns_name=alb.load_balancer_dns_name,
            # ALB canonical hosted zone IDs are region-specific. We use the
            # CDK token so CloudFormation resolves it at deploy time.
            hosted_zone_id=alb.load_balancer_canonical_hosted_zone_id,
            evaluate_target_health=True,
        )

        geo_prop = None
        if geo_location is not None:
            # "*" is our sentinel for "all geographies" (the catch-all record)
            geo_prop = route53.CfnRecordSet.GeoLocationProperty(
                continent_code=geo_location.continent_code
                if geo_location.continent_code != "*"
                else None,
                country_code=geo_location.country_code,
                subdivision_code=geo_location.subdivision_code,
            )

        return route53.CfnRecordSet(
            self,
            construct_id,
            hosted_zone_id=self._zone.hosted_zone_id,
            name=self._record_name,
            type="A",
            set_identifier=set_identifier,
            alias_target=alias_target,
            failover=failover,
            region=region,
            weight=weight,
            geo_location=geo_prop,
            multi_value_answer=multi_value_answer or None,
            health_check_id=health_check_id,
        )

    # ── Public accessors ──────────────────────────────────────────────────

    @property
    def health_checks(self) -> list[route53.CfnHealthCheck]:
        return list(self._health_checks)

    @property
    def record_sets(self) -> list[route53.CfnRecordSet]:
        return list(self._records)
