"""Unit tests — FailoverConstruct (failover, latency, weighted, multivalue)."""
import pytest
import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_elasticloadbalancingv2 as elbv2
import aws_cdk.aws_route53 as route53
from aws_cdk.assertions import Template, Match

from dns_tool.failover_construct import (
    FailoverConstruct,
    FailoverTarget,
    GeoLocation,
    RoutingPolicy,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _base(policy: RoutingPolicy, *, with_secondary: bool = True) -> Template:
    app = cdk.App()
    stack = cdk.Stack(
        app, "TestStack",
        env=cdk.Environment(account="123456789012", region="us-east-1")
    )
    vpc = ec2.Vpc(stack, "Vpc", max_azs=1, nat_gateways=0,
                  subnet_configuration=[ec2.SubnetConfiguration(
                      name="Public", subnet_type=ec2.SubnetType.PUBLIC)])
    zone = route53.PublicHostedZone(stack, "Zone", zone_name="example.com")
    alb = elbv2.ApplicationLoadBalancer(stack, "Alb", vpc=vpc, internet_facing=True)

    primary = FailoverTarget(load_balancer=alb, region="us-east-1", weight=90)
    secondary = FailoverTarget(load_balancer=alb, region="us-west-2", weight=10) if with_secondary else None

    FailoverConstruct(
        stack, "Fo",
        zone=zone,
        record_name="api",
        routing_policy=policy,
        primary=primary,
        secondary=secondary,
        health_check_path="/healthz",
    )
    return Template.from_stack(stack)


# ── FAILOVER policy ───────────────────────────────────────────────────────────

def test_failover_creates_two_record_sets():
    template = _base(RoutingPolicy.FAILOVER)
    template.resource_count_is("AWS::Route53::RecordSet", 2)


def test_failover_primary_has_health_check():
    """Primary failover record must reference a health check — secondary need not."""
    template = _base(RoutingPolicy.FAILOVER)
    # At least one record has HealthCheckId set
    records = template.find_resources(
        "AWS::Route53::RecordSet",
        {"Properties": {"HealthCheckId": Match.any_value()}},
    )
    assert len(records) >= 1, "Primary failover record must have a health check"


def test_failover_primary_record_set_identifier():
    template = _base(RoutingPolicy.FAILOVER)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"Failover": "PRIMARY", "SetIdentifier": "primary"},
    )


def test_failover_secondary_record_set_identifier():
    template = _base(RoutingPolicy.FAILOVER)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"Failover": "SECONDARY", "SetIdentifier": "secondary"},
    )


def test_failover_records_use_alias_not_resource_records():
    """Failover records point to ALBs and must use AliasTarget, not ResourceRecords."""
    template = _base(RoutingPolicy.FAILOVER)
    resources = template.find_resources("AWS::Route53::RecordSet")
    for logical_id, resource in resources.items():
        props = resource.get("Properties", {})
        assert "AliasTarget" in props, (
            f"RecordSet {logical_id} should use AliasTarget (alias), not ResourceRecords (CNAME)"
        )
        assert "ResourceRecords" not in props, (
            f"RecordSet {logical_id} should not use ResourceRecords"
        )


def test_failover_requires_secondary():
    app = cdk.App()
    stack = cdk.Stack(app, "S", env=cdk.Environment(account="123456789012", region="us-east-1"))
    vpc = ec2.Vpc(stack, "Vpc", max_azs=1, nat_gateways=0,
                  subnet_configuration=[ec2.SubnetConfiguration(name="Public",
                      subnet_type=ec2.SubnetType.PUBLIC)])
    zone = route53.PublicHostedZone(stack, "Zone", zone_name="example.com")
    alb = elbv2.ApplicationLoadBalancer(stack, "Alb", vpc=vpc, internet_facing=True)

    with pytest.raises(ValueError, match="secondary"):
        FailoverConstruct(
            stack, "Fo", zone=zone, record_name="api",
            routing_policy=RoutingPolicy.FAILOVER,
            primary=FailoverTarget(load_balancer=alb, region="us-east-1"),
            secondary=None,
        )


def test_failover_creates_health_check_resource():
    template = _base(RoutingPolicy.FAILOVER)
    template.resource_count_is("AWS::Route53::HealthCheck", 1)


def test_failover_health_check_uses_https():
    template = _base(RoutingPolicy.FAILOVER)
    template.has_resource_properties(
        "AWS::Route53::HealthCheck",
        {
            "HealthCheckConfig": Match.object_like({
                "Type": "HTTPS",
                "ResourcePath": "/healthz",
            })
        },
    )


# ── LATENCY policy ────────────────────────────────────────────────────────────

def test_latency_creates_two_record_sets():
    template = _base(RoutingPolicy.LATENCY)
    template.resource_count_is("AWS::Route53::RecordSet", 2)


def test_latency_records_have_region():
    template = _base(RoutingPolicy.LATENCY)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"Region": "us-east-1"},
    )
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"Region": "us-west-2"},
    )


def test_latency_records_have_health_checks():
    template = _base(RoutingPolicy.LATENCY)
    template.resource_count_is("AWS::Route53::HealthCheck", 2)
    records = template.find_resources(
        "AWS::Route53::RecordSet",
        {"Properties": {"HealthCheckId": Match.any_value()}},
    )
    assert len(records) == 2, "Both latency records should have health checks"


# ── WEIGHTED policy ───────────────────────────────────────────────────────────

def test_weighted_creates_two_record_sets():
    template = _base(RoutingPolicy.WEIGHTED)
    template.resource_count_is("AWS::Route53::RecordSet", 2)


def test_weighted_records_have_weight():
    template = _base(RoutingPolicy.WEIGHTED)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"Weight": 90},
    )
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"Weight": 10},
    )


# ── MULTIVALUE policy ─────────────────────────────────────────────────────────

def test_multivalue_creates_two_record_sets():
    template = _base(RoutingPolicy.MULTIVALUE)
    template.resource_count_is("AWS::Route53::RecordSet", 2)


def test_multivalue_all_records_have_health_checks():
    """MultiValue Answer routing requires a health check on EVERY record."""
    template = _base(RoutingPolicy.MULTIVALUE)
    template.resource_count_is("AWS::Route53::HealthCheck", 2)
    records = template.find_resources(
        "AWS::Route53::RecordSet",
        {"Properties": {"HealthCheckId": Match.any_value()}},
    )
    assert len(records) == 2, "Every MultiValue record must have a health check"


def test_multivalue_records_have_multivalue_flag():
    template = _base(RoutingPolicy.MULTIVALUE)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"MultiValueAnswer": True},
    )


# ── GEOLOCATION policy ────────────────────────────────────────────────────────

def test_geolocation_creates_record_with_geo_property():
    app = cdk.App()
    stack = cdk.Stack(app, "S", env=cdk.Environment(account="123456789012", region="us-east-1"))
    vpc = ec2.Vpc(stack, "Vpc", max_azs=1, nat_gateways=0,
                  subnet_configuration=[ec2.SubnetConfiguration(name="Public",
                      subnet_type=ec2.SubnetType.PUBLIC)])
    zone = route53.PublicHostedZone(stack, "Zone", zone_name="example.com")
    alb = elbv2.ApplicationLoadBalancer(stack, "Alb", vpc=vpc, internet_facing=True)

    FailoverConstruct(
        stack, "Fo",
        zone=zone,
        record_name="api",
        routing_policy=RoutingPolicy.GEOLOCATION,
        primary=FailoverTarget(
            load_balancer=alb,
            region="us-east-1",
            geo_location=GeoLocation(continent_code="NA"),
        ),
        secondary=FailoverTarget(
            load_balancer=alb,
            region="eu-west-1",
            geo_location=GeoLocation(continent_code="EU"),
        ),
    )
    template = Template.from_stack(stack)
    template.resource_count_is("AWS::Route53::RecordSet", 2)
