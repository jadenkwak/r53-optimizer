"""Unit tests — record constructs (AliasRecord, CnameRecord, SimpleRecord)."""
import pytest
import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_elasticloadbalancingv2 as elbv2
import aws_cdk.aws_route53 as route53
from aws_cdk.assertions import Template, Match

from dns_tool.record_constructs import (
    AliasRecord,
    AliasTarget,
    CnameRecord,
    RecordType,
    SimpleRecord,
    _is_apex,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _base_stack() -> tuple[cdk.Stack, ec2.Vpc, route53.PublicHostedZone, elbv2.ApplicationLoadBalancer]:
    app = cdk.App()
    stack = cdk.Stack(app, "TestStack", env=cdk.Environment(account="123456789012", region="us-east-1"))
    vpc = ec2.Vpc(stack, "Vpc", max_azs=1, nat_gateways=0,
                  subnet_configuration=[ec2.SubnetConfiguration(
                      name="Public", subnet_type=ec2.SubnetType.PUBLIC)])
    zone = route53.PublicHostedZone(stack, "Zone", zone_name="example.com")
    alb = elbv2.ApplicationLoadBalancer(stack, "Alb", vpc=vpc, internet_facing=True)
    return stack, vpc, zone, alb


# ── _is_apex ─────────────────────────────────────────────────────────────────

def test_is_apex_empty_string():
    app = cdk.App()
    stack = cdk.Stack(app, "S")
    zone = route53.PublicHostedZone(stack, "Z", zone_name="example.com")
    assert _is_apex(zone, "") is True


def test_is_apex_zone_name_itself():
    app = cdk.App()
    stack = cdk.Stack(app, "S")
    zone = route53.PublicHostedZone(stack, "Z", zone_name="example.com")
    assert _is_apex(zone, "example.com") is True


def test_is_apex_subdomain_is_not_apex():
    app = cdk.App()
    stack = cdk.Stack(app, "S")
    zone = route53.PublicHostedZone(stack, "Z", zone_name="example.com")
    assert _is_apex(zone, "www") is False


def test_is_apex_with_trailing_dot():
    app = cdk.App()
    stack = cdk.Stack(app, "S")
    zone = route53.PublicHostedZone(stack, "Z", zone_name="example.com")
    assert _is_apex(zone, "example.com.") is True


# ── AliasRecord ───────────────────────────────────────────────────────────────

def test_alias_record_synthesises_record_set():
    stack, _, zone, alb = _base_stack()
    AliasRecord(stack, "Alias", zone=zone, record_name="www",
                alias_target=AliasTarget.from_load_balancer(alb))
    template = Template.from_stack(stack)
    template.resource_count_is("AWS::Route53::RecordSet", 1)


def test_alias_record_type_is_A():
    """Alias records to ALBs must be type A (not CNAME)."""
    stack, _, zone, alb = _base_stack()
    AliasRecord(stack, "Alias", zone=zone, record_name="www",
                alias_target=AliasTarget.from_load_balancer(alb))
    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"Type": "A"},
    )


def test_alias_record_has_alias_target_not_resource_records():
    """Alias records must use AliasTarget, not ResourceRecords (which would be a CNAME)."""
    stack, _, zone, alb = _base_stack()
    AliasRecord(stack, "Alias", zone=zone, record_name="www",
                alias_target=AliasTarget.from_load_balancer(alb))
    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"AliasTarget": Match.object_like({"DNSName": Match.any_value()})},
    )


def test_alias_record_has_no_ttl():
    """Alias records to AWS resources must NOT have a TTL property."""
    stack, _, zone, alb = _base_stack()
    AliasRecord(stack, "Alias", zone=zone, record_name="www",
                alias_target=AliasTarget.from_load_balancer(alb))
    template = Template.from_stack(stack)
    # Find the RecordSet and assert TTL is absent
    resources = template.find_resources("AWS::Route53::RecordSet")
    for logical_id, resource in resources.items():
        props = resource.get("Properties", {})
        assert "TTL" not in props, f"Alias record {logical_id} must not have a TTL"


def test_alias_record_at_zone_apex():
    """Alias records at the zone apex (record_name='') must be synthesized correctly."""
    stack, _, zone, alb = _base_stack()
    AliasRecord(stack, "ApexAlias", zone=zone, record_name="",
                alias_target=AliasTarget.from_load_balancer(alb))
    template = Template.from_stack(stack)
    template.resource_count_is("AWS::Route53::RecordSet", 1)


def test_alias_record_rejects_non_a_aaaa_type():
    stack, _, zone, alb = _base_stack()
    with pytest.raises(ValueError, match="A or AAAA"):
        AliasRecord(stack, "Bad", zone=zone, record_name="www",
                    alias_target=AliasTarget.from_load_balancer(alb),
                    record_type=RecordType.CNAME)


# ── CnameRecord ───────────────────────────────────────────────────────────────

def test_cname_record_synthesises():
    stack, _, zone, _ = _base_stack()
    CnameRecord(stack, "Cname", zone=zone, record_name="alias",
                domain_name="target.example.net")
    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"Type": "CNAME", "ResourceRecords": ["target.example.net"]},
    )


def test_cname_record_at_apex_raises():
    """CNAME at zone apex must be rejected at synthesis time."""
    stack, _, zone, _ = _base_stack()
    with pytest.raises(ValueError, match="zone apex"):
        CnameRecord(stack, "ApexCname", zone=zone, record_name="",
                    domain_name="target.example.net")


def test_cname_record_at_apex_with_zone_name_raises():
    stack, _, zone, _ = _base_stack()
    with pytest.raises(ValueError, match="zone apex"):
        CnameRecord(stack, "ApexCname2", zone=zone, record_name="example.com",
                    domain_name="target.example.net")


def test_cname_record_has_ttl():
    stack, _, zone, _ = _base_stack()
    CnameRecord(stack, "Cname", zone=zone, record_name="sub",
                domain_name="target.example.net",
                ttl=cdk.Duration.seconds(120))
    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"TTL": "120"},
    )


# ── SimpleRecord ──────────────────────────────────────────────────────────────

def test_simple_record_mx():
    stack, _, zone, _ = _base_stack()
    SimpleRecord(stack, "Mx", zone=zone, record_name="example.com",
                 record_type=RecordType.MX, values=["10 mail.example.com."])
    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"Type": "MX", "ResourceRecords": ["10 mail.example.com."]},
    )


def test_simple_record_txt():
    stack, _, zone, _ = _base_stack()
    SimpleRecord(stack, "Spf", zone=zone, record_name="example.com",
                 record_type=RecordType.TXT, values=['"v=spf1 include:_spf.google.com ~all"'])
    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"Type": "TXT"},
    )


def test_simple_record_ns_delegation():
    stack, _, zone, _ = _base_stack()
    SimpleRecord(stack, "Delegation", zone=zone, record_name="staging",
                 record_type=RecordType.NS,
                 values=["ns-111.awsdns-11.com", "ns-222.awsdns-22.net"])
    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"Type": "NS", "ResourceRecords": Match.array_with(["ns-111.awsdns-11.com"])},
    )


def test_simple_record_cname_at_apex_raises():
    stack, _, zone, _ = _base_stack()
    with pytest.raises(ValueError, match="zone apex"):
        SimpleRecord(stack, "Bad", zone=zone, record_name="",
                     record_type=RecordType.CNAME, values=["target.example.net"])


def test_simple_a_record_has_ip_values():
    stack, _, zone, _ = _base_stack()
    SimpleRecord(stack, "Mail", zone=zone, record_name="mail",
                 record_type=RecordType.A, values=["203.0.113.10"])
    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::Route53::RecordSet",
        {"Type": "A", "ResourceRecords": ["203.0.113.10"]},
    )
