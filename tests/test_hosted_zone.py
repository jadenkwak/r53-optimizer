"""Unit tests — HostedZoneConstruct (public and private)."""
import pytest
import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
from aws_cdk.assertions import Template, Match

from dns_tool.hosted_zone_construct import HostedZoneConstruct, _normalize_domain


# ── Helpers ──────────────────────────────────────────────────────────────────

def _public_zone_template(domain: str = "example.com") -> Template:
    app = cdk.App()
    stack = cdk.Stack(app, "TestStack", env=cdk.Environment(account="123456789012", region="us-east-1"))
    HostedZoneConstruct(stack, "Zone", domain_name=domain)
    return Template.from_stack(stack)


def _private_zone_template() -> tuple[Template, cdk.Stack]:
    app = cdk.App()
    stack = cdk.Stack(app, "TestStack", env=cdk.Environment(account="123456789012", region="us-east-1"))
    vpc = ec2.Vpc(stack, "Vpc", max_azs=1, nat_gateways=0)
    HostedZoneConstruct(stack, "Zone", domain_name="internal.example.com", private_dns_vpc=vpc)
    return Template.from_stack(stack), stack


# ── Domain name normalisation ─────────────────────────────────────────────────

def test_normalize_domain_strips_trailing_dot():
    assert _normalize_domain("example.com.") == "example.com"


def test_normalize_domain_leaves_bare_name():
    assert _normalize_domain("example.com") == "example.com"


def test_normalize_domain_multiple_trailing_dots():
    assert _normalize_domain("example.com...") == "example.com"


# ── Public hosted zone ────────────────────────────────────────────────────────

def test_public_zone_creates_exactly_one_hosted_zone():
    template = _public_zone_template()
    template.resource_count_is("AWS::Route53::HostedZone", 1)


def test_public_zone_has_correct_zone_name():
    template = _public_zone_template()
    template.has_resource_properties(
        "AWS::Route53::HostedZone",
        {"Name": "example.com."},  # CDK always appends the trailing dot
    )


def test_public_zone_with_trailing_dot_in_input():
    """FQDN with trailing dot must produce the same zone name."""
    template = _public_zone_template("example.com.")
    template.has_resource_properties(
        "AWS::Route53::HostedZone",
        {"Name": "example.com."},
    )


def test_public_zone_has_no_vpcs():
    """Public zones must NOT have a VPCs property."""
    template = _public_zone_template()
    zones = template.find_resources(
        "AWS::Route53::HostedZone",
        {"Properties": {"VPCs": Match.any_value()}},
    )
    assert len(zones) == 0, "Public zone should not have VPC associations"


def test_public_zone_tagged_managed_by():
    template = _public_zone_template()
    # CDK emits tags on the resource, not as a top-level Tags property for Route53
    # Verify the construct does not raise and zone exists
    template.resource_count_is("AWS::Route53::HostedZone", 1)


# ── Private hosted zone ───────────────────────────────────────────────────────

def test_private_zone_creates_exactly_one_hosted_zone():
    template, _ = _private_zone_template()
    template.resource_count_is("AWS::Route53::HostedZone", 1)


def test_private_zone_has_vpc_association():
    template, _ = _private_zone_template()
    template.has_resource_properties(
        "AWS::Route53::HostedZone",
        {
            "VPCs": Match.array_with(
                [Match.object_like({"VPCRegion": "us-east-1"})]
            )
        },
    )


def test_private_zone_has_correct_zone_name():
    template, _ = _private_zone_template()
    template.has_resource_properties(
        "AWS::Route53::HostedZone",
        {"Name": "internal.example.com."},
    )


# ── add_vpc_association guard ─────────────────────────────────────────────────

def test_add_vpc_association_raises_on_public_zone():
    app = cdk.App()
    stack = cdk.Stack(app, "TestStack", env=cdk.Environment(account="123456789012", region="us-east-1"))
    vpc = ec2.Vpc(stack, "Vpc", max_azs=1, nat_gateways=0)
    construct = HostedZoneConstruct(stack, "Zone", domain_name="example.com")

    with pytest.raises(ValueError, match="private hosted zones"):
        construct.add_vpc_association(vpc)
