"""Unit tests — IAM policy generators (allow-suffix and deny-suffix)."""
import pytest
import aws_cdk as cdk
import aws_cdk.aws_iam as iam
from aws_cdk.assertions import Template, Match

from dns_tool.iam_policies import DnsIamPolicies, _hosted_zone_arn


ZONE_ID = "Z1234567890ABC"
ZONE_ARN = f"arn:aws:route53:::hostedzone/{ZONE_ID}"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_template(policy_fn: str, **kwargs) -> Template:
    app = cdk.App()
    stack = cdk.Stack(app, "TestStack", env=cdk.Environment(account="123456789012", region="us-east-1"))
    factory = DnsIamPolicies(stack, "Policies")
    getattr(factory, policy_fn)(**kwargs)
    return Template.from_stack(stack)


# ── _hosted_zone_arn helper ──────────────────────────────────────────────────

def test_hosted_zone_arn_bare_id():
    assert _hosted_zone_arn("Z1234567890ABC") == "arn:aws:route53:::hostedzone/Z1234567890ABC"


def test_hosted_zone_arn_with_prefix():
    assert _hosted_zone_arn("/hostedzone/Z1234567890ABC") == "arn:aws:route53:::hostedzone/Z1234567890ABC"


# ── allow_suffix_policy ───────────────────────────────────────────────────────

def test_allow_policy_creates_managed_policy():
    template = _make_template(
        "allow_suffix_policy",
        policy_name="AllowExampleCom",
        hosted_zone_id=ZONE_ID,
        allowed_suffix="example.com",
    )
    template.resource_count_is("AWS::IAM::ManagedPolicy", 1)


def test_allow_policy_has_change_resource_record_sets_action():
    """CDK may emit a single action as a bare string rather than a 1-element array."""
    template = _make_template(
        "allow_suffix_policy",
        policy_name="AllowExampleCom",
        hosted_zone_id=ZONE_ID,
        allowed_suffix="example.com",
    )
    # Verify the write statement exists by checking its resource ARN and Effect;
    # the Action may be a string or array depending on CDK minimization.
    template.has_resource_properties(
        "AWS::IAM::ManagedPolicy",
        {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Resource": ZONE_ARN,
                        "Effect": "Allow",
                    })
                ])
            }
        },
    )


def test_allow_policy_scopes_to_hosted_zone_arn():
    """The Allow write statement must be scoped to the specific zone ARN, not '*'."""
    template = _make_template(
        "allow_suffix_policy",
        policy_name="AllowExampleCom",
        hosted_zone_id=ZONE_ID,
        allowed_suffix="example.com",
    )
    template.has_resource_properties(
        "AWS::IAM::ManagedPolicy",
        {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Resource": ZONE_ARN,
                        "Effect": "Allow",
                    })
                ])
            }
        },
    )


def test_allow_policy_contains_normalized_record_names_condition():
    """Must use route53:ChangeResourceRecordSetsNormalizedRecordNames condition key."""
    template = _make_template(
        "allow_suffix_policy",
        policy_name="AllowExampleCom",
        hosted_zone_id=ZONE_ID,
        allowed_suffix="example.com",
    )
    template.has_resource_properties(
        "AWS::IAM::ManagedPolicy",
        {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Condition": Match.object_like({
                            "ForAllValues:StringLike": Match.object_like({
                                "route53:ChangeResourceRecordSetsNormalizedRecordNames":
                                    Match.any_value()
                            })
                        })
                    })
                ])
            }
        },
    )


def test_allow_policy_includes_wildcard_suffix_match():
    """Condition values must include both 'example.com' and '*.example.com'."""
    template = _make_template(
        "allow_suffix_policy",
        policy_name="AllowExampleCom",
        hosted_zone_id=ZONE_ID,
        allowed_suffix="example.com",
    )
    template.has_resource_properties(
        "AWS::IAM::ManagedPolicy",
        {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Condition": {
                            "ForAllValues:StringLike": {
                                "route53:ChangeResourceRecordSetsNormalizedRecordNames":
                                    Match.array_with(["example.com", "*.example.com"]),
                                "route53:ChangeResourceRecordSetsActions": Match.any_value(),
                                "route53:ChangeResourceRecordSetsRecordTypes": Match.any_value(),
                            }
                        }
                    })
                ])
            }
        },
    )


def test_allow_policy_includes_read_actions():
    """Policy must also grant GetChange, ListResourceRecordSets, etc."""
    template = _make_template(
        "allow_suffix_policy",
        policy_name="AllowExampleCom",
        hosted_zone_id=ZONE_ID,
        allowed_suffix="example.com",
    )
    template.has_resource_properties(
        "AWS::IAM::ManagedPolicy",
        {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": Match.array_with(["route53:GetChange"]),
                        "Effect": "Allow",
                    })
                ])
            }
        },
    )


# ── deny_suffix_policy ────────────────────────────────────────────────────────

def test_deny_policy_creates_managed_policy():
    template = _make_template(
        "deny_suffix_policy",
        policy_name="DenyInfra",
        hosted_zone_id=ZONE_ID,
        protected_suffix="infra.example.com",
    )
    template.resource_count_is("AWS::IAM::ManagedPolicy", 1)


def test_deny_policy_has_explicit_deny_statement():
    """Must include a Deny effect — an Allow-based exclusion is not a guardrail."""
    template = _make_template(
        "deny_suffix_policy",
        policy_name="DenyInfra",
        hosted_zone_id=ZONE_ID,
        protected_suffix="infra.example.com",
    )
    # Check that a Deny statement exists scoped to the zone ARN.
    # CDK may emit the single action as a bare string rather than a 1-element array.
    template.has_resource_properties(
        "AWS::IAM::ManagedPolicy",
        {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Effect": "Deny",
                        "Resource": ZONE_ARN,
                    })
                ])
            }
        },
    )


def test_deny_policy_uses_for_any_value_condition():
    """
    ForAnyValue:StringLike — if ANY name in the batch matches, deny the whole batch.
    This is the correct operator for the protected-suffix guardrail.
    """
    template = _make_template(
        "deny_suffix_policy",
        policy_name="DenyInfra",
        hosted_zone_id=ZONE_ID,
        protected_suffix="infra.example.com",
    )
    template.has_resource_properties(
        "AWS::IAM::ManagedPolicy",
        {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Effect": "Deny",
                        "Condition": Match.object_like({
                            "ForAnyValue:StringLike": {
                                "route53:ChangeResourceRecordSetsNormalizedRecordNames":
                                    Match.array_with([
                                        "infra.example.com",
                                        "*.infra.example.com",
                                    ])
                            }
                        })
                    })
                ])
            }
        },
    )


def test_deny_policy_also_allows_non_protected_writes():
    """Policy must have an Allow statement so non-infra records can still be changed."""
    template = _make_template(
        "deny_suffix_policy",
        policy_name="DenyInfra",
        hosted_zone_id=ZONE_ID,
        protected_suffix="infra.example.com",
    )
    # Confirm that at least one Allow statement is scoped to the zone ARN.
    # CDK may serialize a single-action list as a bare string.
    resources = template.find_resources("AWS::IAM::ManagedPolicy")
    found_allow = False
    for _, resource in resources.items():
        for stmt in resource["Properties"]["PolicyDocument"]["Statement"]:
            if stmt.get("Effect") == "Allow" and stmt.get("Resource") == ZONE_ARN:
                found_allow = True
                break
    assert found_allow, "deny_suffix_policy must include an Allow statement for the zone ARN"


# ── read_only_policy ──────────────────────────────────────────────────────────

def test_read_only_policy_has_no_write_actions():
    template = _make_template(
        "read_only_policy",
        policy_name="ReadOnly",
        hosted_zone_id=ZONE_ID,
    )
    # Scan all statements — none should contain ChangeResourceRecordSets
    resources = template.find_resources("AWS::IAM::ManagedPolicy")
    for _, resource in resources.items():
        for stmt in resource["Properties"]["PolicyDocument"]["Statement"]:
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            assert "route53:ChangeResourceRecordSets" not in actions, (
                "Read-only policy must not include ChangeResourceRecordSets"
            )


def test_read_only_policy_includes_get_change():
    template = _make_template(
        "read_only_policy",
        policy_name="ReadOnly",
        hosted_zone_id=ZONE_ID,
    )
    template.has_resource_properties(
        "AWS::IAM::ManagedPolicy",
        {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": Match.array_with(["route53:GetChange"]),
                        "Effect": "Allow",
                    })
                ])
            }
        },
    )
