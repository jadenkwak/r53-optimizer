"""Top-level demonstration stack — shows every construct working together."""
from __future__ import annotations

import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_elasticloadbalancingv2 as elbv2
import aws_cdk.aws_route53 as route53
import aws_cdk.aws_route53_targets as targets
from constructs import Construct

from .failover_construct import FailoverConstruct, FailoverTarget, RoutingPolicy
from .hosted_zone_construct import HostedZoneConstruct
from .iam_policies import DnsIamPolicies
from .record_constructs import AliasRecord, AliasTarget, RecordType, SimpleRecord


class DnsToolStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── Public hosted zone ──────────────────────────────────────────────
        public_zone = HostedZoneConstruct(
            self,
            "PublicZone",
            domain_name="example.com",
            comment="Managed by DNS-tool CDK app",
        )

        # ── Private hosted zone with a demo VPC ────────────────────────────
        vpc = ec2.Vpc(
            self,
            "DemoVpc",
            max_azs=2,
            enable_dns_hostnames=True,
            enable_dns_support=True,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                )
            ],
        )

        private_zone = HostedZoneConstruct(
            self,
            "PrivateZone",
            domain_name="internal.example.com",
            private_dns_vpc=vpc,
            comment="Internal service discovery — private hosted zone",
        )

        # ── Simple A record (non-alias, plain IP) ──────────────────────────
        SimpleRecord(
            self,
            "MailRecord",
            zone=public_zone.hosted_zone,
            record_name="mail",
            record_type=RecordType.A,
            values=["203.0.113.10"],
            ttl=cdk.Duration.minutes(5),
        )

        # ── MX record ──────────────────────────────────────────────────────
        SimpleRecord(
            self,
            "MxRecord",
            zone=public_zone.hosted_zone,
            record_name="",  # zone apex MX
            record_type=RecordType.MX,
            values=["10 mail.example.com."],
            ttl=cdk.Duration.hours(1),
        )

        # ── ALB for alias targets ───────────────────────────────────────────
        alb = elbv2.ApplicationLoadBalancer(
            self,
            "DemoAlb",
            vpc=vpc,
            internet_facing=True,
        )

        # Zone-apex alias → ALB  (CNAME at apex is forbidden; alias is correct)
        AliasRecord(
            self,
            "ApexAlias",
            zone=public_zone.hosted_zone,
            record_name="",  # zone apex
            alias_target=AliasTarget.from_load_balancer(alb),
        )

        # www subdomain alias → ALB
        AliasRecord(
            self,
            "WwwAlias",
            zone=public_zone.hosted_zone,
            record_name="www",
            alias_target=AliasTarget.from_load_balancer(alb),
        )

        # ── Failover construct (primary + secondary with health check) ──────
        FailoverConstruct(
            self,
            "ApiFailover",
            zone=public_zone.hosted_zone,
            record_name="api",
            routing_policy=RoutingPolicy.FAILOVER,
            primary=FailoverTarget(
                load_balancer=alb,
                region="us-east-1",
            ),
            secondary=FailoverTarget(
                load_balancer=alb,  # same ALB — replace with real secondary
                region="us-west-2",
            ),
            health_check_path="/healthz",
        )

        # ── Subdomain delegation ────────────────────────────────────────────
        # Delegate "staging.example.com" to a separate hosted zone
        staging_ns = ["ns-111.awsdns-11.com", "ns-222.awsdns-22.net"]
        SimpleRecord(
            self,
            "StagingDelegation",
            zone=public_zone.hosted_zone,
            record_name="staging",
            record_type=RecordType.NS,
            values=staging_ns,
            ttl=cdk.Duration.hours(2),
        )

        # ── IAM policies ────────────────────────────────────────────────────
        policies = DnsIamPolicies(self, "DnsPolicies")

        # Allow managing *.example.com records
        allow_policy = policies.allow_suffix_policy(
            policy_name="AllowExampleCom",
            hosted_zone_id=public_zone.hosted_zone.hosted_zone_id,
            allowed_suffix="example.com",
        )

        # Deny touching infra records (*.infra.example.com)
        deny_policy = policies.deny_suffix_policy(
            policy_name="DenyInfraSuffix",
            hosted_zone_id=public_zone.hosted_zone.hosted_zone_id,
            protected_suffix="infra.example.com",
        )

        # ── Outputs ─────────────────────────────────────────────────────────
        cdk.CfnOutput(
            self,
            "PublicZoneId",
            value=public_zone.hosted_zone.hosted_zone_id,
            description="Public hosted zone ID",
        )
        cdk.CfnOutput(
            self,
            "PrivateZoneId",
            value=private_zone.hosted_zone.hosted_zone_id,
            description="Private hosted zone ID",
        )
        cdk.CfnOutput(
            self,
            "AllowPolicyArn",
            value=allow_policy.managed_policy_arn,
            description="IAM policy ARN — allow example.com management",
        )
        cdk.CfnOutput(
            self,
            "DenyPolicyArn",
            value=deny_policy.managed_policy_arn,
            description="IAM policy ARN — deny infra.example.com writes",
        )
