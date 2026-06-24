"""Reusable HostedZone construct — wraps public and private Route 53 hosted zones."""
from __future__ import annotations

import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_route53 as route53
from constructs import Construct


def _normalize_domain(name: str) -> str:
    """Strip trailing dot so callers can pass FQDNs or bare names interchangeably."""
    return name.rstrip(".")


class HostedZoneConstruct(Construct):
    """
    Reusable construct that creates a Route 53 hosted zone.

    Public zones are internet-resolvable. Private zones are scoped to the
    supplied VPC; the VPC must have both enableDnsHostnames and
    enableDnsSupport set to True (CDK sets these by default, but explicit
    IVpc references from imports must have these attributes confirmed).
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        domain_name: str,
        comment: str = "",
        private_dns_vpc: ec2.IVpc | None = None,
    ) -> None:
        super().__init__(scope, construct_id)

        normalized = _normalize_domain(domain_name)

        if private_dns_vpc is not None:
            self._zone = route53.PrivateHostedZone(
                self,
                "Zone",
                zone_name=normalized,
                vpc=private_dns_vpc,
                comment=comment or f"Private zone for {normalized}",
            )
            self._is_private = True
        else:
            self._zone = route53.PublicHostedZone(
                self,
                "Zone",
                zone_name=normalized,
                comment=comment or f"Public zone for {normalized}",
                # CAA records prevent mis-issuance; callers can add CAA records
                # separately — this flag keeps the CDK default (no auto-CAA).
            )
            self._is_private = False

        cdk.Tags.of(self).add("ManagedBy", "dns-tool")
        cdk.Tags.of(self).add("ZoneType", "private" if self._is_private else "public")

    # ── Public surface ──────────────────────────────────────────────────────

    @property
    def hosted_zone(self) -> route53.IHostedZone:
        """The underlying CDK IHostedZone; pass this to record constructs."""
        return self._zone

    @property
    def is_private(self) -> bool:
        return self._is_private

    def add_vpc_association(self, vpc: ec2.IVpc) -> None:
        """Associate an additional VPC with a private zone (cross-account VPCs
        require a separate authorization step outside CDK)."""
        if not self._is_private or not isinstance(self._zone, route53.PrivateHostedZone):
            raise ValueError("VPC associations are only valid for private hosted zones.")
        self._zone.add_vpc(vpc)
