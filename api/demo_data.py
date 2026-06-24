"""
Realistic mock Route 53 data for demo mode.

Three hosted zones are defined, each with a mix of correct and problematic
records that exercise every analysis rule in the engine.
"""
from __future__ import annotations

from typing import Any

DEMO_ZONES: list[dict[str, Any]] = [
    {
        "Id": "/hostedzone/Z1DEMO000ACME1",
        "Name": "acme-corp.com.",
        "Config": {"Comment": "Primary production zone", "PrivateZone": False},
        "ResourceRecordSetCount": 14,
        "CallerReference": "demo-1",
    },
    {
        "Id": "/hostedzone/Z2DEMO000SHOP2",
        "Name": "shop.acme-corp.com.",
        "Config": {"Comment": "E-commerce subdomain", "PrivateZone": False},
        "ResourceRecordSetCount": 9,
        "CallerReference": "demo-2",
    },
    {
        "Id": "/hostedzone/Z3DEMO000INTL3",
        "Name": "internal.acme-corp.com.",
        "Config": {"Comment": "Internal service discovery", "PrivateZone": True},
        "ResourceRecordSetCount": 6,
        "CallerReference": "demo-3",
    },
]

DEMO_RECORDS: dict[str, list[dict[str, Any]]] = {

    # ── acme-corp.com ── many issues ────────────────────────────────────────
    "Z1DEMO000ACME1": [
        # SOA + NS (always present, skipped by rules)
        {
            "Name": "acme-corp.com.",
            "Type": "SOA",
            "TTL": 900,
            "ResourceRecords": [
                {"Value": "ns-1234.awsdns-12.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"}
            ],
        },
        {
            "Name": "acme-corp.com.",
            "Type": "NS",
            "TTL": 172800,
            "ResourceRecords": [
                {"Value": "ns-1234.awsdns-12.com."},
                {"Value": "ns-567.awsdns-34.net."},
                {"Value": "ns-890.awsdns-56.org."},
                {"Value": "ns-112.awsdns-78.co.uk."},
            ],
        },
        # ISSUE: Single A record at apex — no redundancy (SINGLE_POINT_OF_FAILURE)
        {
            "Name": "acme-corp.com.",
            "Type": "A",
            "TTL": 300,
            "ResourceRecords": [{"Value": "203.0.113.42"}],
        },
        # ISSUE: CNAME to CloudFront — should be ALIAS (CNAME_TO_AWS_ENDPOINT)
        {
            "Name": "www.acme-corp.com.",
            "Type": "CNAME",
            "TTL": 300,
            "ResourceRecords": [{"Value": "d3rp1234abcdef.cloudfront.net"}],
        },
        # ISSUE: CNAME to API Gateway — should be ALIAS (CNAME_TO_AWS_ENDPOINT)
        {
            "Name": "api.acme-corp.com.",
            "Type": "CNAME",
            "TTL": 60,
            "ResourceRecords": [
                {"Value": "x7k3m2.execute-api.us-east-1.amazonaws.com"}
            ],
        },
        # ISSUE: CNAME to ELB — should be ALIAS (CNAME_TO_AWS_ENDPOINT)
        {
            "Name": "app.acme-corp.com.",
            "Type": "CNAME",
            "TTL": 300,
            "ResourceRecords": [
                {"Value": "acme-prod-alb-1234567890.us-east-1.elb.amazonaws.com"}
            ],
        },
        # MX records present (triggers SPF/DMARC checks)
        {
            "Name": "acme-corp.com.",
            "Type": "MX",
            "TTL": 3600,
            "ResourceRecords": [
                {"Value": "10 aspmx.l.google.com."},
                {"Value": "20 alt1.aspmx.l.google.com."},
            ],
        },
        # ISSUE: No SPF record (MISSING_SPF) — would need v=spf1 in a TXT
        # ISSUE: No DMARC record (MISSING_DMARC) — would need _dmarc.acme-corp.com
        # ISSUE: No CAA records (MISSING_CAA)
        # Unrelated TXT (not SPF)
        {
            "Name": "acme-corp.com.",
            "Type": "TXT",
            "TTL": 3600,
            "ResourceRecords": [
                {"Value": '"google-site-verification=abc123xyz456"'},
            ],
        },
        # ISSUE: Very high TTL (HIGH_TTL) — 7 days
        {
            "Name": "mail.acme-corp.com.",
            "Type": "A",
            "TTL": 604800,
            "ResourceRecords": [{"Value": "203.0.113.10"}],
        },
        # ISSUE: Very high TTL (HIGH_TTL) — 2 days
        {
            "Name": "vpn.acme-corp.com.",
            "Type": "A",
            "TTL": 172800,
            "ResourceRecords": [{"Value": "203.0.113.99"}],
        },
        # Correct: alias record for assets (no issue)
        {
            "Name": "assets.acme-corp.com.",
            "Type": "A",
            "AliasTarget": {
                "DNSName": "d9abc123defgh.cloudfront.net.",
                "EvaluateTargetHealth": False,
                "HostedZoneId": "Z2FDTNDATAQYW2",
            },
        },
        # Subdomain delegation (correct)
        {
            "Name": "shop.acme-corp.com.",
            "Type": "NS",
            "TTL": 7200,
            "ResourceRecords": [
                {"Value": "ns-111.awsdns-11.com."},
                {"Value": "ns-222.awsdns-22.net."},
            ],
        },
        # staging TXT for verification (correct — no issue)
        {
            "Name": "_acme-challenge.acme-corp.com.",
            "Type": "TXT",
            "TTL": 300,
            "ResourceRecords": [{"Value": '"aBcDeFgHiJkLmNoPqRsTuVwXyZ12345"'}],
        },
    ],

    # ── shop.acme-corp.com ── failover + routing issues ─────────────────────
    "Z2DEMO000SHOP2": [
        {
            "Name": "shop.acme-corp.com.",
            "Type": "SOA",
            "TTL": 900,
            "ResourceRecords": [
                {"Value": "ns-111.awsdns-11.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"}
            ],
        },
        {
            "Name": "shop.acme-corp.com.",
            "Type": "NS",
            "TTL": 172800,
            "ResourceRecords": [
                {"Value": "ns-111.awsdns-11.com."},
                {"Value": "ns-222.awsdns-22.net."},
            ],
        },
        # ISSUE: Failover PRIMARY with no health check (FAILOVER_NO_HEALTH_CHECK)
        {
            "Name": "shop.acme-corp.com.",
            "Type": "A",
            "SetIdentifier": "primary-us-east-1",
            "Failover": "PRIMARY",
            "TTL": 60,
            "ResourceRecords": [{"Value": "203.0.113.20"}],
            # HealthCheckId intentionally absent
        },
        # Secondary failover — correct (no health check required on secondary)
        {
            "Name": "shop.acme-corp.com.",
            "Type": "A",
            "SetIdentifier": "secondary-us-west-2",
            "Failover": "SECONDARY",
            "TTL": 60,
            "ResourceRecords": [{"Value": "203.0.113.21"}],
        },
        # ISSUE: Latency routing with only one region (LATENCY_SINGLE_REGION)
        {
            "Name": "checkout.shop.acme-corp.com.",
            "Type": "A",
            "SetIdentifier": "checkout-us-east-1",
            "Region": "us-east-1",
            "TTL": 60,
            "AliasTarget": {
                "DNSName": "checkout-alb-987654321.us-east-1.elb.amazonaws.com.",
                "EvaluateTargetHealth": True,
                "HostedZoneId": "Z35SXDOTRQ7X7K",
            },
        },
        # ISSUE: Weighted record with weight 0 (WEIGHTED_ZERO)
        {
            "Name": "beta.shop.acme-corp.com.",
            "Type": "A",
            "SetIdentifier": "beta-canary",
            "Weight": 0,
            "TTL": 30,
            "ResourceRecords": [{"Value": "203.0.113.30"}],
        },
        # Weighted primary — also has no health check (WEIGHTED_NO_HEALTH_CHECK)
        {
            "Name": "beta.shop.acme-corp.com.",
            "Type": "A",
            "SetIdentifier": "beta-stable",
            "Weight": 100,
            "TTL": 30,
            "ResourceRecords": [{"Value": "203.0.113.31"}],
        },
        # ISSUE: Very low TTL on a non-routing record (LOW_TTL)
        {
            "Name": "status.shop.acme-corp.com.",
            "Type": "CNAME",
            "TTL": 5,
            "ResourceRecords": [{"Value": "acme-status.statuspage.io."}],
        },
        # MX with no SPF or DMARC
        {
            "Name": "shop.acme-corp.com.",
            "Type": "MX",
            "TTL": 3600,
            "ResourceRecords": [{"Value": "10 inbound-smtp.us-east-1.amazonaws.com."}],
        },
    ],

    # ── internal.acme-corp.com ── private zone, lighter issues ──────────────
    "Z3DEMO000INTL3": [
        {
            "Name": "internal.acme-corp.com.",
            "Type": "SOA",
            "TTL": 900,
            "ResourceRecords": [
                {"Value": "ns-1234.awsdns-12.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"}
            ],
        },
        {
            "Name": "internal.acme-corp.com.",
            "Type": "NS",
            "TTL": 172800,
            "ResourceRecords": [
                {"Value": "ns-1234.awsdns-12.com."},
                {"Value": "ns-567.awsdns-34.net."},
            ],
        },
        # ISSUE: MultiValue Answer with no health check (MULTIVALUE_NO_HEALTH_CHECK)
        {
            "Name": "db.internal.acme-corp.com.",
            "Type": "A",
            "SetIdentifier": "db-replica-1",
            "MultiValueAnswer": True,
            "TTL": 60,
            "ResourceRecords": [{"Value": "10.0.1.100"}],
        },
        {
            "Name": "db.internal.acme-corp.com.",
            "Type": "A",
            "SetIdentifier": "db-replica-2",
            "MultiValueAnswer": True,
            "TTL": 60,
            "ResourceRecords": [{"Value": "10.0.1.101"}],
        },
        # ISSUE: Wildcard record (WILDCARD_RECORD)
        {
            "Name": "*.internal.acme-corp.com.",
            "Type": "A",
            "TTL": 300,
            "ResourceRecords": [{"Value": "10.0.0.1"}],
        },
        # Correct: plain internal record
        {
            "Name": "auth.internal.acme-corp.com.",
            "Type": "A",
            "TTL": 300,
            "ResourceRecords": [{"Value": "10.0.1.50"}],
        },
    ],
}
