#!/usr/bin/env python3
"""CDK app entry point — demonstrates all DNS constructs in a single stack."""
import aws_cdk as cdk

from dns_tool.stack import DnsToolStack

app = cdk.App()

DnsToolStack(
    app,
    "DnsToolStack",
    env=cdk.Environment(
        account=app.node.try_get_context("account") or "123456789012",
        region=app.node.try_get_context("region") or "us-east-1",
    ),
    description="Route 53 DNS Infrastructure-as-Code — portfolio demonstration",
)

app.synth()
