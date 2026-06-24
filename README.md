# Route 53 DNS Infrastructure-as-Code Tool

A production-grade AWS CDK (Python) application that manages Route 53 hosted zones
and DNS records programmatically — replicating and improving on the internal DNS
tooling that platform teams build in practice.

---

## Why CDK over YAML CloudFormation?

| Concern | YAML CloudFormation | AWS CDK (Python) |
|---------|---------------------|------------------|
| Type safety | None — typos fail at deploy | mypy / IDE catches errors locally |
| Reuse | Copy-paste or nested stacks | Classes, loops, conditionals |
| Testability | Manual drift-check | `aws_cdk.assertions` unit tests |
| Code review | Diff is YAML blobs | Diff is Python; intent is clear |
| Version control | Possible but noisy | First-class; every change is a PR |

---

## Project structure

```
R53/
├── app.py                          # CDK app entry point
├── cdk.json                        # CDK configuration
├── requirements.txt                # Runtime dependencies
├── requirements-dev.txt            # Test dependencies
├── dns_tool/
│   ├── hosted_zone_construct.py    # Public + private hosted zone wrapper
│   ├── record_constructs.py        # AliasRecord, CnameRecord, SimpleRecord
│   ├── failover_construct.py       # Multi-Region failover / routing policies
│   ├── iam_policies.py             # Least-privilege IAM policy generators
│   ├── propagation.py              # GetChange polling + batch-change helper
│   └── stack.py                    # Demo stack wiring everything together
└── tests/
    ├── test_hosted_zone.py
    ├── test_record_constructs.py
    ├── test_failover_construct.py
    ├── test_iam_policies.py
    └── test_propagation.py
```

---

## Design decisions and tradeoffs

### 1. Hosted zone construct

`HostedZoneConstruct` wraps both `PublicHostedZone` and `PrivateHostedZone` behind a
single interface. The caller passes `private_dns_vpc` to switch modes; everything else
is identical.

**Domain name normalisation** — callers can pass `example.com` or `example.com.`
interchangeably. The construct strips trailing dots before handing the name to CDK,
which then adds the canonical trailing dot in the CloudFormation resource. This matches
the Route 53 console behaviour and prevents duplicate zone creation from FQDN vs.
bare-name confusion.

**Private zone VPC requirement** — Route 53 private hosted zones require the associated
VPC to have `enableDnsHostnames` and `enableDnsSupport` set to `true`. CDK sets these
by default on new VPCs; imported VPCs must have them confirmed manually. The construct
documents this constraint rather than silently ignoring it.

### 2. Record constructs — alias-first design

Route 53 offers two ways to point a DNS name at an AWS resource:

- **CNAME** — a DNS indirection that requires the resolver to make an additional query.
  Adds latency, costs per-query, and is **forbidden at the zone apex** (RFC 1034 §3.6.2).
- **Alias record** — a Route 53 extension that responds with a direct A/AAAA answer.
  Zero additional queries, no per-query charge for lookups within AWS, and **works at
  the apex**.

`AliasRecord` is the primary construct for all AWS-resource targets. `CnameRecord`
exists for non-AWS targets but raises a `ValueError` at synthesis time if the caller
attempts to place a CNAME at the zone apex, making the error impossible to miss before
deployment.

**TTL on alias records** — when an alias points to an AWS resource (ALB, CloudFront,
etc.), Route 53 controls the TTL and the CDK resource deliberately omits the `TTL`
property. Setting it would cause a CloudFormation error. The unit tests assert its
absence.

### 3. Multi-Region failover construct

`FailoverConstruct` generates a pair (or set) of `CfnRecordSet` resources rather than
L2 constructs because the Route 53 L2 layer does not yet expose `SetIdentifier`,
`Failover`, `Region`, `Weight`, or `MultiValueAnswer`. Using L1 (`Cfn*`) here is
intentional and documented.

**Supported routing policies:**

| Policy | Use case | Health check required? |
|--------|----------|------------------------|
| `FAILOVER` | Active/passive across two regions | Primary only |
| `LATENCY` | Route to lowest-latency region | Recommended (enforced here) |
| `WEIGHTED` | Canary / blue-green traffic split | Recommended (enforced here) |
| `GEOLOCATION` | Serve different content by geography | Recommended (enforced here) |
| `MULTIVALUE` | Return up to 8 healthy IPs per query | **Required** (enforced here) |

**Health checks** use HTTPS by default (30 s interval, 3-failure threshold). The
health check FQDN is derived from the ALB DNS name token so CloudFormation resolves
it at deploy time — no hard-coded values.

**TTL** defaults to 60 seconds for all failover records. A lower TTL means DNS
clients stop caching a stale answer sooner after a failover event fires. The tradeoff
is higher query volume; 60 s is the practical lower bound for standard health checks
(which run every 30 s with a 3-failure threshold, so a failover takes up to 90 s to
trigger and clients must then flush the cached answer within TTL seconds).

### 4. Change safety and propagation verification

Route 53 change batches are **transactional** — either every record in the batch is
applied or none are. `batch_changes()` in `propagation.py` enforces this by requiring
callers to pass all related changes in a single call rather than issuing individual
`ChangeResourceRecordSets` requests.

`wait_for_insync()` polls `GetChange` until the status transitions from `PENDING` to
`INSYNC` (typically < 60 s globally). Automated pipelines should call this before
marking a deployment complete; skipping it risks a pipeline proceeding while DNS is
still inconsistent.

### 5. Least-privilege IAM

Route 53 condition keys narrow exactly which records a principal can modify:

```
route53:ChangeResourceRecordSetsNormalizedRecordNames
```

The "normalized" form lower-cases names and strips trailing dots, making wildcard
matching reliable across tools that format DNS names differently.

**Allow-suffix policy** (`allow_suffix_policy`)

```json
"Condition": {
  "ForAllValues:StringLike": {
    "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
      "example.com",
      "*.example.com"
    ],
    "route53:ChangeResourceRecordSetsActions": ["CREATE", "UPSERT", "DELETE"],
    "route53:ChangeResourceRecordSetsRecordTypes": ["A", "AAAA", ...]
  }
}
```

`ForAllValues:StringLike` — the condition must hold for **every** record name in the
batch. A batch that includes even one out-of-scope name is denied in its entirety.
This is the safe operator choice; `ForAnyValue` would allow an attacker to mix
permitted names with protected names in the same batch.

**Protected-suffix policy** (`deny_suffix_policy`)

```json
"Condition": {
  "ForAnyValue:StringLike": {
    "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
      "infra.example.com",
      "*.infra.example.com"
    ]
  }
}
```

The DENY uses `ForAnyValue:StringLike` — if **any** name in the batch matches the
protected suffix, the whole batch is denied. This mirrors the "no-touch infrastructure
DNS" guardrail that platform teams enforce to prevent application operators from
accidentally overwriting infrastructure records shared with other systems.

IAM DENY statements cannot be overridden by an Allow in the same or a downstream
policy, making this a hard guardrail rather than a soft convention.

---

## Security notes

- All policies are scoped to a specific hosted zone ARN — not `*`.
- Write actions require explicit condition key matches; condition-less wildcard writes
  are not generated by any factory method.
- Health checks use HTTPS and SNI by default; HTTP-only checks are not offered because
  they are trivially spoofable.
- The `ProtectedRecord` / `protected_suffix` concept makes it easy for platform teams
  to mark DNS records as infrastructure-owned so the tool refuses to modify them.
- No credentials are stored in code; the tool relies on the executing principal's
  ambient AWS credentials (instance role, ECS task role, GitHub OIDC, etc.).

---

## Getting started

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# 3. Run all unit tests
pytest tests/ -v

# 4. Synthesize CloudFormation templates (no AWS account needed)
cdk synth

# 5. Deploy to AWS (requires credentials + bootstrapped environment)
cdk bootstrap aws://ACCOUNT_ID/REGION
cdk deploy
```

---

## Running the tests

```
pytest tests/ -v --tb=short
```

The test suite uses `aws_cdk.assertions.Template` to assert against synthesized
CloudFormation JSON — no AWS account or network access required. Tests run in ~2 s.

### What is tested

| Test file | Key assertions |
|-----------|----------------|
| `test_hosted_zone.py` | Correct resource count; VPC attached for private zones; no VPC for public zones; trailing-dot normalisation |
| `test_record_constructs.py` | Alias records use `AliasTarget` not `ResourceRecords`; no TTL on alias records; CNAME at apex raises `ValueError` at synthesis |
| `test_failover_construct.py` | Failover records have health checks; MultiValue records ALL have health checks; alias used (not CNAME); correct set identifiers, weights, regions |
| `test_iam_policies.py` | Allow policy scoped to zone ARN; condition key `ChangeResourceRecordSetsNormalizedRecordNames` present; deny policy has explicit `Effect: Deny`; `ForAnyValue:StringLike` on protected suffix |
| `test_propagation.py` | `wait_for_insync` polls until INSYNC; `TimeoutError` on deadline exceeded; `batch_changes` sends transactional payload; empty list rejected |

---

## Architecture diagram

```
                   ┌──────────────────────────────────────────┐
                   │            Route 53 Hosted Zone           │
                   │              (example.com)                │
                   │                                           │
                   │  apex A (alias) ──────────────────────►  │
                   │  www   A (alias) ──────────────────────►  │──► ALB (us-east-1)
                   │  api   A (failover PRIMARY + HC) ──────►  │
                   │  api   A (failover SECONDARY) ─────────►  │──► ALB (us-west-2)
                   │  mail  A (plain IP)                       │
                   │  @     MX 10 mail.example.com.            │
                   │  staging NS → [delegated zone NS records] │
                   └──────────────────────────────────────────┘

  IAM Policies (least-privilege)
  ┌──────────────────────────────────────┐
  │ AllowExampleCom (ManagedPolicy)      │
  │  Allow: ChangeResourceRecordSets     │
  │  Condition: NormalizedRecordNames    │
  │    ForAllValues:StringLike           │
  │    ["example.com", "*.example.com"]  │
  └──────────────────────────────────────┘
  ┌──────────────────────────────────────┐
  │ DenyInfraSuffix (ManagedPolicy)      │
  │  Deny: ChangeResourceRecordSets      │
  │  Condition: NormalizedRecordNames    │
  │    ForAnyValue:StringLike            │
  │    ["infra.example.com",             │
  │     "*.infra.example.com"]           │
  └──────────────────────────────────────┘
```
