# Route 53 DNS Optimizer

A full-stack AWS portfolio project that combines Infrastructure-as-Code tooling with a live web application for analyzing and optimizing Route 53 DNS configurations.

The project has two layers:

1. **CDK Constructs** — a reusable Python library for managing Route 53 hosted zones, records, failover routing, and IAM policies as code
2. **Web Application** — a FastAPI + vanilla JS dashboard that connects to your AWS account, scans every hosted zone, and surfaces specific optimization findings with explanations and fix recommendations

---

## Live Demo

> Try it without an AWS account using the built-in demo mode, which loads a realistic sample configuration pre-populated with common DNS issues.

---

## What the Analyzer Checks

The analysis engine runs 16 rules across five categories every time you click **Analyze All Zones**.

### Critical
| Rule | What it catches |
|------|----------------|
| `APEX_CNAME` | CNAME at the zone apex — violates RFC 1034 §3.6.2, breaks email delivery |
| `FAILOVER_NO_HEALTH_CHECK` | Failover PRIMARY record with no health check — Route 53 never actually fails over |
| `MULTIVALUE_NO_HEALTH_CHECK` | MultiValue Answer record with no health check — unhealthy endpoints still returned |

### Warning
| Rule | What it catches |
|------|----------------|
| `CNAME_TO_AWS_ENDPOINT` | CNAME pointing to an AWS resource (ALB, CloudFront, API Gateway, S3) — should be an alias record |
| `LATENCY_NO_HEALTH_CHECK` | Latency-based routing with no health check — traffic routed to unhealthy regions |
| `WEIGHTED_NO_HEALTH_CHECK` | Weighted routing with no health check — traffic proportionally sent to down endpoints |
| `DUPLICATE_IP` | Same IP address listed multiple times in a record set — no redundancy benefit |
| `MISSING_CAA` | No CAA records — any certificate authority can issue TLS certs for the domain |
| `MISSING_SPF` | MX records present but no SPF TXT record — domain is trivially spoofable in email |
| `MISSING_DMARC` | MX records present but no `_dmarc` record — no enforcement policy for failed auth |

### Info
| Rule | What it catches |
|------|----------------|
| `HIGH_TTL` | TTL > 86400s — DNS changes take over a day to propagate to all clients |
| `LOW_TTL` | TTL < 60s on non-routing records — inflates Route 53 query costs unnecessarily |
| `SINGLE_POINT_OF_FAILURE` | Single A record at apex or `www` with no routing policy — one endpoint, no recovery |
| `LATENCY_SINGLE_REGION` | Latency routing configured but only one region exists — no routing benefit |
| `WEIGHTED_ZERO` | Weighted record with weight 0 — receives no traffic, dead configuration |
| `WILDCARD_RECORD` | Wildcard `*` record — any undefined subdomain resolves silently, review for exposure |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Web Application                        │
│                                                             │
│   Browser (HTML/CSS/JS)  ◄──────►  FastAPI (Python)        │
│   - Welcome screen                  - /api/auth            │
│   - Credential form                 - /api/analysis        │
│   - Zone sidebar                    - /api/auth/status     │
│   - Findings dashboard              - /api/zones/{id}/...  │
└─────────────────────────────┬───────────────────────────────┘
                              │
                    AWS STS + Route 53
                    (or demo fixture data)
```

```
┌─────────────────────────────────────────────────────────────┐
│                     CDK Construct Library                   │
│                                                             │
│   dns_tool/                                                 │
│   ├── HostedZoneConstruct   public + private zones          │
│   ├── AliasRecord           alias-first, apex-safe          │
│   ├── CnameRecord           zone-apex guard enforced        │
│   ├── SimpleRecord          MX, TXT, NS, SRV, plain IPs     │
│   ├── FailoverConstruct     5 routing policies + HC         │
│   ├── DnsIamPolicies        least-privilege IAM generators  │
│   └── propagation.py        GetChange polling helper        │
└─────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
R53/
├── api/                          # Web application
│   ├── main.py                   # FastAPI app, routes, session management
│   ├── r53_client.py             # boto3 wrapper (live + demo mode)
│   ├── demo_data.py              # Realistic mock Route 53 data
│   ├── analyzer/
│   │   ├── engine.py             # Orchestrates all rules per zone
│   │   ├── models.py             # Pydantic models: Finding, ZoneAnalysis
│   │   └── rules/
│   │       ├── alias_rules.py    # CNAME vs alias checks
│   │       ├── health_check_rules.py
│   │       ├── ttl_rules.py
│   │       ├── security_rules.py # CAA, SPF, DMARC, wildcard
│   │       └── routing_rules.py  # Failover, latency, weighted
│   └── static/                   # Frontend (HTML, CSS, JS)
│       ├── index.html
│       ├── style.css
│       └── app.js
├── dns_tool/                     # CDK construct library
│   ├── hosted_zone_construct.py
│   ├── record_constructs.py
│   ├── failover_construct.py
│   ├── iam_policies.py
│   ├── propagation.py
│   └── stack.py                  # Demo CDK stack
├── tests/                        # 90 unit tests
│   ├── test_auth.py
│   ├── test_hosted_zone.py
│   ├── test_record_constructs.py
│   ├── test_failover_construct.py
│   ├── test_iam_policies.py
│   └── test_propagation.py
├── app.py                        # CDK app entry point
├── Dockerfile
├── Procfile
└── requirements.txt
```

---

## Running Locally

### Prerequisites
- Python 3.11+
- AWS credentials configured (optional — demo mode works without them)

### Setup

```bash
# Clone and set up a virtual environment
git clone https://github.com/jadenkwak/r53-optimizer.git
cd r53-optimizer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Start the web application

```bash
python run_api.py
```

Open [http://localhost:8000](http://localhost:8000).

**Demo Mode** — click *Try Demo* on the welcome screen. No AWS account needed. Loads a pre-built configuration for a fictional company (`acme-corp.com`) with intentional issues across all severity levels.

**Live Mode** — click *Connect to AWS* and enter your IAM credentials. They are validated immediately via `sts:GetCallerIdentity` and stored only in server memory for the current session. Minimum required permissions:
```
route53:ListHostedZones
route53:ListResourceRecordSets
```

### Run the CDK constructs

```bash
# Synthesize CloudFormation templates (no AWS account needed)
cdk synth

# Deploy (requires credentials and a bootstrapped environment)
cdk bootstrap aws://ACCOUNT_ID/REGION
cdk deploy
```

---

## Running Tests

```bash
pytest tests/ -v
```

90 tests, no AWS account required. Tests run in ~2 seconds.

| Test file | What it covers |
|-----------|----------------|
| `test_auth.py` | Full auth flow: valid credentials return token, bad key ID / wrong secret return specific 401 errors, logout clears session, session token used for live analysis |
| `test_hosted_zone.py` | Public/private zone synthesis, VPC association, trailing-dot normalisation |
| `test_record_constructs.py` | Alias records use `AliasTarget` not `ResourceRecords`; no TTL on alias records; CNAME at apex raises `ValueError` at synthesis time |
| `test_failover_construct.py` | Failover records have health checks; MultiValue records ALL have health checks; correct set identifiers, regions, weights |
| `test_iam_policies.py` | Allow policy scoped to zone ARN; `ForAllValues:StringLike` on `ChangeResourceRecordSetsNormalizedRecordNames`; deny policy has explicit `Effect: Deny` |
| `test_propagation.py` | `wait_for_insync` polls until INSYNC; `TimeoutError` on deadline; `batch_changes` sends transactional payload |

---

## CDK Design Decisions

### Alias records over CNAMEs

Route 53 alias records resolve directly inside AWS with no extra DNS hop, incur no per-query charge for AWS-resource targets, and work at the zone apex where CNAMEs are forbidden by RFC 1034 §3.6.2. The `AliasRecord` construct enforces this — `CnameRecord` raises a `ValueError` at synthesis time if you attempt to place a CNAME at the apex.

### Failover uses L1 constructs (`CfnRecordSet`)

The CDK L2 layer for Route 53 does not expose `SetIdentifier`, `Failover`, `Region`, `Weight`, or `MultiValueAnswer`. The `FailoverConstruct` drops down to L1 (`CfnRecordSet`) intentionally to access these properties, while still encapsulating all the health check wiring and routing logic behind a clean Python interface.

### Transactional change batches

Route 53 change batches are all-or-none. The `batch_changes()` helper in `propagation.py` enforces this by requiring all related record changes to be submitted in a single `ChangeResourceRecordSets` call. `wait_for_insync()` then polls `GetChange` until the status transitions from `PENDING` to `INSYNC` before allowing an automated pipeline to continue.

### Least-privilege IAM with condition keys

IAM policies use `route53:ChangeResourceRecordSetsNormalizedRecordNames` to scope a principal to specific DNS suffixes:

- **Allow-suffix policy** uses `ForAllValues:StringLike` — the condition must be true for *every* record name in the batch. A single out-of-scope name rejects the entire batch.
- **Deny-suffix policy** uses `ForAnyValue:StringLike` — if *any* name matches the protected suffix, the entire batch is denied. This is a hard guardrail that no downstream Allow can override.

---

## Deployment

The app is containerized and deployable to any platform that supports Docker.

### Railway (recommended)

1. Push this repo to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Railway detects the `Dockerfile` automatically
4. Settings → Networking → Generate Domain for a permanent `https://` URL

### Render

Connect the GitHub repo on [render.com](https://render.com), set Runtime to Docker, and deploy. The `Procfile` is used as a fallback.

### AWS App Runner

For an AWS-native deployment, point App Runner at this repository. It builds the Dockerfile and provides HTTPS + auto-scaling with no server management.

---

## Security

- Credentials entered in the web UI are validated via `sts:GetCallerIdentity` before being accepted
- Credentials are stored in server memory only for the current session — never written to disk or logged
- Sessions are identified by a random 32-byte token; closing the browser tab clears it
- IAM policies generated by the CDK constructs are scoped to specific zone ARNs, not `*`
- Health checks use HTTPS with SNI enabled by default
