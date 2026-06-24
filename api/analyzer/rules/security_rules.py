"""
Rules: security-focused DNS checks.
"""
from __future__ import annotations

from typing import Any

from api.analyzer.models import Finding, Severity


def check_missing_caa(
    records: list[dict[str, Any]], zone_name: str
) -> Finding | None:
    """
    CAA records authorise specific certificate authorities to issue TLS
    certificates for the domain. Without CAA records, any CA can issue a
    certificate — a significant mis-issuance risk.
    """
    has_caa = any(r.get("Type") == "CAA" for r in records)
    if has_caa:
        return None

    return Finding(
        rule_id="MISSING_CAA",
        severity=Severity.WARNING,
        record_name=zone_name.rstrip("."),
        record_type="CAA",
        title="No CAA records — any CA can issue certificates",
        description=(
            f"The zone '{zone_name.rstrip('.')}' has no CAA (Certification "
            "Authority Authorization) records. Without CAA, any certificate "
            "authority in the world can issue a TLS certificate for your "
            "domain, creating risk of mis-issuance and impersonation attacks."
        ),
        recommendation=(
            "Add CAA records authorising only the CA(s) you use. Example: "
            '"0 issue \\"letsencrypt.org\\"" and '
            '"0 issuewild \\"letsencrypt.org\\"". '
            "Also add an iodef record to receive violation reports: "
            '"0 iodef \\"mailto:security@example.com\\"". '
            "CAA records are checked by all compliant CAs before issuance."
        ),
    )


def check_missing_spf(
    records: list[dict[str, Any]], zone_name: str
) -> Finding | None:
    """
    A zone with MX records but no SPF record allows anyone to send email
    that appears to come from your domain, enabling phishing attacks.
    """
    has_mx = any(r.get("Type") == "MX" for r in records)
    if not has_mx:
        return None

    txt_values = [
        v["Value"].lower()
        for r in records
        if r.get("Type") == "TXT"
        for v in r.get("ResourceRecords", [])
    ]
    has_spf = any("v=spf1" in v for v in txt_values)
    if has_spf:
        return None

    return Finding(
        rule_id="MISSING_SPF",
        severity=Severity.WARNING,
        record_name=zone_name.rstrip("."),
        record_type="TXT",
        title="MX records present but no SPF record",
        description=(
            f"'{zone_name.rstrip('.')}' has MX records indicating it sends "
            "email, but no SPF TXT record. Without SPF, receiving mail servers "
            "cannot verify that senders are authorised, making your domain "
            "trivially spoofable in phishing campaigns."
        ),
        recommendation=(
            'Add a TXT record at the zone apex: "v=spf1 include:<your-mail-provider> ~all". '
            "Replace <your-mail-provider> with your email service's SPF include "
            "(e.g., _spf.google.com for Google Workspace, spf.protection.outlook.com "
            "for Microsoft 365). Use ~all (soft fail) during testing, then harden "
            "to -all once you are confident all senders are listed."
        ),
    )


def check_missing_dmarc(
    records: list[dict[str, Any]], zone_name: str
) -> Finding | None:
    """
    DMARC builds on SPF and DKIM to give domain owners policy control over
    how receiving mail servers handle messages that fail authentication.
    Without DMARC, even a correctly configured SPF/DKIM setup has no
    enforcement policy.
    """
    has_mx = any(r.get("Type") == "MX" for r in records)
    if not has_mx:
        return None

    bare_zone = zone_name.rstrip(".")
    dmarc_name = f"_dmarc.{bare_zone}."
    has_dmarc = any(r.get("Name") == dmarc_name for r in records)
    if has_dmarc:
        return None

    return Finding(
        rule_id="MISSING_DMARC",
        severity=Severity.WARNING,
        record_name=f"_dmarc.{bare_zone}",
        record_type="TXT",
        title="No DMARC record — email spoofing enforcement is absent",
        description=(
            f"'{bare_zone}' sends email (has MX records) but has no DMARC "
            "record at _dmarc." + bare_zone + ". DMARC tells receiving "
            "servers what to do when SPF/DKIM checks fail — without it, "
            "spoofed emails may reach inboxes even if you have SPF and DKIM."
        ),
        recommendation=(
            f"Create a TXT record at '_dmarc.{bare_zone}' with value: "
            '"v=DMARC1; p=none; rua=mailto:dmarc-reports@' + bare_zone + '". '
            "Start with p=none to collect reports without affecting delivery. "
            "Analyse reports, then escalate to p=quarantine and finally "
            "p=reject once you are confident all legitimate senders pass."
        ),
    )


def check_wildcard_record(record: dict[str, Any]) -> Finding | None:
    """
    Wildcard DNS records match any subdomain not explicitly defined.
    This can expose infrastructure unexpectedly — any typo in a subdomain
    silently resolves rather than returning NXDOMAIN.
    """
    name = record.get("Name", "")
    if not name.startswith("*."):
        return None
    if record.get("Type") in ("NS", "MX"):
        return None

    return Finding(
        rule_id="WILDCARD_RECORD",
        severity=Severity.INFO,
        record_name=name,
        record_type=record["Type"],
        title="Wildcard record — review for unintended exposure",
        description=(
            f"The wildcard record '{name}' matches any subdomain not explicitly "
            "defined. This means typos, enumeration, and deprecated subdomains "
            "all resolve silently, potentially exposing endpoints that should "
            "return NXDOMAIN."
        ),
        recommendation=(
            "Confirm this wildcard is intentional. If possible, replace it with "
            "explicit records for each subdomain you serve. If you must keep "
            "the wildcard, ensure the target is actively monitored and that "
            "any TLS certificate covers the wildcard scope."
        ),
    )
