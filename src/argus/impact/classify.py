"""
argus/impact/classify.py — data classification.

Pure-function classification of text blobs into regulator-meaningful
data classes. No LLM in the path — every rule is a compiled regex
with a citation (which regulation / standard it maps to) so the
downstream Impact Optimizer can produce a defensible regulatory
impact statement.

Classes emitted:
  SECRET        API keys, OAuth tokens, private keys, JWT bearers
  PII           emails, phone numbers, SSNs, dates of birth, street
                addresses, national identifiers
  PCI           payment-card numbers (Luhn-validated), CVV shapes,
                bank account / routing numbers
  PHI           protected health info signals (medical record
                numbers, NPI, ICD-10 codes)
  CREDENTIAL    database URIs, SSH keys, cloud metadata creds, env
                vars named as credentials (TOKEN=, API_KEY=, ...)
  BIOMETRIC     biometric identifier shapes (face embedding, etc.)
                — signal-only, not a value scan
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from enum import Enum


class DataClass(str, Enum):
    SECRET     = "SECRET"
    PII        = "PII"
    PCI        = "PCI"
    PHI        = "PHI"
    CREDENTIAL = "CREDENTIAL"
    BIOMETRIC  = "BIOMETRIC"


# ── Class → (pattern_name, regex, regulatory_tag) ──────────────────────────

_CLASSIFIERS: dict[DataClass, list[tuple[str, re.Pattern, list[str]]]] = {
    # Pattern names harmonised with argus.agents.agent_11_environment_pivot
    # _CRED_PATTERNS and argus.impact.optimizer.DEFAULT_TRUST_EDGES. The
    # trust-edge matcher keys off these names — don't rename without
    # updating the edge list.
    DataClass.SECRET: [
        ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),            ["SOC2"]),
        ("openai_api_key",    re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"), ["SOC2"]),
        ("aws_access_key",    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                    ["SOC2", "FedRAMP"]),
        ("aws_session_token", re.compile(r"\bASIA[0-9A-Z]{16}\b"),                    ["SOC2", "FedRAMP"]),
        ("google_api_key",    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),              ["SOC2"]),
        ("google_oauth_acc",  re.compile(r"\bya29\.[0-9A-Za-z\-_]{30,}"),             ["SOC2"]),
        ("github_pat",        re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),                ["SOC2"]),
        ("github_app_tok",    re.compile(r"\bghs_[A-Za-z0-9]{30,}\b"),                ["SOC2"]),
        ("slack_bot_token",   re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"),         ["SOC2"]),
        ("stripe_live_key",   re.compile(r"\bsk_live_[A-Za-z0-9_\-]{20,}"),            ["PCI-DSS", "SOC2"]),
        ("vercel_token",      re.compile(r"\bvc_[A-Za-z0-9_]{20,}"),                  ["SOC2"]),
        ("jwt_bearer",        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), ["SOC2"]),
        ("pem_private",       re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), ["SOC2", "FedRAMP"]),
    ],
    DataClass.PII: [
        ("email",          re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,}\b"), ["GDPR", "CCPA"]),
        ("us_phone",       re.compile(r"\b(?:\+?1[\s\-.])?(?:\(\d{3}\)|\d{3})[\s\-.]?\d{3}[\s\-.]?\d{4}\b"), ["GDPR", "CCPA"]),
        ("us_ssn",         re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                   ["GLBA", "GDPR", "CCPA", "HIPAA"]),
        ("date_of_birth",  re.compile(r"(?i)\b(?:dob|date of birth)[:=\s]+\d{1,4}[\-/]\d{1,2}[\-/]\d{1,4}\b"), ["GDPR", "CCPA", "HIPAA"]),
        ("street_address", re.compile(r"\b\d{1,6}\s+[A-Z][a-z]+\s+(?:St|Street|Ave|Avenue|Blvd|Boulevard|Rd|Road|Ln|Lane|Dr|Drive)\b"), ["GDPR", "CCPA"]),
        ("drivers_lic",    re.compile(r"(?i)\b(?:dl|driver'?s? license)[:#=\s]+[A-Z0-9]{6,20}\b"), ["GDPR", "CCPA"]),
        ("passport",       re.compile(r"(?i)\bpassport[:#=\s]+[A-Z0-9]{6,12}\b"),    ["GDPR", "CCPA"]),
    ],
    DataClass.PCI: [
        ("pan_visa",       re.compile(r"\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"), ["PCI-DSS"]),
        ("pan_mc",         re.compile(r"\b5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"), ["PCI-DSS"]),
        ("pan_amex",       re.compile(r"\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b"),    ["PCI-DSS"]),
        ("cvv",            re.compile(r"(?i)\bcvv[:\s=]+\d{3,4}\b"),                 ["PCI-DSS"]),
        ("iban",           re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),          ["PCI-DSS", "GDPR"]),
        ("routing",        re.compile(r"(?i)\b(?:routing|aba)[:\s#=]+\d{9}\b"),      ["GLBA"]),
    ],
    DataClass.PHI: [
        ("icd10",          re.compile(r"\b[A-TV-Z][0-9][A-Z0-9](?:\.[A-Z0-9]{1,4})?\b(?=.*(?:diagnos|patient|medical|treatment))"), ["HIPAA"]),
        ("npi",            re.compile(r"\b(?:NPI|npi)[:\s#=]+\d{10}\b"),             ["HIPAA"]),
        ("mrn",            re.compile(r"(?i)\b(?:mrn|medical record(?:\s+no)?)[:\s#=]+[A-Z0-9\-]{5,20}\b"), ["HIPAA"]),
    ],
    DataClass.CREDENTIAL: [
        ("db_uri",         re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis|mssql)://[^\s\"'<>]{5,}"), ["SOC2"]),
        ("env_tokenlike",  re.compile(r"(?i)\b(?:TOKEN|API_KEY|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY)\s*[:=]\s*[^\s\"']{8,}"), ["SOC2"]),
        ("basic_auth",     re.compile(r"(?i)\bauthorization:\s*basic\s+[A-Za-z0-9+/=]{16,}"), ["SOC2"]),
        ("bearer_auth",    re.compile(r"(?i)\bauthorization:\s*bearer\s+[A-Za-z0-9_\-\.]{20,}"), ["SOC2"]),
    ],
    DataClass.BIOMETRIC: [
        ("face_embedding_shape", re.compile(r"(?i)\bface_embedding\s*[:=]\s*\[[\d\.,\s\-]{50,}\]"), ["GDPR", "BIPA"]),
        ("fingerprint_hash",     re.compile(r"(?i)\bfingerprint_hash\s*[:=]\s*[a-f0-9]{32,}"), ["GDPR", "BIPA"]),
    ],
}


def _luhn_valid(digits: str) -> bool:
    """Luhn check used to keep PAN matches from firing on random digit strings."""
    stripped = re.sub(r"\D", "", digits)
    if not (13 <= len(stripped) <= 19):
        return False
    total = 0
    for i, ch in enumerate(reversed(stripped)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ── Output shapes ───────────────────────────────────────────────────────────

@dataclass
class DataClassification:
    """Result of classifying one text blob."""
    classes:           dict[str, list[str]]            # class -> pattern hits
    regulatory_tags:   list[str]                       # union of tags across hits
    total_hits:        int
    source:            str                             # free-form source label

    def is_sensitive(self) -> bool:
        return self.total_hits > 0

    def to_dict(self) -> dict:
        return asdict(self)


# ── Classification entry points ─────────────────────────────────────────────

def classify_text(text: str, *, source: str = "") -> DataClassification:
    """
    Classify a single text blob. Returns a DataClassification with
    per-class pattern-name hits and a union of regulatory tags.
    """
    classes: dict[str, list[str]] = {}
    regs: set[str] = set()
    total = 0

    if not text:
        return DataClassification(classes={}, regulatory_tags=[],
                                  total_hits=0, source=source)

    for cls, entries in _CLASSIFIERS.items():
        for name, pat, tags in entries:
            m = pat.search(text)
            if not m:
                continue
            # PCI PAN matches must Luhn-validate to avoid fake-digit noise.
            if cls == DataClass.PCI and name.startswith("pan_"):
                if not _luhn_valid(m.group(0)):
                    continue
            classes.setdefault(cls.value, []).append(name)
            regs.update(tags)
            total += 1

    return DataClassification(
        classes={k: sorted(set(v)) for k, v in classes.items()},
        regulatory_tags=sorted(regs),
        total_hits=total,
        source=source,
    )


def classify_evidence(evidence) -> DataClassification:
    """
    Classify a DeterministicEvidence object's reachable text: every
    inbound pcap payload body + container_logs + oob_callback body.
    This is the "what did the adversary actually see?" classification
    the Impact Optimizer then maps into regulatory exposure.
    """
    from argus.evidence import DeterministicEvidence
    if not isinstance(evidence, DeterministicEvidence):
        raise TypeError("classify_evidence: expected DeterministicEvidence")

    blobs: list[str] = []
    for rec in evidence.pcap:
        if rec.direction == "in":
            blobs.append(str(rec.payload))
    if evidence.container_logs:
        blobs.append(evidence.container_logs)
    for cb in evidence.oob_callbacks:
        if cb.body:
            blobs.append(cb.body)

    text = "\n".join(blobs)
    return classify_text(text, source=f"evidence:{evidence.evidence_id}")
