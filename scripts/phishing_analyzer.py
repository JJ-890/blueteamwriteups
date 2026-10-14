

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
import re
import sys


# ============================================================
# REGULAR EXPRESSIONS
# ============================================================

AUTH_RESULTS_HEADER = "Authentication-Results"

SPF_PATTERN = re.compile(
    r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)
SPF_MAILFROM_PATTERN = re.compile(
    r"\bsmtp\.mailfrom=([^\s;]+)", re.IGNORECASE
)

DKIM_PATTERN = re.compile(
    r"\bdkim=(pass|fail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)
DKIM_DOMAIN_PATTERN = re.compile(
    r"\bheader\.d=([^\s;]+)", re.IGNORECASE
)
DKIM_IDENTITY_PATTERN = re.compile(
    r"\bheader\.i=([^\s;]+)", re.IGNORECASE
)

DMARC_PATTERN = re.compile(
    r"\bdmarc=(pass|fail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)
DMARC_DOMAIN_PATTERN = re.compile(
    r"\bheader\.from=([^\s;]+)", re.IGNORECASE
)
DMARC_ACTION_PATTERN = re.compile(
    r"\baction=([^\s;]+)", re.IGNORECASE
)

COMPAUTH_PATTERN = re.compile(
    r"\bcompauth=(pass|fail|none)\b", re.IGNORECASE
)
COMPAUTH_REASON_PATTERN = re.compile(
    r"\breason=([^\s;]+)", re.IGNORECASE
)


# ============================================================
# EMAIL PARSING AND SENDER EXTRACTION
# ============================================================

def parse_email(file_path):
    """Parse an .eml file and return its EmailMessage object."""
    with file_path.open("rb") as email_file:
        return BytesParser(policy=policy.default).parse(email_file)


def extract_address_info(header_value):
    """Return the parsed email address and its domain, when available."""
    if not header_value:
        return {"address": None, "domain": None}

    _, address = parseaddr(str(header_value))

    if not address:
        return {"address": None, "domain": None}

    address = address.strip()

    if "@" not in address:
        return {"address": address, "domain": None}

    domain = address.rsplit("@", 1)[1].strip().rstrip(">").lower() or None

    return {
        "address": address,
        "domain": domain,
    }


def extract_sender_information(email_message):
    """Extract From, Reply-To, and Return-Path identities."""
    return {
        "from": extract_address_info(email_message.get("From")),
        "reply_to": extract_address_info(email_message.get("Reply-To")),
        "return_path": extract_address_info(
            email_message.get("Return-Path")
        ),
    }


# ============================================================
# AUTHENTICATION EXTRACTION
# ============================================================

def get_authentication_results(email_message):
    """Return the Authentication-Results header as text, if present."""
    value = email_message.get(AUTH_RESULTS_HEADER)
    return str(value) if value else ""


def extract_authentication_value(header_value, pattern):
    """Extract a matching authentication value, or return None."""
    match = pattern.search(header_value)
    return match.group(1).lower() if match else None


def extract_spf_information(email_message):
    """Extract SPF result and smtp.mailfrom identity."""
    auth_results = get_authentication_results(email_message)

    mail_from = extract_authentication_value(
        auth_results, SPF_MAILFROM_PATTERN
    )

    if mail_from and "@" in mail_from:
        domain = mail_from.rsplit("@", 1)[1].lower()
    else:
        domain = mail_from.lower() if mail_from else None

    return {
        "result": extract_authentication_value(
            auth_results, SPF_PATTERN
        ),
        "mail_from": mail_from,
        "domain": domain,
    }


def extract_dkim_information(email_message):
    """Extract DKIM result, signing domain, and identity."""
    auth_results = get_authentication_results(email_message)

    return {
        "result": extract_authentication_value(
            auth_results, DKIM_PATTERN
        ),
        "domain": extract_authentication_value(
            auth_results, DKIM_DOMAIN_PATTERN
        ),
        "identity": extract_authentication_value(
            auth_results, DKIM_IDENTITY_PATTERN
        ),
    }


def extract_dmarc_information(email_message):
    """Extract DMARC result, header.from domain, and action."""
    auth_results = get_authentication_results(email_message)

    return {
        "result": extract_authentication_value(
            auth_results, DMARC_PATTERN
        ),
        "domain": extract_authentication_value(
            auth_results, DMARC_DOMAIN_PATTERN
        ),
        "action": extract_authentication_value(
            auth_results, DMARC_ACTION_PATTERN
        ),
    }


def extract_compauth_information(email_message):
    """Extract composite authentication result and reason."""
    auth_results = get_authentication_results(email_message)

    return {
        "result": extract_authentication_value(
            auth_results, COMPAUTH_PATTERN
        ),
        "reason": extract_authentication_value(
            auth_results, COMPAUTH_REASON_PATTERN
        ),
    }


# ============================================================
# DOMAIN CORRELATION
# ============================================================

def compare_domains(first_domain, second_domain):
    """Compare domains; return None when either is unavailable."""
    if not first_domain or not second_domain:
        return None

    return (
        first_domain.lower().rstrip(".")
        == second_domain.lower().rstrip(".")
    )


def correlate_sender_domains(
    sender_information,
    spf_information,
    dkim_information,
    dmarc_information,
):
    """Calculate sender and authentication domain relationships."""
    from_domain = sender_information["from"]["domain"]
    reply_to_domain = sender_information["reply_to"]["domain"]
    return_path_domain = sender_information["return_path"]["domain"]

    return {
        "spf_from": compare_domains(
            spf_information["domain"], from_domain
        ),
        "dkim_from": compare_domains(
            dkim_information["domain"], from_domain
        ),
        "dmarc_from": compare_domains(
            dmarc_information["domain"], from_domain
        ),
        "reply_to_from": compare_domains(
            reply_to_domain, from_domain
        ),
        "return_path_from": compare_domains(
            return_path_domain, from_domain
        ),
        "reply_to_return_path": compare_domains(
            reply_to_domain, return_path_domain
        ),
        "spf_return_path": compare_domains(
            spf_information["domain"], return_path_domain
        ),
        "spf_reply_to": compare_domains(
            spf_information["domain"], reply_to_domain
        ),
    }


# ============================================================
# AUTHENTICATION ALIGNMENT AND ANALYST ASSESSMENT
# ============================================================

def assess_dmarc_alignment(
    spf_information,
    dkim_information,
    relationships,
):
    """Assess passing SPF and DKIM results against the From domain."""
    return {
        "spf_aligned": (
            spf_information["result"] == "pass"
            and relationships["spf_from"] is True
        ),
        "dkim_aligned": (
            dkim_information["result"] == "pass"
            and relationships["dkim_from"] is True
        ),
    }


def build_analyst_assessment(
    spf_information,
    dkim_information,
    dmarc_information,
    relationships,
):
    """Build findings from authentication and sender-domain evidence."""
    findings = []

    # Authentication results
    for protocol, information in (
        ("SPF", spf_information),
        ("DKIM", dkim_information),
        ("DMARC", dmarc_information),
    ):
        result = information["result"]

        if result == "pass":
            findings.append(f"{protocol} authentication passed.")
        elif result is not None:
            findings.append(
                f"{protocol} authentication returned {result}."
            )

    # Domain relationship findings
    relationship_findings = (
        (
            "spf_from",
            "The SPF domain does not match the visible From domain.",
        ),
        (
            "dkim_from",
            "The DKIM signing domain does not match the visible From domain.",
        ),
        (
            "reply_to_from",
            "The Reply-To domain differs from the visible From domain.",
        ),
        (
            "return_path_from",
            "The Return-Path domain differs from the visible From domain.",
        ),
        (
            "reply_to_return_path",
            "The Reply-To domain differs from the Return-Path domain.",
        ),
        (
            "spf_reply_to",
            "The SPF domain differs from the Reply-To domain.",
        ),
    )

    for relationship, finding in relationship_findings:
        if relationships[relationship] is False:
            findings.append(finding)

    if relationships["spf_return_path"] is True:
        findings.append(
            "The SPF domain corresponds to the Return-Path domain."
        )

    if findings:
        assessment = (
            "Authentication and sender-identity observations were "
            "identified for analyst review. These observations are not, "
            "by themselves, a determination that the email is malicious."
        )
    else:
        assessment = (
            "No notable authentication or sender-identity observations "
            "were identified from the available evidence."
        )

    return {
        "assessment": assessment,
        "findings": findings,
    }


# ============================================================
# ANALYSIS ORCHESTRATION
# ============================================================

def build_analysis(email_message):
    """Run extraction and analysis, returning structured results."""
    sender = extract_sender_information(email_message)
    spf = extract_spf_information(email_message)
    dkim = extract_dkim_information(email_message)
    dmarc = extract_dmarc_information(email_message)
    compauth = extract_compauth_information(email_message)

    relationships = correlate_sender_domains(
        sender, spf, dkim, dmarc
    )

    alignment = assess_dmarc_alignment(
        spf, dkim, relationships
    )

    analyst_assessment = build_analyst_assessment(
        spf, dkim, dmarc, relationships
    )

    return {
        "sender": sender,
        "authentication": {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "compauth": compauth,
        },
        "relationships": relationships,
        "alignment": alignment,
        "analyst_assessment": analyst_assessment,
    }


# ============================================================
# REPORTING
# ============================================================

def print_section(title):
    """Print a consistent report section heading."""
    print(f"\n========== {title} ==========")


def print_report(report):
    """Print analysis results in a consistent report format."""
    sender = report["sender"]
    auth = report["authentication"]
    relationships = report["relationships"]
    alignment = report["alignment"]

    print_section("PHISHING EMAIL ANALYZER — PHASE 2")

    print_section("SENDER IDENTITIES")

    for label, key in (
        ("From", "from"),
        ("Reply-To", "reply_to"),
        ("Return-Path", "return_path"),
    ):
        print(f"{label}:")
        print(f"  Address: {sender[key]['address']}")
        print(f"  Domain:  {sender[key]['domain']}")

    print_section("AUTHENTICATION RESULTS")

    spf = auth["spf"]
    dkim = auth["dkim"]
    dmarc = auth["dmarc"]
    compauth = auth["compauth"]

    print("SPF:")
    print(f"  Result:    {spf['result']}")
    print(f"  Mail From: {spf['mail_from']}")
    print(f"  Domain:    {spf['domain']}")

    print("DKIM:")
    print(f"  Result:   {dkim['result']}")
    print(f"  Domain:   {dkim['domain']}")
    print(f"  Identity: {dkim['identity']}")

    print("DMARC:")
    print(f"  Result: {dmarc['result']}")
    print(f"  Domain: {dmarc['domain']}")
    print(f"  Action: {dmarc['action']}")

    print("Composite Authentication:")
    print(f"  Result: {compauth['result']}")
    print(f"  Reason: {compauth['reason']}")

    print_section("DOMAIN RELATIONSHIPS")

    relationship_labels = (
        ("spf_from", "SPF domain ↔ From domain"),
        ("dkim_from", "DKIM domain ↔ From domain"),
        ("dmarc_from", "DMARC domain ↔ From domain"),
        ("reply_to_from", "Reply-To domain ↔ From domain"),
        ("return_path_from", "Return-Path domain ↔ From domain"),
        (
            "reply_to_return_path",
            "Reply-To domain ↔ Return-Path domain",
        ),
        ("spf_return_path", "SPF domain ↔ Return-Path domain"),
        ("spf_reply_to", "SPF domain ↔ Reply-To domain"),
    )

    for key, label in relationship_labels:
        print(f"{label}: {relationships[key]}")

    print_section("DMARC ALIGNMENT CHECK")
    print(f"Passing SPF aligned with From: {alignment['spf_aligned']}")
    print(f"Passing DKIM aligned with From: {alignment['dkim_aligned']}")

    print_section("SOC ANALYST ASSESSMENT")

    assessment = report["analyst_assessment"]
    print(f"Assessment: {assessment['assessment']}")
    print("Findings:")

    if assessment["findings"]:
        for finding in assessment["findings"]:
            print(f"  - {finding}")
    else:
        print("  - No findings generated from the available evidence.")


# ============================================================
# COMMAND-LINE ENTRY POINT
# ============================================================

def main():
    """Run the phishing email analyzer."""
    if len(sys.argv) != 2:
        print("Usage: python phishing_analyzer.py <email.eml>")
        return

    file_path = Path(sys.argv[1])

    if not file_path.is_file() or file_path.suffix.lower() != ".eml":
        print("Error: Provide a valid .eml file.")
        return

    try:
        email_message = parse_email(file_path)
    except (OSError, ValueError) as error:
        print(f"Error reading email: {error}")
        return

    report = build_analysis(email_message)
    print_report(report)


if __name__ == "__main__":
    main()