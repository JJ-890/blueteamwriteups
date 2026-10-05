# Phishing Email Analysis

## Project Overview

This project is a hands-on cybersecurity lab focused on analyzing suspicious email messages from an **SOC Analyst perspective**.

The objective is to build a workflow that can take an email sample, extract relevant header information, analyze sender identities and email authentication results, and present the findings in a format that can support an analyst during initial triage.

Phase 2 expanded the project beyond basic email parsing by introducing **sender identity normalization, SPF/DKIM/DMARC analysis, authentication alignment analysis, and structured SOC-oriented findings**.

The project is designed as an **analyst-assistance tool**, not as an automated replacement for human investigation.

---

## Project Objectives

The primary objectives of Phase 2 were to:

* Extract relevant sender information from an email.
* Normalize `From`, `Reply-To`, and `Return-Path` information.
* Analyze SPF authentication results.
* Analyze DKIM authentication results.
* Analyze DMARC authentication results.
* Determine authentication alignment with the visible `From` domain.
* Identify potentially suspicious relationships between sender identities.
* Generate structured findings for analyst review.
* Present the results in a concise SOC-oriented assessment.

---

# SOC Analyst Workflow

The project follows a simplified email-triage workflow:

```text
Email / EML File
       |
       v
Header Extraction
       |
       v
Sender Normalization
       |
       v
Authentication Analysis
       |
       +---- SPF
       |
       +---- DKIM
       |
       +---- DMARC
       |
       v
Domain Alignment Analysis
       |
       v
Finding Generation
       |
       v
SOC Analyst Review
```

The goal is to reproduce part of the initial analysis an L1 SOC analyst may perform when investigating a suspicious email.

---

# Phase 2 Features

## 1. Sender Identity Normalization

The analyzer extracts multiple sender-related fields instead of relying exclusively on the visible `From` address.

The analysis considers:

* `From`
* `Reply-To`
* `Return-Path`

Each address is normalized into useful information such as:

* Full email address
* Domain
* Relationship between sender domains

This is important because suspicious emails can present different identities across the visible sender, reply destination, and envelope sender.

For example:

```text
From:
    noreply@example.com

Reply-To:
    suspicious@example-token.com

Return-Path:
    bounce@example-mail.com
```

The analyzer allows these identities to be examined together rather than treating the visible `From` address as the only sender identity.

---

# 2. SPF Analysis

The analyzer parses SPF authentication results and records whether SPF authentication passed or failed.

It also evaluates whether the SPF-authenticated domain aligns with the visible `From` domain.

Example:

```text
SPF:
  Result: pass
  From Alignment: False
```

This distinction is important because an SPF `pass` does not automatically establish that the visible sender is legitimate.

The analyzer therefore separates:

**Authentication result**

from

**Authentication alignment**

This gives the analyst additional context during investigation.

---

# 3. DKIM Analysis

DKIM authentication is analyzed in a similar manner.

The analyzer records:

* DKIM authentication result
* DKIM signing domain
* Whether the DKIM signing domain aligns with the visible `From` domain

Example:

```text
DKIM:
  Result: pass
  From Alignment: False
```

Again, a DKIM `pass` is not automatically interpreted as proof that the email is legitimate.

The signing identity and its relationship to the visible sender provide additional investigative context.

---

# 4. DMARC Analysis

The analyzer also evaluates the DMARC authentication result and alignment information.

Example:

```text
DMARC:
  Result: none
  From Alignment: True
```

The project intentionally preserves the distinction between:

* Authentication status
* Domain alignment
* Overall analyst interpretation

This prevents individual authentication mechanisms from being treated as definitive on their own.

---

# Authentication Assessment

The individual authentication results are consolidated into an authentication assessment.

Example:

```text
========== AUTHENTICATION ASSESSMENT ==========

SPF:
  Result: pass
  From Alignment: False

DKIM:
  Result: pass
  From Alignment: False

DMARC:
  Result: none
  From Alignment: True
```

This gives an analyst a quick view of the authentication relationships associated with the message.

---

# SOC Analyst Assessment

The authentication and sender-identity information can then be translated into analyst-oriented findings.

Example:

```text
========== SOC ANALYST ASSESSMENT ==========

Assessment:
  Multiple authentication and sender-identity relationships
  were identified for analyst review.

Findings:
  - SPF authentication passed.
  - The SPF domain does not match the visible From domain.
  - DKIM authentication passed.
  - The DKIM signing domain does not match the visible From domain.
  - DMARC authentication returned none.
```

The wording is intentionally evidence-based.

The analyzer identifies observations and relationships that may warrant investigation rather than automatically declaring the message malicious.

This is an important distinction in an SOC environment: **automated tooling can surface evidence, while the analyst determines the significance of that evidence within the broader investigation.**

---

# Testing & Validation

Testing was performed against controlled email samples to validate the behavior of the sender and authentication analysis.

Testing included different combinations of:

* Visible `From` domain
* SPF authentication results
* SPF domain alignment
* DKIM authentication results
* DKIM signing-domain alignment
* DMARC results
* DMARC alignment
* `Reply-To`
* `Return-Path`

The purpose was to verify that the analyzer correctly represented authentication results and did not treat an authentication `pass` as synonymous with sender legitimacy.

The testing process also helped validate the analyzer's ability to distinguish between authentication **success** and authentication **alignment**.

---

# Security & Privacy Considerations

Email headers can contain sensitive information.

Before using real-world email samples in a public portfolio, sensitive information should be removed or redacted, including:

* Personal email addresses
* Internal domains
* IP addresses
* Message IDs
* Recipient information
* Organization-specific identifiers
* Other infrastructure information

The project documentation therefore focuses on the **analysis methodology and technical implementation** rather than exposing sensitive organizational information.

---

# Limitations

The current project is primarily focused on email-header and authentication analysis.

It does not currently attempt to:

* Automatically determine that an email is malicious
* Analyze the contents of attachments
* Execute or detonate attachments
* Determine whether a URL is malicious
* Perform comprehensive threat-intelligence enrichment
* Replace analyst investigation
* Establish sender legitimacy solely from authentication results

These limitations are intentional at this stage of the project.

---

# Future Improvements

Potential future phases could expand the analyzer with capabilities such as:

* URL extraction and analysis
* IOC extraction
* Threat-intelligence enrichment
* Attachment metadata analysis
* Domain reputation analysis
* Automated severity scoring
* SIEM-style event formatting
* Additional correlation logic
* Investigation timelines
* Structured alert generation

These improvements would allow the project to progress from an email-analysis tool toward a broader SOC-oriented phishing investigation workflow.

---

# Skills Demonstrated

This project demonstrates practical experience with:

* Email security analysis
* Email header analysis
* SPF
* DKIM
* DMARC
* Domain alignment
* Sender identity analysis
* Phishing investigation
* Python
* Security automation
* Structured security output
* SOC analyst triage methodology
* Testing and validation
* Technical documentation

---

# Project Status

**Phase 2: Complete**

Phase 2 established the project's core sender-identity normalization, authentication analysis, domain-alignment analysis, and SOC-oriented finding generation capabilities.

The project is now positioned for future phases focused on expanding phishing detection and investigation capabilities.
