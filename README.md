# Blue Team Writeups

![Blue Team](https://img.shields.io/badge/Focus-Blue%20Team-blue)
![SOC](https://img.shields.io/badge/Focus-SOC%20Analysis-darkblue)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

A collection of hands-on **blue team, SOC analysis, detection, and incident investigation writeups** documenting my progression in cybersecurity.

This repository focuses on practical security investigations rather than simply completing lab objectives. Each writeup is intended to document the **analyst thought process**, including initial triage, evidence collection, log analysis, correlation, findings, limitations, and final assessment.

---

## 🎯 Purpose

The goal of this repository is to build and demonstrate practical blue team skills through hands-on labs and security investigations.

Areas of focus include:

* 🔎 Security alert triage
* 📊 SIEM investigation
* 📝 Log analysis
* 🚨 Incident detection and response
* 🧠 Threat investigation
* 🔗 Event correlation
* 🛡️ Detection engineering
* 🗺️ MITRE ATT&CK mapping
* ⚙️ Security automation
* 📋 Incident documentation
* 🎯 False-positive analysis

The emphasis is on understanding **why an alert fired, what the available evidence proves, what it does not prove, and what an analyst should investigate next.**

---

## 📂 Repository Structure

```text
blueteamwriteups/
│
├── screenshots/
│   └── Investigation screenshots and supporting evidence
│
├── 001_thm_phishing_sim.md
│   └── Phishing Alert Investigation
│
└── README.md
```

As additional investigations are completed, writeups will be numbered chronologically.

---

## 🔬 Current Investigations

# Phishing Email Analyzer

A Python command-line tool that parses `.eml` files and reports **sender-identity and email-authentication evidence** to support SOC Analyst L1 triage.

It does not label an email "phishing" or "safe." It extracts the identities an email presents (`From`, `Reply-To`, `Return-Path`), reads the SPF, DKIM, DMARC, and compauth results from the `Authentication-Results` header, compares the domains against each other, and prints evidence-based findings for an analyst to review.

> **Core idea: authentication does not equal legitimacy.**
> SPF or DKIM can pass for a domain that has no relationship to the visible `From` address. The tool reports the *result* and the *alignment* separately so that gap is visible.

**Status:** Phase 2 complete. Phase 1 covered basic `.eml` parsing; Phase 2 added sender normalization, authentication parsing, domain correlation, and findings.

---

## Usage

Requires Python 3 and the standard library only (`email`, `re`, `pathlib`, `sys`).

```bash
python phishing_analyzer.py path/to/sample.eml
```

The script exits with an error if no file is given, the file does not exist, or the extension is not `.eml`. Output is printed to the console.

---

## How It Works

```text
.eml file
   |
   v
parse_email()                        (email.parser, policy.default)
   |
   +--> extract_sender_information()      From / Reply-To / Return-Path
   |
   +--> extract_spf_information()         Authentication-Results
   +--> extract_dkim_information()        Authentication-Results
   +--> extract_dmarc_information()       Authentication-Results
   +--> extract_compauth_information()    Authentication-Results
   |
   v
correlate_*()                        domain comparisons (True / False / None)
   |
   v
assess_dmarc_alignment()             SPF/DKIM pass AND domain match
   |
   v
build_*_assessment()                 consolidated views + findings
   |
   v
console report
```

### Sender normalization

`extract_address_info()` uses `parseaddr` to split each header into an **address** and a lowercase **domain**. Missing or malformed values return `None` instead of raising an error.

| Header | Why it matters |
|---|---|
| `From` | The visible sender the recipient sees |
| `Reply-To` | Where replies actually go |
| `Return-Path` | The envelope sender; the identity SPF is evaluated against |

### Authentication parsing

Values are extracted with regular expressions from the `Authentication-Results` header:

| Mechanism | Fields captured |
|---|---|
| SPF | result, `smtp.mailfrom`, mail-from domain |
| DKIM | result, `header.d` (signing domain), `header.i` (identity) |
| DMARC | result, `header.from` domain, `action` |
| compauth | result, `reason` (Microsoft composite authentication) |

### Domain correlation

Each correlation compares two domains and returns `True`, `False`, or `None` (when either value is missing). `None` is intentionally distinct from `False`: missing data is not treated as a mismatch.

* From ↔ Reply-To
* From ↔ Return-Path
* Reply-To ↔ Return-Path
* SPF ↔ From
* SPF ↔ Return-Path
* SPF ↔ Reply-To
* DKIM ↔ From
* DMARC `header.from` ↔ From

### Result vs. alignment

`assess_dmarc_alignment()` reports whether SPF and DKIM each provide alignment with the `From` domain. A mechanism counts as aligned only when the result is `pass` **and** its domain matches `From`. This is why a message can show `SPF: pass` and still report `SPF Aligned: False`.

### Findings

`build_analyst_assessment()` turns the correlations into plain-language observations, such as:

* SPF / DKIM / DMARC result statements (`pass` or the returned value)
* SPF or DKIM domain does not match the visible `From` domain
* `Reply-To` or `Return-Path` differs from `From`
* `Reply-To` differs from `Return-Path`
* SPF domain corresponds to / differs from `Return-Path` and `Reply-To`

Findings are worded as observations, not verdicts. The analyzer flags relationships worth investigating; the analyst decides what they mean. Note that compauth and the DMARC alignment check are printed in the report but are not currently turned into findings.

---

## Example Output

Illustrative, abridged output for a sanitized sample using reserved example domains. Section order matches the script.

```text
============COMPAUTH DATA========
Result: None
Reason: None

========== DMARC DATA ==========
Result: none
Domain: example.com
Action: None

========== DKIM DATA ==========
Result: pass
Domain: example-bulk.net
Identity: None

========== NORMALIZED SENDER DATA ==========
From:
  Address: noreply@example.com
  Domain:  example.com
Reply-To:
  Address: help@example-support.net
  Domain:  example-support.net
Return-Path:
  Address: bounce@mailer.example-bulk.net
  Domain:  mailer.example-bulk.net

========== SPF DATA ==========
Result: pass
Mail From: bounce@mailer.example-bulk.net
Domain: mailer.example-bulk.net

========== SPF / FROM CORRELATION ==========
From Domain: example.com
SPF Domain: mailer.example-bulk.net
Domain Match: False

[... DKIM, DMARC, Reply-To, Return-Path correlations ...]

========== DMARC ALIGNMENT ASSESSMENT ==========
SPF Aligned: False
DKIM Aligned: False

[... authentication / sender identity and header context assessments ...]

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
  - The Reply-To domain differs from the visible From domain.
  - The Return-Path domain differs from the visible From domain.
  - The Reply-To domain differs from the Return-Path domain.
  - The SPF domain corresponds to the Return-Path domain.
  - The SPF domain differs from the Reply-To domain.
```

**Reading this as an analyst:** SPF and DKIM both pass, but for a bulk-mailing domain rather than `example.com`, and replies are routed to a third domain. That is not proof of malice (legitimate third-party senders look similar), but it justifies checking who operates those domains and whether `example.com` authorizes that sender.

---

## Testing

The analyzer was run against controlled `.eml` samples covering combinations of:

* SPF result and SPF-domain alignment
* DKIM result and signing-domain alignment
* DMARC result
* Matching and mismatching `Reply-To` and `Return-Path`

The goal was to confirm that authentication results and alignment are reported independently, and that a `pass` is never treated as proof of legitimacy.

---

## Limitations and Known Issues

* **Exact domain matching.** Alignment compares full domains. DMARC's relaxed alignment treats `mail.example.com` and `example.com` as aligned; this tool will report a mismatch. Organizational-domain matching is planned.
* **Single `Authentication-Results` header.** Only the first header is read, and each regex returns the first match. Messages with multiple headers or multiple DKIM signatures are not fully represented.
* **Trusts the header as written.** It does not re-verify SPF, DKIM, or DMARC. The header is only reliable if added by your own receiving infrastructure.
* **Messages with no `Authentication-Results` header are not handled gracefully yet** (missing keys cause an error during output). Fix in progress.
* **Header-only analysis.** No URL, attachment, or body analysis; no threat-intelligence enrichment; no verdict or severity scoring.
* **Console output only.** No JSON or SIEM-formatted output yet.

---

## Privacy

Email headers can expose personal addresses, internal hostnames, IP addresses, and Message-IDs. Samples in this repo use reserved example domains only. Redact real samples before publishing.

---

## Roadmap

* Fix handling of messages without authentication headers
* Relaxed (organizational-domain) alignment
* Include compauth and DMARC alignment in findings
* Use the existing `display_headers()` output (Received chain, DKIM-Signature) in the report
* **Phase 3:** URL and IOC extraction
* Threat-intelligence and domain reputation enrichment
* Attachment metadata analysis
* Severity scoring and JSON output
* Automated tests with a sanitized sample set

## 🧰 Tools & Technologies

Tools used throughout the investigations may include:

| Category            | Technologies                                |
| ------------------- | ------------------------------------------- |
| SIEM                | Splunk                                      |
| Log Analysis        | Splunk SPL                                  |
| Threat Intelligence | URL/IP reputation services                  |
| Frameworks          | MITRE ATT&CK                                |
| Documentation       | Markdown                                    |
| Version Control     | Git / GitHub                                |
| Automation          | Python / Bash                               |
| Lab Platforms       | TryHackMe and other controlled environments |

This list will expand as the lab environment and investigations become more advanced.

---

## 🧠 Investigation Methodology

My investigations generally follow a structured SOC workflow:

```text
1. Alert
   ↓
2. Initial Triage
   ↓
3. Hypothesis
   ↓
4. Evidence Collection
   ↓
5. Log Analysis
   ↓
6. Event Correlation
   ↓
7. Threat Intelligence
   ↓
8. Timeline Construction
   ↓
9. Findings
   ↓
10. Classification
   ↓
11. Detection Improvements
   ↓
12. Documentation
```

A major principle throughout these investigations is:

> **An alert is a starting point for investigation, not a conclusion.**

Where possible, findings are separated into:

* **Confirmed activity**
* **Suspected activity**
* **Unconfirmed activity**
* **Evidence of absence**
* **Lack of available evidence**

This distinction helps prevent overconfidence when working with incomplete telemetry.

---

## 📊 What I Am Practicing

This repository is intended to demonstrate practical experience with:

### SOC Analysis

* Alert triage
* Investigation prioritization
* Evidence assessment
* Incident classification
* False-positive identification
* Analyst documentation

### SIEM

* Searching security telemetry
* Writing and refining SPL queries
* Correlating events
* Investigating timestamps
* Identifying suspicious patterns
* Evaluating detection logic

### Threat Detection

* Understanding detection conditions
* Investigating alert triggers
* Identifying gaps in telemetry
* Improving detection logic
* Reducing false positives

### Incident Response

* Establishing timelines
* Identifying indicators of interest
* Determining scope
* Assessing potential impact
* Documenting findings
* Recommending additional investigation

### Threat Intelligence

* URL investigation
* IP investigation
* Domain investigation
* Reputation analysis
* Indicator correlation

---

## 🗺️ MITRE ATT&CK

Where appropriate, investigations are mapped to relevant **MITRE ATT&CK techniques**.

For example, the phishing investigation includes:

* **T1566 — Phishing**
* **T1566.002 — Spearphishing Link**

ATT&CK mappings are used to provide context around the observed behavior rather than treating a technique mapping as proof of successful compromise.

---

## 📸 Evidence & Screenshots

Screenshots are included when they provide useful evidence for an investigation.

Sensitive information may be:

* Redacted
* Blurred
* Replaced with placeholders

Examples of information that should be removed before publication include:

* Personal information
* Credentials
* API keys
* Tokens
* Private IP addresses
* Internal hostnames
* Email addresses
* Sensitive infrastructure details

The objective is to demonstrate the **investigation process and analyst reasoning** without exposing sensitive information.

---

## 📈 Roadmap

This repository will continue to expand as I work through increasingly complex blue team scenarios.

Planned areas include:

* [x] Phishing investigation
* [x] Splunk alert triage
* [ ] Windows event log investigations
* [ ] Brute-force detection
* [ ] Authentication investigations
* [ ] PowerShell investigations
* [ ] Endpoint compromise investigation
* [ ] Network intrusion investigation
* [ ] Malware analysis
* [ ] Detection engineering
* [ ] Automated alert enrichment
* [ ] Automated IOC investigation
* [ ] Incident response playbooks
* [ ] Advanced SIEM correlation
* [ ] Security automation

---

## 📚 Learning Philosophy

These writeups are not intended to simply document whether a lab was completed.

Instead, I use each investigation to answer questions such as:

**What happened?**

**How do I know?**

**What evidence supports that conclusion?**

**What evidence is missing?**

**What else could explain the activity?**

**What would I investigate next in a real SOC environment?**

This approach helps develop the analytical mindset required for security operations rather than focusing solely on finding the "correct" lab answer.

---

## ⚠️ Disclaimer

All investigations documented in this repository are performed in **authorized lab, simulation, or controlled environments**.

Any potentially malicious activity described in these writeups is conducted for educational and defensive security purposes.

No unauthorized systems are intentionally targeted.

---

## 👤 About

I'm building this repository as part of my progression toward a career in **cybersecurity / SOC analysis**, with a focus on developing practical blue team skills through hands-on investigation.

I'm particularly interested in:

* Security Operations
* Threat Detection
* Incident Response
* SIEM
* Detection Engineering
* Security Automation
* Threat Intelligence

This repository serves as a record of that progression.

---

⭐ If you're interested in blue team labs, SOC investigations, or practical cybersecurity learning, feel free to explore the individual writeups.
