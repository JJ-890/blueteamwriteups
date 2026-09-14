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

### 001 — Phishing Alert Investigation

**Environment:** Controlled phishing simulation
**SIEM:** Splunk
**Investigation Type:** Phishing alert triage
**Final Assessment:** Likely false positive
**Confidence:** Moderate

This investigation examines a simulated phishing alert and follows the activity from:

```text
Phishing Email
      ↓
Email Delivery
      ↓
User Interaction
      ↓
URL Access
      ↓
Potential Compromise
```

The investigation focuses on determining which stages of the attack chain can actually be supported by available telemetry.

Key areas investigated:

* Phishing email delivery
* Sender and recipient identification
* Duplicate email events
* URL investigation
* User interaction
* Link-click evidence
* Event correlation
* URL reputation
* Detection logic
* Telemetry limitations
* MITRE ATT&CK mapping
* False-positive assessment

➡️ **[Read the full investigation](./001_thm_phishing_sim.md)**

---

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
