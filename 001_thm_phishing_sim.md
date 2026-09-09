# Phishing Alert Investigation

## Overview

This writeup documents the investigation of a phishing alert generated during a controlled phishing simulation.

The purpose of the investigation was to determine why the alert was generated, identify the activity associated with the alert, and determine whether there was evidence that the targeted user interacted with the phishing email or its embedded link.

The investigation was performed in a controlled lab environment using Splunk as the primary source of security telemetry.

**Investigation Type:** Phishing Alert Triage
**Environment:** Controlled Phishing Simulation
**SIEM:** Splunk
**Final Assessment:** Likely False Positive

---

# 1. Investigation Objective

The initial alert indicated potentially malicious phishing activity involving an email sent to a recipient within the simulated environment.

The primary goals of the investigation were to:

* Identify the email associated with the alert.
* Determine when the email was sent and delivered.
* Identify the sender and recipient.
* Determine whether the recipient interacted with the email.
* Search for evidence that the embedded link was clicked.
* Identify any activity occurring after the email was delivered.
* Determine why the alert was generated.
* Decide whether the alert represented a legitimate security event or a false positive.

An important distinction throughout the investigation was made between **email delivery** and **user interaction**.

The presence of a phishing email in a mailbox does not by itself demonstrate that the recipient clicked the link or was compromised.

---

# 2. Initial Alert

The investigation began after a phishing-related alert appeared in Splunk.

The alert contained information relating to a suspicious email and the sender and recipient associated with the event.

### Initial Alert Information

| Field            | Value          |
| ---------------- | -------------- |
| Alert            | `[ALERT NAME]` |
| Severity         | `[SEVERITY]`   |
| Timestamp        | `[TIMESTAMP]`  |
| Sender           | `[REDACTED]`   |
| Recipient        | `[REDACTED]`   |
| Subject          | `[REDACTED]`   |
| Detection Source | Splunk         |

### Initial Assessment

At this stage, the alert was treated as a potentially legitimate phishing event.

No assumptions were made regarding whether the recipient had clicked the link.

The investigation therefore proceeded by examining the underlying telemetry.

> **Screenshot:** Insert screenshot of the original Splunk alert here.

---

# 3. Initial Hypothesis

Based on the alert, the initial hypothesis was that a phishing email had been delivered to the recipient and that the recipient may have interacted with the malicious link.

The potential attack chain was considered to be:

```text
Phishing Email
      |
      v
Email Delivery
      |
      v
User Interaction
      |
      v
Link Click
      |
      v
Potential Follow-on Activity
```

The investigation was intended to determine which parts of this sequence could actually be supported by the available telemetry.

---

# 4. Email Event Investigation

The first investigation focused on identifying the email events associated with the alert.

### Splunk Search

```spl
recipient= ”j.garcia@thetrydaily.thm”
sender= "onboarding@hrconnex.thm"
```

### Purpose

The purpose of this search was to locate email events associated with the sender, recipient, subject, and relevant timeframe.

The search was also used to determine whether additional email events existed around the time the alert was generated.

### Findings

The search identified email activity involving the same sender and recipient associated with the alert.

During the investigation, two email events were observed involving the same sender and recipient at approximately around  the same time.

This was notable because the alert may have been related to repeated or duplicate email activity.

However, at this point it was not possible to determine whether the repeated events were responsible for triggering the alert.

The detection logic would need to be examined to determine the exact reason the alert fired.

> **Screenshot:** Insert screenshot of the email events/search results here.

---

# 5. Investigating for Link Interaction

After identifying the email events, the next step was to determine whether there was evidence that the recipient clicked the link contained within the phishing email.

### Splunk Search

```spl
index=* "hrconnex.thm" action=allowed
index=* "hrconnex.thm" action=blocked
index=* "https://hrconnex.thm/onboarding/15400654060/j.garcia"
```

### Investigation Approach

The investigation searched the available telemetry for events that could indicate interaction with the URL.

Depending on the available data sources, evidence of a link click could include:

* Web proxy requests
* HTTP/HTTPS connections
* DNS queries
* Firewall connections
* Browser activity
* Endpoint telemetry
* URL-click tracking events
* Network connections to the phishing destination

### Findings

No event was identified within the available telemetry that directly demonstrated that the recipient clicked the phishing link.

The available Splunk data primarily contained email-related events.

This meant that the investigation could confirm the presence of the email activity, but could not confirm successful interaction with the embedded link.

> **Screenshot:** Insert screenshot of the search for link/click activity here.

---

# 6. Event Correlation

The next step was to correlate the events surrounding the alert.

The investigation showed that the sender appeared to have sent two emails to the same recipient at approximately around the same timestamp.

This raised the possibility that the detection was triggered by multiple related email events rather than evidence of a successful phishing interaction.

### Observed Activity

```text
Sender
  |
  +---- Email Event #1 ----> Recipient
  |
  +---- Email Event #2 ----> Recipient
                |
                +---- around  same timestamp
```

The repeated email events were therefore treated as an important piece of evidence during the investigation.

However, the investigation did not establish that duplicate email events were definitively the cause of the alert.

That conclusion would require examining the detection rule or correlation search responsible for generating the alert.

> **Screenshot:** Insert screenshot showing the correlated email events here.

---

# 7. Timeline

The following timeline was constructed from the available Splunk events.

| Time     | Event                             | Significance                             |
| -------- | --------------------------------- | ---------------------------------------- |
| `[TIME]` | Email event recorded              | Phishing-related email activity          |
| `[TIME]` | Second email event recorded       | Same sender/recipient                    |
| `[TIME]` | Phishing alert generated          | Detection triggered                      |
| `[TIME]` | Investigation initiated           | Analyst triage                           |
| `[TIME]` | Link interaction search performed | No supporting click telemetry identified |

The exact timestamps should be replaced with the timestamps observed during the investigation.

---

# 8. Indicators of Interest

The following indicators were associated with the investigation.

| Indicator      | Value                              | Status        |
| -------------- | ---------------------------------- | ------------- |
| Sender         | `[REDACTED]`                       | Investigated  |
| Recipient      | `[REDACTED]`                       | Target        |
| Subject        | `[REDACTED]`                       | Investigated  |
| URL            | `[REDACTED]`                       | Investigated  |
| Source IP      | `[REDACTED]`                       | Investigated  |
| Destination IP | `[REDACTED]`                       | Investigated  |
| Link Click     | No supporting telemetry identified | Not Confirmed |

Sensitive information should be redacted before publishing the investigation to GitHub.

---

# 9. MITRE ATT&CK Mapping

The simulated activity can be associated with the following MITRE ATT&CK technique:

## T1566 — Phishing

The activity falls under the Phishing technique because the simulated attack used an email as the delivery mechanism.

## T1566.002 — Spearphishing Link

If the phishing email contained a link designed to direct the recipient to a simulated or malicious destination, the activity can be further mapped to:

**T1566.002 — Spearphishing Link**

### Technique Assessment

| Activity                | Status        |
| ----------------------- | ------------- |
| Phishing email sent     | Confirmed     |
| Email delivered         | Confirmed     |
| Suspicious link present | Confirmed     |
| Link clicked            | Not confirmed |
| Successful compromise   | Not confirmed |

This distinction is important because the presence of a phishing email does not necessarily mean that the attack succeeded.

---

# 10. Investigation Limitations

One limitation of this investigation was the available telemetry.

The Splunk environment contained email events, but there was not sufficient browser, proxy, endpoint, or URL-click telemetry available to directly confirm user interaction with the phishing link.

Therefore, the investigation cannot definitively state that the link was never clicked.

Instead, the appropriate conclusion is:

> No evidence of link interaction was identified within the available telemetry.

This distinction is important when performing security investigations.

A lack of telemetry should not automatically be interpreted as proof that an event did not occur.

---

# 11. Findings

The investigation produced several findings.

### Finding 1 — Phishing Email Activity Was Confirmed

The investigation identified email events associated with the phishing simulation.

### Finding 2 — Multiple Email Events Were Observed

Two email events involving the same sender and recipient were observed at approximately the same time.

### Finding 3 — Link Interaction Was Not Confirmed

No available telemetry demonstrated that the recipient clicked the phishing link.

### Finding 4 — Successful Compromise Was Not Confirmed

No available evidence demonstrated that the recipient was successfully compromised as a result of the phishing email.

### Finding 5 — The Alert May Have Been Triggered by Email Activity

The repeated email events provide a possible explanation for why the detection was generated.

However, the exact detection logic should be reviewed before stating that duplicate email events were definitively responsible for the alert.
### Finding 6- The Url Was Checked And Came Back Clean

I was able to put the URL through a checker and the URL used in the email itself was clean.
---

# 12. Final Assessment

## Classification

**Likely False Positive**

## Confidence

**Moderate**

### Reasoning

The investigation confirmed suspicious phishing-related email activity.

However, the available telemetry did not provide evidence demonstrating that the recipient clicked the embedded link.

Additionally, two email events involving the same sender and recipient were observed at approximately the same time.

This repeated email activity provides a plausible explanation for the alert, although the exact detection condition would need to be reviewed to determine whether the duplicate events caused the alert.

Based on the evidence available during the investigation, the alert was classified as a **likely false positive** rather than a confirmed successful phishing interaction.

The classification is limited to the telemetry available within the lab environment.

---

# 13. Detection Analysis

This investigation highlighted an important consideration when designing phishing detections:

> **Email delivery should not automatically be treated as evidence of user interaction.**

A more complete detection workflow could distinguish between several stages of the attack:

```text
Suspicious Email
      |
      v
Email Delivered
      |
      v
User Interaction
      |
      v
URL Access
      |
      v
Endpoint / Authentication Activity
```

Each stage provides a different level of confidence.

For example, an email being delivered could represent a suspicious event, while a subsequent web request to the phishing domain would provide stronger evidence of user interaction.

### Potential Detection Improvements

Future detection logic could consider:

* Duplicate email events
* Sender reputation
* URL reputation
* Email authentication results
* URL-click telemetry
* Proxy logs
* DNS logs
* Endpoint telemetry
* Authentication activity
* Correlation between email delivery and subsequent network activity

This could help reduce false positives while increasing confidence in alerts that indicate actual user interaction.

---

# 14. Recommended Follow-up

If additional telemetry becomes available, the following investigations should be performed.

### Proxy / Web Logs

Search for network requests to the phishing URL or destination IP around the time the email was delivered.

```spl
[INSERT SPL QUERY HERE]
```

### DNS Logs

Search for DNS queries associated with the phishing domain.

```spl
[INSERT SPL QUERY HERE]
```

### Endpoint Telemetry

Search for browser and network activity originating from the recipient's endpoint.

```spl
[INSERT SPL QUERY HERE]
```

### Authentication Logs

Search for suspicious authentication activity following delivery of the phishing email.

```spl
[INSERT SPL QUERY HERE]
```

---

# 15. Lessons Learned

This investigation demonstrated several important blue-team concepts.

### 1. Alerts are starting points, not conclusions

A SIEM alert identifies activity that requires investigation. It should not automatically be treated as proof that an attack succeeded.

### 2. Email delivery and user interaction are different events

A phishing email being delivered does not demonstrate that a user clicked the link.

### 3. Correlation is critical

Examining events around the alert timestamp helped identify the repeated sender/recipient activity.

### 4. Telemetry limitations must be documented

When the available logs cannot prove or disprove an action, the limitation should be explicitly documented.

### 5. False positives are still valuable investigations

Determining that an alert is likely a false positive is a legitimate SOC outcome when the conclusion is supported by evidence.

### 6. Detection engineering and incident investigation are connected

An investigation can reveal weaknesses in detection logic and provide opportunities to improve future alerting.

---

# 16. Evidence

The following screenshots should be added to the final GitHub version of this investigation.

### Initial Alert

`[INSERT SCREENSHOT HERE]`

### Email Event Search

`[INSERT SCREENSHOT HERE]`

### Link / Click Investigation

`[INSERT SCREENSHOT HERE]`

### Correlated Sender and Recipient Events

`[INSERT SCREENSHOT HERE]`

### Additional Relevant Splunk Results

`[INSERT SCREENSHOT HERE]`

---

# Conclusion

This investigation examined a phishing alert generated during a controlled phishing simulation.

The investigation confirmed the presence of phishing-related email activity and identified multiple email events involving the same sender and recipient at approximately the same time.

However, no available telemetry provided evidence that the recipient clicked the phishing link or that a successful compromise occurred.

Based on the available evidence, the alert was classified as a **likely false positive** with moderate confidence.

The investigation also demonstrated the importance of distinguishing between **email delivery, user interaction, and confirmed compromise** when analyzing phishing alerts.

Further improvement to the detection could involve correlating email events with URL, proxy, DNS, endpoint, and authentication telemetry to provide greater confidence when determining whether a phishing attempt resulted in actual user interaction.
