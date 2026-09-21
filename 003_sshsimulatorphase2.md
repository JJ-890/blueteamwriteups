# Phase 2 — SSH Threat Detection & Detection Engineering

## TL;DR

In Phase 1, I built and debugged a Python-based SSH monitoring script that detected failed login attempts on a Linux server.

Phase 2 expanded that project from simply identifying failed authentication events to analyzing **patterns within those events**.

The detection logic was extended to:

* Identify activity targeting a single account versus multiple accounts.
* Correlate authentication events by source IP, username, event type, and time.
* Identify behavior consistent with password guessing and password spraying.
* Implement **5-minute alert deduplication based on `event_type + source_ip`**.
* Store persistent alert information in `logs/alert.json`.
* Test how detection output and persistent alert records behave under different conditions.
* Consider how a SOC analyst would investigate and validate the resulting alerts.

One important limitation remains: the 5-minute deduplication currently prevents duplicate **persistent alert records**, but it does not completely suppress the detection from appearing in the script's runtime output.

This phase taught me that detection engineering is not just about finding an event. It is about adding enough context to determine what the activity means, preserving useful state, reducing unnecessary alert duplication, and understanding where the detection still needs improvement.

---

# Phase 2 Objectives

The primary goal of Phase 2 was to make the SSH monitor more useful from a Blue Team and SOC perspective.

The project moved beyond:

```text
Failed SSH login → Alert
```

toward:

```text
Authentication telemetry
        ↓
Event correlation
        ↓
Behavioral pattern
        ↓
Detection
        ↓
Alert state
        ↓
Persistent record
```

The main objectives were:

1. Correlate multiple authentication events.
2. Determine whether activity targets one account or multiple accounts.
3. Add behavioral context to authentication alerts.
4. Implement persistent alert deduplication.
5. Test the detection against different authentication scenarios.
6. Identify false-positive considerations.
7. Evaluate limitations that would matter in a real SOC environment.

---

# 1. Expanding SSH Detection

The original monitor focused primarily on failed SSH authentication events.

While detecting failed authentication is useful, a single failed login does not provide much context by itself.

For example:

```text
Source IP → admin → failed login
```

could represent:

* A user entering the wrong password.
* An administrator mistyping credentials.
* A misconfigured service.
* An automated scanner.
* An authorized security assessment.
* Potentially malicious authentication activity.

Because of this, Phase 2 focused on **patterns of authentication activity rather than isolated events**.

The monitor began correlating information such as:

* Source IP
* Username
* Event type
* Number of attempts
* Time of activity
* Previously observed activity

This allowed the detection to provide more context around the authentication behavior.

---

# 2. Single-Account vs. Multi-Account Targeting

One of the major additions in Phase 2 was recognizing whether the same source IP was repeatedly targeting one account or attempting authentication against multiple accounts.

### Single-account pattern

```text
Source IP → admin
Source IP → admin
Source IP → admin
Source IP → admin
```

This can provide context consistent with **password guessing**.

MITRE ATT&CK categorizes password guessing as:

**T1110.001 — Password Guessing**

### Multi-account pattern

```text
Source IP → admin
Source IP → user1
Source IP → user2
Source IP → user3
```

This provides different behavioral context and can be consistent with **password spraying**.

MITRE ATT&CK categorizes password spraying as:

**T1110.003 — Password Spraying**

These classifications describe the observed behavior; they do not by themselves prove that the source is malicious.

That distinction is important for a Blue Team detection system.

The purpose of the detection is to identify activity that deserves investigation, not automatically determine intent.

---

# 3. Event Correlation

The addition of event correlation allowed the monitor to look at authentication activity as a group rather than treating every failed login as an independent event.

For example, the system can consider:

```text
Source IP
    ↓
Event Type
    ↓
Targeted Username(s)
    ↓
Time Window
    ↓
Previously Observed Activity
```

This creates more useful context for an analyst.

Instead of simply reporting:

```text
Failed SSH login
```

the detection can identify a pattern such as:

```text
Multiple failed authentication events
from the same source IP
targeting multiple accounts
```

That difference is important because the second alert provides significantly more investigative context.

---

# 4. Five-Minute Alert Deduplication

Phase 2 also introduced **5-minute alert deduplication**.

The deduplication logic uses:

```text
event_type + source_ip
```

as the alert identity.

When the system is preparing to create a persistent alert record, it checks `logs/alert.json` to determine whether the same `event_type + source_ip` combination has already been recorded within the previous **5 minutes**.

Conceptually:

```text
New Detection
      ↓
event_type + source_ip
      ↓
Check alert.json
      ↓
Was the same combination recorded
within the previous 5 minutes?
      ↓
   Yes        No
    ↓          ↓
No new      Create
record      alert record
```

The purpose is to reduce repeated persistent records for the same activity and make the stored alert data easier to review.

### Important implementation detail

This is **persistent alert deduplication**, not complete runtime alert suppression.

If an existing alert matches the 5-minute deduplication criteria, the system prevents another persistent record from being written to `alert.json`.

However, the underlying detection can still appear in the script's runtime output.

Therefore:

```text
Detection output ≠ persistent alert record
```

This distinction became an important architectural lesson during Phase 2.

---

# 5. Persistent Alert State

Earlier versions of the project relied more heavily on information held in memory while the Python process was running.

The problem with runtime-only state is that it disappears when the process stops.

For example:

```text
Python starts
     ↓
Detection occurs
     ↓
Information stored in memory
     ↓
Python stops
     ↓
Runtime state disappears
```

That makes it difficult for a future execution of the monitor to know what happened previously.

Phase 2 introduced persistent alert state through:

```text
logs/alert.json
```

The architecture therefore became:

```text
auth.log
   ↓
Detection / Correlation
   ↓
Persistent Alert State
   ↓
logs/alert.json
```

This allowed the monitor to retain information between executions.

The introduction of persistent state also exposed new design questions, particularly around how long an alert should remain relevant and how recurring activity should be handled.

---

# 6. Detection Validation

The detection logic was tested against several different scenarios rather than only testing whether the Python script executed successfully.

### Test 1 — No suspicious activity

The monitor was run under normal conditions to establish a baseline.

The purpose was to verify that the system could operate without generating unnecessary detection records when the relevant authentication behavior was not present.

<img src="screenshots/noactivity.png" alt="Debug version of **`ssh_monitor.py`** used to determine why the original monitoring script was not producing authentication events." width="900">

---

### Test 2 — Password spraying behavior

Authentication activity was generated in a way that targeted multiple accounts from the same source.

The purpose was to verify that the monitor could recognize the multi-account pattern and provide the expected detection output.

<img src="screenshots/firstalert.png" alt="Debug version of **`ssh_monitor.py`** used to determine why the original monitoring script was not producing authentication events." width="900">

---

### Test 3 — Existing alert / deduplication

An alert that had already been recorded was used to test the 5-minute deduplication behavior.

The expected behavior was that another persistent record would not be created when the same `event_type + source_ip` combination was already represented within the relevant time window.
<img src="screenshots/secondalertfirstsupress.png" alt="Debug version of **`ssh_monitor.py`** used to determine why the original monitoring script was not producing authentication events." width="900">

---

### Test 4 — Authentication logs

The underlying authentication logs were reviewed to compare the raw telemetry against what the detection logic reported.

This helped validate that the detection was based on actual authentication events rather than an unexpected source of data.

<img src="screenshots/firstlog.png" alt="Debug version of **`ssh_monitor.py`** used to determine why the original monitoring script was not producing authentication events." width="900">

---

### Test 5 — Persistent alert state

The `alert.json` file was reviewed to verify how detections were being stored.

This provided a direct view of the persistent state used by the deduplication logic.

<img src="screenshots/norepeatlog.png" alt="Debug version of **`ssh_monitor.py`** used to determine why the original monitoring script was not producing authentication events." width="900">

---

### Test 6 — Detection vs. persistent record behavior

The testing also demonstrated the distinction between the detection appearing in runtime output and whether a new persistent record was created.

This was important because the deduplication mechanism does not completely suppress the detection itself.

<img src="screenshots/failthensucess.png" alt="Debug version of **`ssh_monitor.py`** used to determine why the original monitoring script was not producing authentication events." width="900">
<img src="screenshots/failthensucesslog.png" alt="Debug version of **`ssh_monitor.py`** used to determine why the original monitoring script was not producing authentication events." width="900">

---

# 7. SOC Analyst Perspective

A detection should not be treated as proof that malicious activity occurred.

For example, repeated failed SSH authentication could have several explanations:

* A legitimate user repeatedly entering an incorrect password.
* An administrator mistyping credentials.
* A misconfigured service account.
* An automated scanner.
* An authorized security assessment.
* Potentially malicious authentication activity.

A SOC analyst receiving this type of alert would need additional context before deciding how to handle it.

Potential investigation steps could include:

1. Identify the source IP.
2. Determine which accounts were targeted.
3. Review the frequency and timing of attempts.
4. Determine whether the source is known or expected.
5. Look for successful authentication following the failed attempts.
6. Correlate the activity with other available security telemetry.
7. Determine whether the activity should be monitored, escalated, or closed as benign.

This is one of the main lessons from Phase 2:

> **Detection identifies activity that deserves attention; investigation determines what that activity means.**

---

# 8. Limitations & Next Steps

The current implementation works as a personal Blue Team detection-engineering exercise, but testing also exposed several areas that would need to be addressed in a more mature system.

## 8.1 Five-minute deduplication window

The current deduplication logic uses a 5-minute window.

That creates an important question:

**What should happen when the same source returns after the window expires?**

The current design treats activity based on whether the same `event_type + source_ip` combination was recorded within the relevant five-minute period.

A future version could introduce a more explicit alert lifecycle and track recurring activity over longer periods.

---

## 8.2 Attack volume is not fully represented

Deduplicating repeated alerts reduces duplicate records, but it can also make it harder to understand the total scale of an event.

For example:

```text
10 failed attempts
```

and

```text
1,000 failed attempts
```

could potentially result in similar persistent alert representation if the alert state is not also tracking event counts.

A future version could track:

* Total attempts.
* Number of targeted accounts.
* First-seen timestamp.
* Last-seen timestamp.
* Number of detection occurrences.
* Duration of the activity.

---

## 8.3 Runtime detection vs. persistent alert state

The current implementation demonstrates an important distinction:

```text
Detection occurs
        ↓
Runtime output
        ↓
Persistent alert deduplication
```

The detection can still appear in runtime output even when a duplicate persistent alert record is not created.

A future iteration could separate these concepts more explicitly by introducing alert states such as:

```text
New
↓
Recurring
↓
Investigating
↓
Resolved
```

---

## 8.4 More advanced event correlation

Future detection improvements could incorporate additional context such as:

* Frequency of authentication attempts.
* Number of accounts targeted.
* Time between attempts.
* Successful authentication following repeated failures.
* Network or geographic context.
* Other authentication telemetry.
* Additional host security logs.

This would allow the detection to move beyond simple pattern recognition toward richer behavioral correlation.

---

# 9. Lessons Learned

### Detection engineering is different from log parsing.

Reading an authentication log is only the first step.

The more difficult question is:

> What does the pattern of events tell me?

---

### Context matters.

A single failed login and repeated authentication attempts against multiple accounts are technically similar events, but they provide very different investigative context.

---

### Persistent state changes the architecture.

Once the detection system needs to remember previous activity, a simple script becomes more than:

```text
Read log → detect → print
```

It becomes:

```text
Read telemetry
      ↓
Correlate events
      ↓
Evaluate previous state
      ↓
Generate detection
      ↓
Update persistent state
```

---

### Testing exposes architectural problems.

The 5-minute deduplication testing did more than demonstrate that the feature worked.

It exposed questions about:

* Alert lifetime.
* Recurring activity.
* Attack volume.
* Runtime versus persistent alert behavior.
* Future alert lifecycle management.

That is valuable because detection engineering is an iterative process.

---

# Conclusion

Phase 2 expanded the SSH monitoring project from basic failed-login detection into a more context-aware Blue Team detection exercise.

The project now considers authentication patterns, distinguishes single-account from multi-account targeting, correlates events, implements **5-minute alert deduplication based on `event_type + source_ip`**, and maintains persistent alert state through `logs/alert.json`.

More importantly, testing exposed limitations that would not have been obvious from simply getting the detection to work.

The next stage of the project can build on these findings by improving alert lifecycle management, tracking recurring activity and attack volume, and incorporating additional security telemetry.

The overall development process has become:

```text
Collect telemetry
      ↓
Develop detection
      ↓
Correlate behavior
      ↓
Test detection
      ↓
Identify limitations
      ↓
Improve architecture
      ↓
Validate again
```

This phase reinforced an important Blue Team principle:

**A useful detection is not just an alert. It is a piece of security context that helps an analyst understand what happened and determine what should happen next.**
