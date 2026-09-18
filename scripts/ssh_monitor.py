import subprocess
import re
import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta


# ==========================================
# Detection Configuration
# ==========================================
ALERT_CACHE={}
LOG_ENTRIES_TO_ANALYZE = 500

WINDOW_MINUTES = 5

MEDIUM_THRESHOLD = 3
HIGH_THRESHOLD = 5
CRITICAL_THRESHOLD = 10

#ALERT_LOG = "logs/logfile"


# ==========================================
# Severity Calculation
# ==========================================

def calculate_severity(attempts):
    """
    Determine severity based on the number of
    failed authentication attempts within the
    detection window.
    """

    if attempts >= CRITICAL_THRESHOLD:
        return "CRITICAL"

    if attempts >= HIGH_THRESHOLD:
        return "HIGH"

    if attempts >= MEDIUM_THRESHOLD:
        return "MEDIUM"

    if attempts >= 1:
        return "LOW"

    return None
    # ==========================================
# Alert / Event Logging
# ==========================================

def write_event(
    event_type,
    source_ip,
    username=None,
    targeted_usernames=None,
    failed_attempts=None,
    severity=None,
    action="Detected"):
    """
    Write a structured security event to logs/logile.
    """
    alert_key = (event_type, source_ip)

    current_time = datetime.now(timezone.utc)

    if alert_key in alert_cache:

        last_alert_time = alert_cache[alert_key]

        time_elapsed = current_time - last_alert_time

        suppression_window = timedelta(minutes=5)

        if time_elapsed < suppression_window:
            print("[!] Duplicate alert suppressed.")
            return

    alert_cache[alert_key] = current_time


    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "targeted_usernames": targeted_usernames,
        "failed_attempts": failed_attempts,
        "severity": severity,
        "action": action
    }

    with open(ALERT_LOG, "a") as file:
        file.write(json.dumps(event) + "\n")

    print("[+] Security event written to logs/logfile")
    # ==========================================
# Retrieve SSH Logs
# ==========================================

def get_ssh_logs():
    """
    Retrieve recent SSH authentication events
    from the systemd journal.
    """

    command = [
        "journalctl",
        "-u", "ssh",
        "--no-pager",
        "-n", str(LOG_ENTRIES_TO_ANALYZE),
        "-o", "short-iso"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout.splitlines()


# ==========================================
# Parse SSH Events
# ==========================================

def parse_ssh_events(log_lines):
    """
    Parse SSH log lines and identify:

    - Invalid users
    - Failed passwords
    - Successful password authentication
    - Successful public-key authentication
    - Connection activity

    Returns a list of structured events.
    """
    events = []

    for line in log_lines:

        timestamp_match = re.match(
            r"^(\d{4}-\d{2}-\d{2}T[\d:.+-]+)",
            line
        )

        if not timestamp_match:
            continue

        timestamp_string = timestamp_match.group(1)

        try:
            timestamp = datetime.fromisoformat(timestamp_string)
        except ValueError:
            continue

        # --------------------------------------
        # Invalid username
        # --------------------------------------

        invalid_user = re.search(
            r"Invalid user (\S+) from "
            r"(\d{1,3}(?:\.\d{1,3}){3})",
            line
        )

        if invalid_user:

            events.append({
                "timestamp": timestamp,
                "event_type": "ssh_auth_failure",
                "source_ip": invalid_user.group(2),
                "username": invalid_user.group(1)
            })

            continue

        # --------------------------------------
        # Failed password
        # --------------------------------------

        failed_password = re.search(
            r"Failed password for "
                        r"(?:invalid user )?(\S+) from "
            r"(\d{1,3}(?:\.\d{1,3}){3})",
            line
        )

        if failed_password:

            events.append({
                "timestamp": timestamp,
                "event_type": "ssh_auth_failure",
                "source_ip": failed_password.group(2),
                "username": failed_password.group(1)
            })

            continue

        # --------------------------------------
        # Successful password authentication
        # --------------------------------------

        accepted_password = re.search(
            r"Accepted password for (\S+) from "
            r"(\d{1,3}(?:\.\d{1,3}){3})",
            line
        )

        if accepted_password:

            events.append({
                "timestamp": timestamp,
                "event_type": "ssh_auth_success",
                "source_ip": accepted_password.group(2),
                "username": accepted_password.group(1)
            })

            continue

        # --------------------------------------
        # Successful public-key authentication
        # --------------------------------------

        accepted_key = re.search(
            r"Accepted publickey for (\S+) from "
            r"(\d{1,3}(?:\.\d{1,3}){3})",
                        line
        )

        if accepted_key:

            events.append({
                "timestamp": timestamp,
                "event_type": "ssh_auth_success",
                "source_ip": accepted_key.group(2),
                "username": accepted_key.group(1)
            })

            continue

        # --------------------------------------
        # SSH connection closed
        # --------------------------------------

        connection_closed = re.search(
            r"Connection closed by "
            r"(\d{1,3}(?:\.\d{1,3}){3})",
            line
        )

        if connection_closed:

            events.append({
                "timestamp": timestamp,
                "event_type": "ssh_connection_closed",
                "source_ip": connection_closed.group(1),
                "username": None
            })

            continue

    return events



# ==========================================
# Analyze Authentication Failures
# ==========================================
def analyze_failed_authentication(events):
    """
    Analyze failed SSH authentication attempts
    within the configured detection window.
    """

    now = datetime.now(timezone.utc)


    failed_by_ip = defaultdict(list)

    for event in events:

        if event["event_type"] != "ssh_auth_failure":
            continue

        if now - event["timestamp"] <= timedelta(
            minutes=WINDOW_MINUTES
        ):
            failed_by_ip[event["source_ip"]].append(event)

    if not failed_by_ip:

        print(
            f"[+] No failed authentication attempts "
            f"in the last {WINDOW_MINUTES} minutes."
        )

        return

    print("\n[*] Authentication activity detected:")

    for ip, failures in failed_by_ip.items():

        attempts = len(failures)

        severity = calculate_severity(attempts)

        usernames = sorted(
            set(
                event["username"]
                for event in failures
                if event["username"]
                           )
        )

        if len(usernames)==1:
            targeting_type = "single_account"
            
        else:
             targeting_type = "multi_account"

        print("\n--------------------------------")
        print(f"Source IP: {ip}")
        print(f"Failed attempts: {attempts}")
        print(f"Severity: {severity}")
        print(f"Targeting Type: {targeting_type}")


        if usernames:
            print(
                "Targeted usernames: "
                + ", ".join(usernames)
            )

        print("--------------------------------")

        # Development mode:
        # Log every severity level

        write_event(
            event_type="ssh_bruteforce",
            source_ip=ip,
            targeted_usernames=usernames,
            failed_attempts=attempts,
            severity=severity
        )


# ==========================================
# Analyze Successful Authentication
# ==========================================

def analyze_successful_logins(events):
    """
    Identify successful SSH authentication events
    occurring within the detection window.
    """
    now = datetime.now(timezone.utc)

    successful_logins = [
        event
        for event in events
        if event["event_type"] == "ssh_auth_success"
        and now - event["timestamp"]
        <= timedelta(minutes=WINDOW_MINUTES)
    ]

    if not successful_logins:

        print(
            f"\n[+] No successful SSH authentications "
            f"in the last {WINDOW_MINUTES} minutes."
        )

        return

    print("\n[*] Successful SSH authentication detected:")

    for event in successful_logins:

        print("\n--------------------------------")
        print(f"Source IP: {event['source_ip']}")
        print(f"Username: {event['username']}")
        print(f"Timestamp: {event['timestamp']}")
        print("--------------------------------")

        write_event(
            event_type="ssh_auth_success",
            source_ip=event["source_ip"],
            username=event["username"],
            severity="INFO",
            action="Successful authentication"
        )


# ==========================================
# Failure → Success Correlation
# ==========================================

def correlate_failures_and_success(events):
    """
    Identify source IPs that experienced failed
       authentication attempts followed by a successful
    authentication within the detection window.
    """

    now = datetime.now(timezone.utc)

    recent_events = [
        event
        for event in events
        if now - event["timestamp"]
        <= timedelta(minutes=WINDOW_MINUTES)
    ]

    failed_by_ip = defaultdict(list)
    successful_by_ip = defaultdict(list)

    for event in recent_events:

        if event["event_type"] == "ssh_auth_failure":
            failed_by_ip[event["source_ip"]].append(event)

        elif event["event_type"] == "ssh_auth_success":
            successful_by_ip[event["source_ip"]].append(event)

    for ip in failed_by_ip:

        if ip not in successful_by_ip:
            continue

        failures = failed_by_ip[ip]
        successes = successful_by_ip[ip]

        print(
            "\n[!] Authentication failure → success "
            "sequence detected!"
        )

        print("\n--------------------------------")
        print(f"Source IP: {ip}")
        print(f"Failed attempts: {len(failures)}")

        usernames = sorted(
            set(
                event["username"]
                for event in failures
                if event["username"]
            )
        )

        if usernames:
            print(
                "Failed usernames: "
                + ", ".join(usernames)
            )

        for success in successes:

            print(
                f"Successful username: "
                f"{success['username']}"
            )

            print(
                f"Success timestamp: "
                f"{success['timestamp']}"
            )

        print("--------------------------------")

        write_event(
            event_type="ssh_failure_success_correlation",
            source_ip=ip,
            username=successes[0]["username"],
            targeted_usernames=usernames,
            failed_attempts=len(failures),
            severity="HIGH",
            action="Investigation required"
        )


# ==========================================
# Analyze Connection Activity
# ==========================================
def analyze_connections(events):
    """
    Count recent SSH connection closures.

    These are informational and are not treated
    as authentication failures.
    """

    now = datetime.now(timezone.utc)

    connections = [
        event
        for event in events
        if event["event_type"] == "ssh_connection_closed"
        and now - event["timestamp"]
        <= timedelta(minutes=WINDOW_MINUTES)
    ]

    if not connections:

        print(
            f"[+] No SSH connection closures "
            f"in the last {WINDOW_MINUTES} minutes."
        )

        return

    print(
        f"\n[*] SSH connection activity: "
        f"{len(connections)} connection(s) closed."
    )


# ==========================================
# Main
# ==========================================

def main():

    print("[*] SSH Authentication Detection Engine")

    print(
        f"[*] Analyzing last "
        f"{LOG_ENTRIES_TO_ANALYZE} journal entries..."
    )
    print(
        f"[*] Detection window: "
        f"{WINDOW_MINUTES} minutes\n"
    )

    logs = get_ssh_logs()

    print(
        f"[+] Retrieved {len(logs)} journal entries."
    )

    events = parse_ssh_events(logs)
    
    print(
        f"[+] Parsed {len(events)} SSH events."
    )

    analyze_failed_authentication(events)

    analyze_successful_logins(events)

    correlate_failures_and_success(events)

    analyze_connections(events)


if __name__ == "__main__":
    main()
