from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Any


WINDOW = timedelta(minutes=5)
THRESHOLD = 5

SUCCESS_WINDOW = timedelta(minutes=10)
SUCCESS_THRESHOLD = 5


def parse_timestamp(value: str) -> datetime:
    """Convert an ISO-8601 timestamp ending in Z into a datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_events(file_path: str | Path) -> list[dict[str, Any]]:
    """Load, validate, and sort security events from a JSON file."""
    path = Path(file_path)

    with path.open("r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("The JSON file must contain a list of events.")

    required_fields = {
        "timestamp",
        "event_type",
        "username",
        "source_ip",
        "hostname",
    }

    for event in events:
        missing_fields = required_fields - event.keys()

        if missing_fields:
            missing = ", ".join(sorted(missing_fields))
            raise ValueError(f"Event is missing required fields: {missing}")

        event["_parsed_timestamp"] = parse_timestamp(event["timestamp"])

    return sorted(events, key=lambda event: event["_parsed_timestamp"])


def detect_failed_login_bursts(
    events: list[dict[str, Any]],
    threshold: int = THRESHOLD,
    window: timedelta = WINDOW,
) -> list[dict[str, Any]]:
    """
    Detect repeated failed logins involving one username
    and one source IP within a limited time window.
    """
    event_windows: dict[
        tuple[str, str],
        deque[dict[str, Any]],
    ] = defaultdict(deque)

    alerted_keys: set[tuple[str, str]] = set()
    alerts: list[dict[str, Any]] = []

    for event in events:
        if event["event_type"] != "failed_login":
            continue

        key = (event["username"], event["source_ip"])
        current_window = event_windows[key]
        current_time = event["_parsed_timestamp"]
        cutoff = current_time - window

        current_window.append(event)

        while (
            current_window
            and current_window[0]["_parsed_timestamp"] < cutoff
        ):
            current_window.popleft()

        if len(current_window) >= threshold and key not in alerted_keys:
            alert = {
                "rule_name": "Repeated Failed Logins",
                "severity": "high",
                "username": event["username"],
                "source_ip": event["source_ip"],
                "hostname": event["hostname"],
                "failed_attempts": len(current_window),
                "first_seen": current_window[0]["timestamp"],
                "last_seen": current_window[-1]["timestamp"],
                "mitre_technique": "T1110.001 - Password Guessing",
                "status": "new",
            }

            alerts.append(alert)
            alerted_keys.add(key)

    return alerts
def detect_success_after_failed_logins(
    events: list[dict[str, Any]],
    threshold: int = SUCCESS_THRESHOLD,
    window: timedelta = SUCCESS_WINDOW,
) -> list[dict[str, Any]]:
    """
    Detect a successful login following repeated failed
    logins for the same username and source IP.
    """
    failed_login_windows: dict[
        tuple[str, str],
        deque[dict[str, Any]],
    ] = defaultdict(deque)

    alerts: list[dict[str, Any]] = []

    for event in events:
        key = (
            event["username"],
            event["source_ip"],
        )

        current_time = event["_parsed_timestamp"]
        cutoff = current_time - window
        current_window = failed_login_windows[key]

        while (
            current_window
            and current_window[0]["_parsed_timestamp"] < cutoff
        ):
            current_window.popleft()

        if event["event_type"] == "failed_login":
            current_window.append(event)
            continue

        if event["event_type"] != "login_success":
            continue

        if len(current_window) < threshold:
            continue

        alert = {
            "rule_name": (
                "Successful Login After Repeated Failures"
            ),
            "severity": "critical",
            "username": event["username"],
            "source_ip": event["source_ip"],
            "hostname": event["hostname"],
            "failed_attempts": len(current_window),
            "first_seen": current_window[0]["timestamp"],
            "last_seen": event["timestamp"],
            "mitre_technique": (
                "T1110.001 / T1078 - Password Guessing "
                "and Valid Accounts"
            ),
            "status": "new",
        }

        alerts.append(alert)

        # Clear the failures so the same sequence does not
        # generate another alert from a second successful login.
        current_window.clear()

    return alerts
def detect_all_alerts(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Run all available detection rules."""
    alerts: list[dict[str, Any]] = []

    alerts.extend(
        detect_failed_login_bursts(events)
    )

    alerts.extend(
        detect_success_after_failed_logins(events)
    )

    return alerts