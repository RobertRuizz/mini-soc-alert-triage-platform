from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Any


WINDOW = timedelta(minutes=5)
THRESHOLD = 5


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