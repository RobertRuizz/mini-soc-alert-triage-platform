from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Any

from app.rule_loader import load_all_rules


def parse_timestamp(value: str) -> datetime:
    """Convert an ISO-8601 timestamp ending in Z into a datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_events(file_path: str | Path) -> list[dict[str, Any]]:
    """Load, validate, and chronologically sort security events."""
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

    for event_number, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValueError(
                f"Event {event_number} must be a JSON object."
            )

        missing_fields = required_fields - event.keys()

        if missing_fields:
            missing = ", ".join(sorted(missing_fields))
            raise ValueError(
                f"Event {event_number} is missing fields: {missing}"
            )

        event["_parsed_timestamp"] = parse_timestamp(
            event["timestamp"]
        )

    return sorted(
        events,
        key=lambda event: event["_parsed_timestamp"],
    )


def build_mitre_label(rule: dict[str, Any]) -> str:
    """Create a readable MITRE ATT&CK label from a YAML rule."""
    mitre = rule["mitre"]

    technique_id = mitre.get(
        "technique_id",
        "Unknown",
    )

    technique_name = mitre.get(
        "technique_name",
        "Unknown Technique",
    )

    return f"{technique_id} - {technique_name}"


def detect_failed_login_bursts(
    events: list[dict[str, Any]],
    rule: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect repeated failures against one account."""
    threshold = int(rule["threshold"])

    window = timedelta(
        minutes=int(rule["window_minutes"])
    )

    event_type = rule.get(
        "event_type",
        "failed_login",
    )

    event_windows: dict[
        tuple[str, str],
        deque[dict[str, Any]],
    ] = defaultdict(deque)

    alerted_keys: set[tuple[str, str]] = set()
    alerts: list[dict[str, Any]] = []

    for event in events:
        if event["event_type"] != event_type:
            continue

        key = (
            event["username"],
            event["source_ip"],
        )

        current_window = event_windows[key]
        current_time = event["_parsed_timestamp"]
        cutoff = current_time - window

        current_window.append(event)

        while (
            current_window
            and current_window[0]["_parsed_timestamp"] < cutoff
        ):
            current_window.popleft()

        if (
            len(current_window) >= threshold
            and key not in alerted_keys
        ):
            alerts.append(
                {
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"].lower(),
                    "username": event["username"],
                    "affected_accounts": "",
                    "source_ip": event["source_ip"],
                    "hostname": event["hostname"],
                    "failed_attempts": len(current_window),
                    "first_seen": current_window[0][
                        "timestamp"
                    ],
                    "last_seen": current_window[-1][
                        "timestamp"
                    ],
                    "mitre_technique": build_mitre_label(
                        rule
                    ),
                    "status": "new",
                }
            )

            alerted_keys.add(key)

    return alerts


def detect_success_after_failed_logins(
    events: list[dict[str, Any]],
    rule: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect success after repeated failures."""
    threshold = int(rule["threshold"])

    window = timedelta(
        minutes=int(rule["window_minutes"])
    )

    failed_event_type = rule.get(
        "failed_event_type",
        "failed_login",
    )

    success_event_type = rule.get(
        "success_event_type",
        "login_success",
    )

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

        if event["event_type"] == failed_event_type:
            current_window.append(event)
            continue

        if event["event_type"] != success_event_type:
            continue

        if len(current_window) < threshold:
            continue

        alerts.append(
            {
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"].lower(),
                "username": event["username"],
                "affected_accounts": "",
                "source_ip": event["source_ip"],
                "hostname": event["hostname"],
                "failed_attempts": len(current_window),
                "first_seen": current_window[0][
                    "timestamp"
                ],
                "last_seen": event["timestamp"],
                "mitre_technique": build_mitre_label(
                    rule
                ),
                "status": "new",
            }
        )

        current_window.clear()

    return alerts


def detect_password_spraying(
    events: list[dict[str, Any]],
    rule: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect one source failing against multiple accounts."""
    account_threshold = int(
        rule["account_threshold"]
    )

    window = timedelta(
        minutes=int(rule["window_minutes"])
    )

    event_type = rule.get(
        "event_type",
        "failed_login",
    )

    source_windows: dict[
        str,
        deque[dict[str, Any]],
    ] = defaultdict(deque)

    alerted_sources: set[str] = set()
    alerts: list[dict[str, Any]] = []

    for event in events:
        if event["event_type"] != event_type:
            continue

        source_ip = event["source_ip"]
        current_time = event["_parsed_timestamp"]
        cutoff = current_time - window
        current_window = source_windows[source_ip]

        current_window.append(event)

        while (
            current_window
            and current_window[0]["_parsed_timestamp"] < cutoff
        ):
            current_window.popleft()

        affected_accounts = sorted(
            {
                failed_event["username"]
                for failed_event in current_window
            }
        )

        if (
            len(affected_accounts) >= account_threshold
            and source_ip not in alerted_sources
        ):
            alerts.append(
                {
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"].lower(),
                    "username": "multiple_accounts",
                    "affected_accounts": ", ".join(
                        affected_accounts
                    ),
                    "source_ip": source_ip,
                    "hostname": event["hostname"],
                    "failed_attempts": len(
                        current_window
                    ),
                    "first_seen": current_window[0][
                        "timestamp"
                    ],
                    "last_seen": current_window[-1][
                        "timestamp"
                    ],
                    "mitre_technique": build_mitre_label(
                        rule
                    ),
                    "status": "new",
                }
            )

            alerted_sources.add(source_ip)

    return alerts


def detect_all_alerts(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Load YAML rules and run each supported detector."""
    rules = load_all_rules()

    detection_handlers = {
        "AUTH-001": detect_failed_login_bursts,
        "AUTH-002": detect_success_after_failed_logins,
        "AUTH-003": detect_password_spraying,
    }

    alerts: list[dict[str, Any]] = []

    for rule_id, rule in rules.items():
        handler = detection_handlers.get(rule_id)

        if handler is None:
            print(
                f"Warning: No detection handler exists "
                f"for rule {rule_id}."
            )
            continue

        rule_alerts = handler(events, rule)
        alerts.extend(rule_alerts)

    return alerts