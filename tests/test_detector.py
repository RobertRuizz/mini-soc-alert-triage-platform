from copy import deepcopy
from typing import Any

from app.detector import (
    detect_all_alerts,
    detect_failed_login_bursts,
    detect_password_spraying,
    detect_success_after_failed_logins,
)


def test_repeated_failed_login_detection(
    sample_events: list[dict[str, Any]],
    detection_rules: dict[str, dict[str, Any]],
) -> None:
    rule = detection_rules["AUTH-001"]

    alerts = detect_failed_login_bursts(
        sample_events,
        rule,
    )

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["rule_id"] == "AUTH-001"
    assert alert["rule_name"] == "Repeated Failed Logins"
    assert alert["severity"] == "high"
    assert alert["username"] == "rruiz"
    assert alert["source_ip"] == "203.0.113.50"
    assert alert["failed_attempts"] == 5
    assert alert["mitre_technique"] == (
        "T1110.001 - Password Guessing"
    )


def test_success_after_failures_detection(
    sample_events: list[dict[str, Any]],
    detection_rules: dict[str, dict[str, Any]],
) -> None:
    rule = detection_rules["AUTH-002"]

    alerts = detect_success_after_failed_logins(
        sample_events,
        rule,
    )

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["rule_id"] == "AUTH-002"
    assert alert["severity"] == "critical"
    assert alert["username"] == "rruiz"
    assert alert["source_ip"] == "203.0.113.50"
    assert alert["failed_attempts"] == 6
    assert alert["last_seen"] == (
        "2026-08-04T14:08:00Z"
    )
    assert alert["mitre_technique"] == (
        "T1078 - Valid Accounts"
    )


def test_password_spraying_detection(
    sample_events: list[dict[str, Any]],
    detection_rules: dict[str, dict[str, Any]],
) -> None:
    rule = detection_rules["AUTH-003"]

    alerts = detect_password_spraying(
        sample_events,
        rule,
    )

    assert len(alerts) == 1

    alert = alerts[0]

    expected_accounts = {
        "devon",
        "jordan",
        "maria",
        "sam",
        "taylor",
    }

    actual_accounts = {
        account.strip()
        for account in alert[
            "affected_accounts"
        ].split(",")
    }

    assert alert["rule_id"] == "AUTH-003"
    assert alert["severity"] == "high"
    assert alert["source_ip"] == "192.0.2.77"
    assert alert["failed_attempts"] == 5
    assert actual_accounts == expected_accounts
    assert alert["mitre_technique"] == (
        "T1110.003 - Password Spraying"
    )


def test_all_enabled_rules_generate_alerts(
    sample_events: list[dict[str, Any]],
) -> None:
    alerts = detect_all_alerts(sample_events)

    generated_rules = {
        alert["rule_id"]
        for alert in alerts
    }

    assert len(alerts) == 3

    assert generated_rules == {
        "AUTH-001",
        "AUTH-002",
        "AUTH-003",
    }


def test_yaml_threshold_controls_detection(
    sample_events: list[dict[str, Any]],
    detection_rules: dict[str, dict[str, Any]],
) -> None:
    rule = deepcopy(
        detection_rules["AUTH-001"]
    )

    rule["threshold"] = 7

    alerts = detect_failed_login_bursts(
        sample_events,
        rule,
    )

    assert alerts == []