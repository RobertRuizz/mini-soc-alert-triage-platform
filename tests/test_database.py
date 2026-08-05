from pathlib import Path
from typing import Any

import pytest

from app.database import (
    fetch_all_alerts,
    initialize_database,
    save_alerts,
    update_alert,
)
from app.detector import detect_failed_login_bursts


def generate_test_alert(
    sample_events: list[dict[str, Any]],
    detection_rules: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Generate one alert for database testing."""
    alerts = detect_failed_login_bursts(
        sample_events,
        detection_rules["AUTH-001"],
    )

    assert alerts

    return alerts[0]


def test_duplicate_alerts_are_not_saved(
    tmp_path: Path,
    sample_events: list[dict[str, Any]],
    detection_rules: dict[str, dict[str, Any]],
) -> None:
    database_path = tmp_path / "test_soc.db"

    initialize_database(database_path)

    alert = generate_test_alert(
        sample_events,
        detection_rules,
    )

    first_insert = save_alerts(
        [alert],
        database_path,
    )

    second_insert = save_alerts(
        [alert],
        database_path,
    )

    stored_alerts = fetch_all_alerts(
        database_path
    )

    assert first_insert == 1
    assert second_insert == 0
    assert len(stored_alerts) == 1


def test_alert_status_and_notes_can_be_updated(
    tmp_path: Path,
    sample_events: list[dict[str, Any]],
    detection_rules: dict[str, dict[str, Any]],
) -> None:
    database_path = tmp_path / "test_soc.db"

    initialize_database(database_path)

    alert = generate_test_alert(
        sample_events,
        detection_rules,
    )

    save_alerts(
        [alert],
        database_path,
    )

    stored_alert = fetch_all_alerts(
        database_path
    )[0]

    updated = update_alert(
        alert_id=stored_alert["id"],
        status="investigating",
        analyst_notes=(
            "Reviewed authentication events and "
            "escalated for account-owner validation."
        ),
        db_path=database_path,
    )

    refreshed_alert = fetch_all_alerts(
        database_path
    )[0]

    assert updated is True
    assert refreshed_alert["status"] == "investigating"
    assert refreshed_alert["analyst_notes"] == (
        "Reviewed authentication events and "
        "escalated for account-owner validation."
    )


def test_invalid_alert_status_is_rejected(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "test_soc.db"

    initialize_database(database_path)

    with pytest.raises(
        ValueError,
        match="Invalid alert status",
    ):
        update_alert(
            alert_id=1,
            status="random_status",
            analyst_notes="Test note",
            db_path=database_path,
        )