import json
from pathlib import Path

from app.database import (
    fetch_all_alerts,
    initialize_database,
    save_alerts,
)
from app.detector import (
    detect_all_alerts,
    load_events,
)


def display_alert(alert: dict) -> None:
    """Print one alert in a readable terminal format."""
    print(
        f"[{alert['severity'].upper()}] {alert['rule_name']}\n"
        f"  User: {alert['username']}\n"
        f"  Source IP: {alert['source_ip']}\n"
        f"  Host: {alert['hostname']}\n"
        f"  Attempts: {alert['failed_attempts']}\n"
        f"  Time range: {alert['first_seen']} "
        f"to {alert['last_seen']}\n"
        f"  MITRE ATT&CK: {alert['mitre_technique']}\n"
        f"  Status: {alert['status']}\n"
    )


def main() -> None:
    project_root = Path(__file__).resolve().parent
    data_path = project_root / "data" / "sample_events.json"

    try:
        events = load_events(data_path)
        alerts = detect_all_alerts(events)

        initialize_database()
        inserted_count = save_alerts(alerts)
        stored_alerts = fetch_all_alerts()

    except (
        FileNotFoundError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        print(f"Unable to process events: {error}")
        return

    print(f"Loaded {len(events)} events.")
    print(f"Generated {len(alerts)} alert(s).")
    print(f"Saved {inserted_count} new alert(s) to SQLite.")
    print(f"Database contains {len(stored_alerts)} alert(s).\n")

    if not alerts:
        print("No suspicious activity detected.")
        return

    for alert in alerts:
        display_alert(alert)


if __name__ == "__main__":
    main()