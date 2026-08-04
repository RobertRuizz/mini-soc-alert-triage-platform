import json
from pathlib import Path

from app.detector import detect_failed_login_bursts, load_events


def main() -> None:
    project_root = Path(__file__).resolve().parent
    data_path = project_root / "data" / "sample_events.json"

    try:
        events = load_events(data_path)
        alerts = detect_failed_login_bursts(events)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as error:
        print(f"Unable to process events: {error}")
        return

    print(f"Loaded {len(events)} events.")
    print(f"Generated {len(alerts)} alert(s).\n")

    if not alerts:
        print("No suspicious activity detected.")
        return

    for alert in alerts:
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


if __name__ == "__main__":
    main()