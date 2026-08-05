# Mini SOC Alert-Triage Platform

A Python-based security monitoring project that analyzes synthetic logs,
detects suspicious activity, maps alerts to MITRE ATT&CK, and supports
basic SOC investigation workflows.

## Current Features

- Loads synthetic authentication events from JSON
- Validates required event fields
- Sorts events chronologically
- Detects repeated failed logins
- Uses a five-minute detection window
- Assigns alert severity
- Maps alerts to MITRE ATT&CK T1110.001
- Displays alerts in the terminal
- Stores alerts in a local SQLite database
- Prevents duplicate alert records
- Displays alerts in an interactive Streamlit dashboard
- Includes severity and case-status filters
- Displays alert metrics and investigation details
- Allows analysts to update case statuses
- Saves analyst investigation notes in SQLite
- Supports new, investigating, resolved, and false-positive cases
- Refreshes dashboard metrics after case updates
- Detects successful logins following repeated failures
- Runs multiple detection rules against the same event dataset
- Assigns critical severity to possible account compromise
- Maps authentication behavior to MITRE ATT&CK
- Detects possible password-spraying activity
- Identifies one source IP targeting multiple accounts
- Tracks all accounts affected by a spraying event
- Maps password spraying to MITRE ATT&CK T1110.003
- Loads detection settings from YAML rule files
- Supports configurable thresholds and time windows
- Allows detection rules to be enabled or disabled
- Loads rule names, severities, and MITRE mappings dynamically
- Separates detection content from Python implementation logic
## Planned Features
- Suspicious PowerShell detection
- Alert filtering and reporting

## Running the Project

Activate the virtual environment:

```bash
source .venv/bin/activate


## Project Structure

```text
Mini-soc-platform/
├── app/
│   ├── __init__.py
│   ├── database.py
│   ├── detector.py
│   └── rule_loader.py
├── data/
│   ├── sample_events.json
│   └── soc_alerts.db
├── rules/
│   ├── password_spraying.yml
│   ├── repeated_failed_logins.yml
│   └── success_after_failures.yml
├── tests/
├── .gitignore
├── dashboard.py
├── README.md
├── requirements.txt
└── run_detection.py
```

### Main Components

* `app/detector.py` contains the Python detection logic.
* `app/database.py` manages alert storage and case updates in SQLite.
* `app/rule_loader.py` loads configurable detection rules from YAML.
* `rules/` contains the detection thresholds, severity levels, event types, and MITRE ATT&CK mappings.
* `data/sample_events.json` contains fictional authentication logs used for testing.
* `dashboard.py` provides the Streamlit SOC dashboard.
* `run_detection.py` runs all enabled detection rules and stores generated alerts.
* `tests/` will contain automated tests in the next phase.

## Detection Rules

Detection rules are stored in the `rules/` directory:

* `repeated_failed_logins.yml`
* `success_after_failures.yml`
* `password_spraying.yml`

Each YAML rule defines its severity, threshold, time window, event types, enabled status, and MITRE ATT&CK mapping.
