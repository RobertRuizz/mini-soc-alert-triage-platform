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

## Planned Features
- Suspicious PowerShell detection
- Alert filtering and reporting

## Running the Project

Activate the virtual environment:

```bash
source .venv/bin/activate