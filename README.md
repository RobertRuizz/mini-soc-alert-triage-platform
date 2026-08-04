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

## Planned Features

- SQLite alert and case storage
- Streamlit investigation dashboard
- Analyst notes and case statuses
- Password-spraying detection
- Suspicious PowerShell detection
- Successful login after repeated failures
- Alert filtering and reporting

## Running the Project

Activate the virtual environment:

```bash
source .venv/bin/activate