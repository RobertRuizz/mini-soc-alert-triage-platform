import sqlite3
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "soc_alerts.db"
)


def get_connection(
    db_path: str | Path = DEFAULT_DB_PATH,
) -> sqlite3.Connection:
    """Create and return a connection to the SQLite database."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database(
    db_path: str | Path = DEFAULT_DB_PATH,
) -> None:
    """Create the alerts table if it does not already exist."""
    with get_connection(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                username TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                hostname TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                mitre_technique TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                analyst_notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                UNIQUE (
                    rule_name,
                    username,
                    source_ip,
                    first_seen,
                    last_seen
                )
            )
            """
        )


def save_alerts(
    alerts: list[dict[str, Any]],
    db_path: str | Path = DEFAULT_DB_PATH,
) -> int:
    """
    Save alerts to SQLite.

    Duplicate alerts are ignored. Returns the number of newly
    inserted alerts.
    """
    inserted_count = 0

    with get_connection(db_path) as connection:
        for alert in alerts:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO alerts (
                    rule_name,
                    severity,
                    username,
                    source_ip,
                    hostname,
                    failed_attempts,
                    first_seen,
                    last_seen,
                    mitre_technique,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["rule_name"],
                    alert["severity"],
                    alert["username"],
                    alert["source_ip"],
                    alert["hostname"],
                    alert["failed_attempts"],
                    alert["first_seen"],
                    alert["last_seen"],
                    alert["mitre_technique"],
                    alert["status"],
                ),
            )

            if cursor.rowcount == 1:
                inserted_count += 1

    return inserted_count


def fetch_all_alerts(
    db_path: str | Path = DEFAULT_DB_PATH,
) -> list[dict[str, Any]]:
    """Return all stored alerts, newest first."""
    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                rule_name,
                severity,
                username,
                source_ip,
                hostname,
                failed_attempts,
                first_seen,
                last_seen,
                mitre_technique,
                status,
                analyst_notes,
                created_at
            FROM alerts
            ORDER BY id DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]
VALID_ALERT_STATUSES = {
    "new",
    "investigating",
    "resolved",
    "false_positive",
}


def update_alert(
    alert_id: int,
    status: str,
    analyst_notes: str,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> bool:
    """
    Update the status and analyst notes for one alert.

    Returns True when an alert was updated.
    """
    normalized_status = status.strip().lower()
    normalized_notes = analyst_notes.strip()

    if normalized_status not in VALID_ALERT_STATUSES:
        allowed_statuses = ", ".join(
            sorted(VALID_ALERT_STATUSES)
        )
        raise ValueError(
            f"Invalid alert status. Allowed values: "
            f"{allowed_statuses}"
        )

    with get_connection(db_path) as connection:
        cursor = connection.execute(
            """
            UPDATE alerts
            SET
                status = ?,
                analyst_notes = ?
            WHERE id = ?
            """,
            (
                normalized_status,
                normalized_notes,
                alert_id,
            ),
        )

    return cursor.rowcount == 1