import pandas as pd
import streamlit as st

from app.database import fetch_all_alerts, update_alert


STATUS_OPTIONS = [
    "new",
    "investigating",
    "resolved",
    "false_positive",
]

STATUS_LABELS = {
    "new": "New",
    "investigating": "Investigating",
    "resolved": "Resolved",
    "false_positive": "False Positive",
}

def count_affected_users(
    alerts_frame: pd.DataFrame,
) -> int:
    """Count unique accounts represented by the alerts."""
    users: set[str] = set()

    for _, alert in alerts_frame.iterrows():
        affected_accounts = str(
            alert.get("affected_accounts", "")
        ).strip()

        if affected_accounts:
            users.update(
                account.strip()
                for account in affected_accounts.split(",")
                if account.strip()
            )
            continue

        username = str(alert.get("username", "")).strip()

        if username and username != "multiple_accounts":
            users.add(username)

    return len(users)

st.set_page_config(
    page_title="Mini SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Mini SOC Alert-Triage Platform")
st.caption(
    "A security monitoring dashboard built with Python, "
    "SQLite, and synthetic event data."
)

if "flash_message" in st.session_state:
    st.success(st.session_state.pop("flash_message"))

alerts = fetch_all_alerts()

if not alerts:
    st.warning(
        "No alerts were found. Run `python3 run_detection.py` "
        "before opening the dashboard."
    )
    st.stop()

alerts_df = pd.DataFrame(alerts)

alerts_df["severity"] = (
    alerts_df["severity"]
    .fillna("unknown")
    .str.lower()
)

alerts_df["status"] = (
    alerts_df["status"]
    .fillna("new")
    .str.lower()
)

st.sidebar.header("Alert Filters")

available_severities = sorted(
    alerts_df["severity"].unique().tolist()
)

available_statuses = sorted(
    alerts_df["status"].unique().tolist()
)

selected_severities = st.sidebar.multiselect(
    "Severity",
    options=available_severities,
    default=available_severities,
    format_func=lambda value: value.replace(
        "_",
        " ",
    ).title(),
)

selected_statuses = st.sidebar.multiselect(
    "Status",
    options=available_statuses,
    default=available_statuses,
    format_func=lambda value: STATUS_LABELS.get(
        value,
        value.replace("_", " ").title(),
    ),
)

filtered_df = alerts_df[
    alerts_df["severity"].isin(selected_severities)
    & alerts_df["status"].isin(selected_statuses)
].copy()

total_alerts = len(filtered_df)

high_risk_alerts = int(
    filtered_df["severity"]
    .isin(["high", "critical"])
    .sum()
)

new_alerts = int(
    filtered_df["status"]
    .eq("new")
    .sum()
)

investigating_alerts = int(
    filtered_df["status"]
    .eq("investigating")
    .sum()
)

affected_users = count_affected_users(filtered_df)

metric_1, metric_2, metric_3, metric_4, metric_5 = (
    st.columns(5)
)

metric_1.metric(
    label="Total Alerts",
    value=total_alerts,
)

metric_2.metric(
    label="High / Critical",
    value=high_risk_alerts,
)

metric_3.metric(
    label="New Cases",
    value=new_alerts,
)

metric_4.metric(
    label="Investigating",
    value=investigating_alerts,
)

metric_5.metric(
    label="Affected Users",
    value=affected_users,
)

st.divider()

st.subheader("Alert Queue")

if filtered_df.empty:
    st.info("No alerts match the selected filters.")
    st.stop()

display_columns = [
    "id",
    "severity",
    "status",
    "rule_name",
    "username",
    "affected_accounts",
    "source_ip",
    "hostname",
    "failed_attempts",
    "mitre_technique",
    "first_seen",
    "last_seen",
    "created_at",
]

display_df = filtered_df[display_columns].copy()

display_df["severity"] = (
    display_df["severity"]
    .str.replace("_", " ")
    .str.title()
)

display_df["status"] = display_df["status"].map(
    lambda value: STATUS_LABELS.get(
        value,
        value.replace("_", " ").title(),
    )
)

display_df = display_df.rename(
    columns={
        "id": "Alert ID",
        "severity": "Severity",
        "status": "Status",
        "rule_name": "Detection Rule",
        "username": "Username",
        "affected_accounts": "Affected Accounts",
        "source_ip": "Source IP",
        "hostname": "Hostname",
        "failed_attempts": "Attempts",
        "mitre_technique": "MITRE ATT&CK",
        "first_seen": "First Seen",
        "last_seen": "Last Seen",
        "created_at": "Created At",
    }
)

st.dataframe(
    display_df,
    width="stretch",
    hide_index=True,
)

st.divider()

st.subheader("Case Investigation")

alert_ids = filtered_df["id"].astype(int).tolist()

selected_alert_id = st.selectbox(
    "Choose an alert ID",
    options=alert_ids,
    format_func=lambda alert_id: f"Alert #{alert_id}",
)

selected_alert = filtered_df[
    filtered_df["id"] == selected_alert_id
].iloc[0]

detail_1, detail_2 = st.columns(2)

with detail_1:
    st.write(
        "**Detection rule:**",
        selected_alert["rule_name"],
    )
    st.write(
        "**Severity:**",
        selected_alert["severity"].upper(),
    )
    st.write(
        "**Current status:**",
        STATUS_LABELS.get(
            selected_alert["status"],
            selected_alert["status"].title(),
        ),
    )
    st.write(
        "**Username:**",
        selected_alert["username"],
    )
    affected_accounts = (
        selected_alert.get("affected_accounts", "")
        or ""
    )

    if affected_accounts:
        st.write(
            "**Affected accounts:**",
            affected_accounts,
        )
    st.write(
        "**Source IP:**",
        selected_alert["source_ip"],
    )
    st.write(
        "**Hostname:**",
        selected_alert["hostname"],
    )

with detail_2:
    st.write(
        "**Failed attempts:**",
        int(selected_alert["failed_attempts"]),
    )
    st.write(
        "**MITRE ATT&CK:**",
        selected_alert["mitre_technique"],
    )
    st.write(
        "**First seen:**",
        selected_alert["first_seen"],
    )
    st.write(
        "**Last seen:**",
        selected_alert["last_seen"],
    )
    st.write(
        "**Created at:**",
        selected_alert["created_at"],
    )

current_status = selected_alert["status"]

if current_status not in STATUS_OPTIONS:
    STATUS_OPTIONS.append(current_status)

current_status_index = STATUS_OPTIONS.index(
    current_status
)

current_notes = selected_alert["analyst_notes"] or ""

with st.form(
    key=f"investigation_form_{selected_alert_id}"
):
    new_status = st.selectbox(
        "Case Status",
        options=STATUS_OPTIONS,
        index=current_status_index,
        format_func=lambda value: STATUS_LABELS.get(
            value,
            value.replace("_", " ").title(),
        ),
    )

    analyst_notes = st.text_area(
        "Analyst Notes",
        value=current_notes,
        height=180,
        placeholder=(
            "Document what you investigated, what evidence "
            "you reviewed, and why you chose this status."
        ),
    )

    submitted = st.form_submit_button(
        "Save Investigation",
        type="primary",
        use_container_width=True,
    )

if submitted:
    try:
        updated = update_alert(
            alert_id=int(selected_alert_id),
            status=new_status,
            analyst_notes=analyst_notes,
        )
    except ValueError as error:
        st.error(str(error))
    else:
        if updated:
            st.session_state["flash_message"] = (
                f"Alert #{selected_alert_id} was updated."
            )
            st.rerun()
        else:
            st.error(
                "The alert could not be found in the database."
            )