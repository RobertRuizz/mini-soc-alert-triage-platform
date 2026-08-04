import pandas as pd
import streamlit as st

from app.database import fetch_all_alerts


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

alerts = fetch_all_alerts()

if not alerts:
    st.warning(
        "No alerts were found. Run `python3 run_detection.py` "
        "before opening the dashboard."
    )
    st.stop()

alerts_df = pd.DataFrame(alerts)

alerts_df["severity"] = alerts_df["severity"].str.lower()
alerts_df["status"] = alerts_df["status"].str.lower()

st.sidebar.header("Alert Filters")

available_severities = sorted(
    alerts_df["severity"].dropna().unique().tolist()
)

available_statuses = sorted(
    alerts_df["status"].dropna().unique().tolist()
)

selected_severities = st.sidebar.multiselect(
    "Severity",
    options=available_severities,
    default=available_severities,
)

selected_statuses = st.sidebar.multiselect(
    "Status",
    options=available_statuses,
    default=available_statuses,
)

filtered_df = alerts_df[
    alerts_df["severity"].isin(selected_severities)
    & alerts_df["status"].isin(selected_statuses)
].copy()

total_alerts = len(filtered_df)

high_alerts = (
    filtered_df["severity"]
    .eq("high")
    .sum()
)

new_alerts = (
    filtered_df["status"]
    .eq("new")
    .sum()
)

affected_users = filtered_df["username"].nunique()

metric_1, metric_2, metric_3, metric_4 = st.columns(4)

metric_1.metric(
    label="Total Alerts",
    value=total_alerts,
)

metric_2.metric(
    label="High Severity",
    value=int(high_alerts),
)

metric_3.metric(
    label="New Cases",
    value=int(new_alerts),
)

metric_4.metric(
    label="Affected Users",
    value=affected_users,
)

st.divider()

st.subheader("Alert Queue")

if filtered_df.empty:
    st.info("No alerts match the selected filters.")
else:
    display_columns = [
        "id",
        "severity",
        "status",
        "rule_name",
        "username",
        "source_ip",
        "hostname",
        "failed_attempts",
        "mitre_technique",
        "first_seen",
        "last_seen",
        "created_at",
    ]

    display_df = filtered_df[display_columns].rename(
        columns={
            "id": "Alert ID",
            "severity": "Severity",
            "status": "Status",
            "rule_name": "Detection Rule",
            "username": "Username",
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

st.subheader("Selected Alert Details")

alert_ids = filtered_df["id"].tolist()

if alert_ids:
    selected_alert_id = st.selectbox(
        "Choose an alert ID",
        options=alert_ids,
    )

    selected_alert = filtered_df[
        filtered_df["id"] == selected_alert_id
    ].iloc[0]

    detail_1, detail_2 = st.columns(2)

    with detail_1:
        st.write("**Detection rule:**", selected_alert["rule_name"])
        st.write("**Severity:**", selected_alert["severity"].upper())
        st.write("**Status:**", selected_alert["status"].upper())
        st.write("**Username:**", selected_alert["username"])
        st.write("**Source IP:**", selected_alert["source_ip"])
        st.write("**Hostname:**", selected_alert["hostname"])

    with detail_2:
        st.write(
            "**Failed attempts:**",
            selected_alert["failed_attempts"],
        )
        st.write(
            "**MITRE ATT&CK:**",
            selected_alert["mitre_technique"],
        )
        st.write("**First seen:**", selected_alert["first_seen"])
        st.write("**Last seen:**", selected_alert["last_seen"])
        st.write("**Created at:**", selected_alert["created_at"])

    notes = selected_alert.get("analyst_notes", "")

    st.text_area(
        "Analyst Notes",
        value=notes,
        disabled=True,
        help=(
            "Editing and saving investigation notes "
            "will be added in the next phase."
        ),
    )