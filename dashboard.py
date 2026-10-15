"""Streamlit dashboard for synthetic or authorized audit logs."""
from pathlib import Path
import json
import pandas as pd
import streamlit as st
import altair as alt
from detection import analyze_events, REQUIRED_COLUMNS

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "data" / "sample_audit_logs.csv"

st.set_page_config(page_title="Insider Threat Triage", page_icon="🛡️", layout="wide")
st.title("🛡️ Insider Threat & Evidence Avoidance Detection")
st.caption("Defensive audit-log triage using transparent rules. Alerts are indicators for review, not proof of wrongdoing.")

with st.sidebar:
    st.header("Input and settings")
    uploaded = st.file_uploader("Upload audit-log CSV", type=["csv"])
    source_mode = st.radio("Data source", ["Included sample data", "Upload my CSV"])
    failed_threshold = st.slider("Failed-login threshold (15 min)", 1, 10, 3)
    delete_threshold = st.slider("Deletion threshold (15 min)", 1, 20, 5)
    st.caption("Timestamps are interpreted in UTC in this demo.")

try:
    if source_mode == "Upload my CSV":
        if uploaded is None:
            st.info("Upload a CSV to begin. Required columns: " + ", ".join(REQUIRED_COLUMNS))
            st.stop()
        data = pd.read_csv(uploaded)
    else:
        data = pd.read_csv(SAMPLE)

    st.subheader("Audit events")
    st.dataframe(data, use_container_width=True, hide_index=True)

    if st.button("Analyze logs", type="primary"):
        findings, summary = analyze_events(
            data,
            failed_login_threshold=failed_threshold,
            deletion_threshold=delete_threshold,
        )
        st.session_state["findings"] = findings
        st.session_state["summary"] = summary

    if "findings" in st.session_state:
        findings = st.session_state["findings"]
        summary = st.session_state["summary"]
        a, b, c = st.columns(3)
        a.metric("Events analyzed", summary["events_analyzed"])
        b.metric("Findings", summary["findings_count"])
        c.metric("Users with findings", summary["users_with_findings"])

        if findings.empty:
            st.success("No configured indicators detected in this dataset.")
        else:
            st.warning("Review findings in context. A risk score is a heuristic and does not establish intent.")
            st.subheader("Findings")
            st.dataframe(findings, use_container_width=True, hide_index=True)

            left, right = st.columns(2)
            with left:
                st.markdown("**Findings by severity**")
                sev = findings.groupby("severity", as_index=False).size()
                chart = alt.Chart(sev).mark_bar().encode(
                    x=alt.X("severity:N", sort=["Critical", "High", "Medium", "Low"], title="Severity"),
                    y=alt.Y("size:Q", title="Count"),
                    tooltip=["severity", "size"]
                )
                st.altair_chart(chart, use_container_width=True)
            with right:
                st.markdown("**Findings by rule**")
                rules = findings.groupby("rule", as_index=False).size().sort_values("size", ascending=False)
                chart = alt.Chart(rules).mark_bar().encode(
                    x=alt.X("size:Q", title="Count"),
                    y=alt.Y("rule:N", sort="-x", title="Detection rule"),
                    tooltip=["rule", "size"]
                )
                st.altair_chart(chart, use_container_width=True)

            st.subheader("Event timeline")
            timeline = findings.copy()
            timeline["timestamp"] = pd.to_datetime(timeline["timestamp"], utc=True)
            st.line_chart(timeline.set_index("timestamp").resample("1h")["risk_points"].sum())

            st.download_button(
                "Download findings CSV",
                findings.to_csv(index=False).encode("utf-8"),
                file_name="findings.csv",
                mime="text/csv"
            )
            st.download_button(
                "Download summary JSON",
                json.dumps(summary, indent=2).encode("utf-8"),
                file_name="analysis_summary.json",
                mime="application/json"
            )
except Exception as exc:
    st.error(f"Could not analyze data: {exc}")
