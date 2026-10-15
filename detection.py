"""Transparent rule-based analysis of audit events."""
from __future__ import annotations
from datetime import time
import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp", "user", "event_type", "resource", "result", "source_ip", "details"
]

SENSITIVE_TERMS = ("/finance/", "/hr/", "/evidence/", "/legal/", "confidential")
AUDIT_TAMPER_TERMS = ("audit_log_cleared", "logging_disabled", "audit_log_deleted")


def analyze_events(df: pd.DataFrame, failed_login_threshold: int = 3,
                   deletion_threshold: int = 5,
                   business_start: int = 7, business_end: int = 20) -> tuple[pd.DataFrame, dict]:
    """Return one finding per flagged event and a summary dictionary."""
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError("Missing required CSV columns: " + ", ".join(missing))

    work = df.copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"], errors="coerce", utc=True)
    work = work.dropna(subset=["timestamp"]).copy()
    for col in ["user", "event_type", "resource", "result", "source_ip", "details"]:
        work[col] = work[col].fillna("").astype(str)
    work["event_type_norm"] = work["event_type"].str.lower().str.strip()
    work["resource_norm"] = work["resource"].str.lower()
    work["details_norm"] = work["details"].str.lower()

    # Count activity in a rolling 15-minute window per user.
    work = work.sort_values("timestamp").reset_index(drop=True)
    findings = []
    user_events = {user: group for user, group in work.groupby("user", sort=False)}

    def add_finding(row, rule, severity, points, explanation):
        findings.append({
            "timestamp": row["timestamp"].isoformat(),
            "user": row["user"],
            "event_type": row["event_type"],
            "resource": row["resource"],
            "source_ip": row["source_ip"],
            "rule": rule,
            "severity": severity,
            "risk_points": points,
            "explanation": explanation,
            "analyst_note": "Indicator only; validate with authorized records and context."
        })

    for user, group in user_events.items():
        group = group.sort_values("timestamp")
        for idx, row in group.iterrows():
            current_time = row["timestamp"]
            window = group[
                (group["timestamp"] >= current_time - pd.Timedelta(minutes=15)) &
                (group["timestamp"] <= current_time)
            ]
            et = row["event_type_norm"]
            resource = row["resource_norm"]
            details = row["details_norm"]

            if et in {"login_failed", "failed_login", "authentication_failure"}:
                count = int(window["event_type_norm"].isin(
                    {"login_failed", "failed_login", "authentication_failure"}
                ).sum())
                if count >= failed_login_threshold:
                    add_finding(row, "Repeated failed logins", "High", 25,
                                f"{count} failed login events for this account within 15 minutes.")

            if et in {"file_deleted", "file_delete", "delete"}:
                count = int(window["event_type_norm"].isin(
                    {"file_deleted", "file_delete", "delete"}
                ).sum())
                if count >= deletion_threshold:
                    add_finding(row, "High-volume file deletion", "High", 30,
                                f"{count} deletion events for this account within 15 minutes.")

            if any(term in resource for term in SENSITIVE_TERMS):
                add_finding(row, "Sensitive-path access", "Medium", 15,
                            "The resource path matches a configured sensitive-path keyword.")

            if any(term in et or term in details for term in AUDIT_TAMPER_TERMS):
                add_finding(row, "Audit logging change indicator", "Critical", 40,
                            "The event name or details mention audit-log clearing/deletion or logging being disabled.")

            if et in {"file_access_denied", "access_denied", "permission_denied"} or row["result"].lower() == "denied":
                denied_count = int(window[
                    (window["event_type_norm"].isin(
                        {"file_access_denied", "access_denied", "permission_denied"}
                    )) | (window["result"].str.lower() == "denied")
                ].shape[0])
                if denied_count >= 3:
                    add_finding(row, "Repeated access denied", "Medium", 15,
                                f"{denied_count} denied-access events for this account within 15 minutes.")

            # Interpret timestamps in UTC for this demo; configure local timezone before real use.
            hour = int(row["timestamp"].hour)
            if hour < business_start or hour >= business_end:
                add_finding(row, "Outside configured business hours", "Low", 5,
                            f"Event occurred at {hour:02d}:00 UTC, outside configured hours {business_start:02d}:00–{business_end:02d}:00 UTC.")

    findings_df = pd.DataFrame(findings)
    if not findings_df.empty:
        findings_df = findings_df.drop_duplicates(
            subset=["timestamp", "user", "event_type", "resource", "rule"]
        )
        findings_df = findings_df.sort_values(["risk_points", "timestamp"], ascending=[False, True])
        # Transparent aggregate risk score per account, capped at 100.
        findings_df["user_risk_score"] = findings_df.groupby("user")["risk_points"].transform("sum").clip(upper=100)
    else:
        findings_df = pd.DataFrame(columns=[
            "timestamp", "user", "event_type", "resource", "source_ip", "rule",
            "severity", "risk_points", "explanation", "analyst_note", "user_risk_score"
        ])

    summary = {
        "events_analyzed": int(len(work)),
        "findings_count": int(len(findings_df)),
        "users_with_findings": int(findings_df["user"].nunique()) if not findings_df.empty else 0,
        "severity_counts": (
            findings_df["severity"].value_counts().to_dict() if not findings_df.empty else {}
        ),
        "rule_counts": (
            findings_df["rule"].value_counts().to_dict() if not findings_df.empty else {}
        ),
        "note": "Risk scores are heuristic triage signals, not proof of malicious intent."
    }
    return findings_df, summary
