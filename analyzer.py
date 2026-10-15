"""CLI entry point for the Insider Threat and Evidence Avoidance Detection System."""
import argparse
import json
from pathlib import Path
import pandas as pd
from detection import analyze_events


def main():
    parser = argparse.ArgumentParser(description="Analyze authorized audit logs for defensive triage indicators.")
    parser.add_argument("--input", required=True, help="Path to audit-log CSV")
    parser.add_argument("--output", default="reports", help="Output directory (default: reports)")
    parser.add_argument("--failed-login-threshold", type=int, default=3)
    parser.add_argument("--deletion-threshold", type=int, default=5)
    args = parser.parse_args()

    source = Path(args.input)
    if not source.exists():
        parser.error(f"Input file not found: {source}")
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(source)
    findings, summary = analyze_events(
        df,
        failed_login_threshold=max(1, args.failed_login_threshold),
        deletion_threshold=max(1, args.deletion_threshold),
    )

    csv_path = output_dir / "findings.csv"
    json_path = output_dir / "analysis_summary.json"
    findings.to_csv(csv_path, index=False)
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n=== INSIDER THREAT TRIAGE SUMMARY ===")
    print(f"Events analyzed      : {summary['events_analyzed']}")
    print(f"Findings             : {summary['findings_count']}")
    print(f"Users with findings  : {summary['users_with_findings']}")
    print(f"Severity counts      : {summary['severity_counts']}")
    print(f"Findings CSV         : {csv_path.resolve()}")
    print(f"Summary JSON         : {json_path.resolve()}")
    print("\nReminder: validate indicators with context; do not treat them as proof.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
