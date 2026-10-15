# Insider Threat and Evidence Avoidance Detection System

A defensive cybersecurity and digital-forensics learning project that analyzes **synthetic audit logs** for unusual access patterns and possible evidence-handling anomalies. It is designed for coursework, hackathons, and local demonstrations.

## What it does
- Loads CSV audit events from a sample dataset
- Flags rule-based indicators such as repeated failed logins, unusual access times, bulk file deletions, repeated access-denied events, and activity involving sensitive paths
- Calculates a transparent risk score and lists the rules that contributed
- Shows an event timeline and findings in a Streamlit dashboard
- Exports analysis results as CSV and JSON

## Safety and limitations
- This is a **defensive triage aid**, not proof of malicious intent.
- Events can have legitimate explanations; analysts should validate alerts with independent evidence and organizational policy.
- It uses synthetic/sample audit data. Do not collect employee data or monitor systems without authorization.
- The “evidence avoidance” rules identify **possible indicators** such as audit-log clearing events or suspicious deletion patterns. They do not establish that evidence was intentionally concealed.
- No offensive actions, exploitation, or stealth features are included.

## Requirements
- Python 3.10+
- Optional dashboard packages listed in `requirements.txt`

## Windows setup (PowerShell)
Open PowerShell in this project directory:
```powershell
python --version
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
If script activation is blocked in this terminal:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Kali Linux setup
```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
If needed, install venv support with `sudo apt install python3-venv`.

## Run the command-line analyzer
Analyze the included dataset:
```bash
python analyzer.py --input data/sample_audit_logs.csv --output reports
```
Kali:
```bash
python3 analyzer.py --input data/sample_audit_logs.csv --output reports
```
The tool prints a summary and writes:
- `reports/findings.csv`
- `reports/analysis_summary.json`

## Run the dashboard
```bash
streamlit run dashboard.py
```
Choose the sample CSV in the sidebar and click **Analyze logs**. Findings, risk scores, charts, and the event timeline will appear.

## CSV format
The analyzer expects these columns:
- `timestamp` — ISO date/time
- `user` — synthetic or authorized account identifier
- `event_type` — e.g. `login_failed`, `file_deleted`, `file_access_denied`
- `resource` — file path or system resource
- `result` — e.g. `success`, `failure`, `denied`
- `source_ip` — source address or lab placeholder
- `details` — short event description

## Detection rules (transparent and configurable)
- 3+ failed logins by one user within a short time window
- 5+ file deletion events by one user within a short time window
- Access to sensitive-looking paths (e.g. `/finance/`, `/hr/`, `/evidence/`)
- Events indicating audit-log clearing or disabling
- Repeated access-denied events
- Access outside the configurable business-hours window

Rules produce **indicators for review**, not a definitive accusation. Tune thresholds to match your lab and organization's policies.

## Project structure
```text
Insider_Threat_Evidence_Avoidance_Detection_System/
├── analyzer.py
├── detection.py
├── dashboard.py
├── requirements.txt
├── README.md
├── data/
│   └── sample_audit_logs.csv
└── reports/
    └── .gitkeep
```
