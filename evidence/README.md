# Synthetic evidence pack

> © 2026 Denis Dallas. Licensed under [CC BY 4.0](../LICENSE-CC-BY-4.0). For reuse, credit Denis Dallas, SOC & DFIR Investigations, link to the repository and license, and indicate changes.
Every record in this folder is fictional and exists only to support the portfolio case studies. This is a normalized event summary, not a raw log export or real incident evidence. It contains no real credentials, personal data, malware, or usable threat-intelligence feed.

## Dataset

- [events.csv](events.csv) contains the illustrative timeline events from the three reports.
- Times are time-of-day UTC values copied from the reports; no incident date is asserted.
- Example domains and RFC 5737 documentation IP addresses are reserved examples.
- Encoded command-line content and session token values are intentionally omitted.
- Assessments distinguish observed events, user reports, anomalies, and response actions. An event marked observed does not prove a broader conclusion such as data theft.

## Render a case

Run this command from the repository root:

~~~sh
python scripts/summarize_case.py INC-01
~~~

Use INC-02 or INC-03 for the other cases. The command requires only Python 3 and the standard library. GitHub Actions runs the same command for all three cases.

## Data dictionary

| Field | Meaning |
|---|---|
| case_id | Fictional report identifier: INC-01, INC-02, or INC-03 |
| time_utc | Illustrative time-of-day in UTC; not a real-world date or timestamp |
| source | Simulated log or response source |
| asset | Fictional host, account scope, or system |
| identity | Fictional account when relevant |
| source_ip | Reserved documentation IP, when specified |
| destination | Reserved example domain or documentation IP, when relevant |
| event_type | Normalized event label for investigation exercises |
| observation | Concise statement aligned to the case report |
| assessment | Evidence status or response-action label |

## Case links

- [Incident 01 — Phishing and Account Compromise](../incidents/01-phishing-account-compromise.md)
- [Incident 02 — Ransomware and Digital Forensics](../incidents/02-ransomware-investigation.md)
- [Incident 03 — Network Intrusion and Simulated Data Exfiltration](../incidents/03-network-intrusion-data-exfiltration.md)

See [query examples](../queries/README.md). These artifacts are for training and review only; do not block, alert on, or attribute activity based on this synthetic dataset.
