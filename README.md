# SOC & Digital Forensics and Incident Response Investigations

A portfolio of structured, fictional security-incident investigations demonstrating Security Operations Center (SOC), incident response, and digital forensics workflows.

> **Portfolio disclaimer:** Every incident in this repository is a fictional simulation created for educational and portfolio demonstration purposes. These reports do not describe real organizations, victims, investigations, or threat actors. Indicators of compromise (IoCs), timestamps, hostnames, and event details are synthetic. IP addresses use documentation-only ranges and domains use reserved example domains. Placeholder hashes are not valid threat intelligence and must not be used for blocking or detection.

## Case studies

| # | Investigation | Focus areas | Report |
|---|---|---|---|
| 01 | Phishing and Account Compromise | Email analysis, identity logs, account takeover, persistence review, containment | [Read report](incidents/01-phishing-account-compromise.md) |
| 02 | Ransomware Incident and Digital Forensics | Endpoint triage, execution chain, host forensics, impact assessment, recovery | [Read report](incidents/02-ransomware-investigation.md) |
| 03 | Network Intrusion and Simulated Data Exfiltration | Network telemetry, lateral movement hypotheses, egress analysis, data exposure assessment | [Read report](incidents/03-network-intrusion-data-exfiltration.md) |

## Investigation approach

Each case study follows a repeatable incident-response structure:

1. **Triage and scope** — establish the reported alert, affected assets, business impact, and investigation boundaries.
2. **Evidence preservation** — identify relevant logs and artifacts, preserve originals, record collection details, and maintain chain-of-custody discipline.
3. **Analysis** — correlate endpoint, identity, email, and network telemetry; distinguish directly observed facts from hypotheses.
4. **Assessment** — document timeline, severity, confidence, IoCs, and MITRE ATT&CK technique mapping.
5. **Response** — recommend containment, eradication, recovery, and validation actions.
6. **Lessons learned** — prioritize preventive and detective controls and identify remaining evidence gaps.

## Evidence-handling principles

- Preserve source evidence and work from verified copies.
- Record acquisition time, source, collector, method, and integrity checks.
- Normalize timestamps to UTC while retaining original timestamps and timezone context where available.
- Correlate independent telemetry before drawing conclusions.
- Label assumptions, unverified leads, and evidence gaps explicitly.
- Avoid attribution unless supported by reliable evidence.
- Distinguish attempted activity, confirmed access, confirmed execution, and confirmed data transfer.

## Synthetic indicator conventions

- Documentation IP ranges: `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` (RFC 5737 TEST-NET).
- Example domains: `example.com`, `example.net`, and `example.org`.
- Hash values, where shown, are clearly marked placeholders and are not usable indicators.
- All usernames, organizations, devices, and event records are fictional.

## MITRE ATT&CK

Technique references are included to demonstrate structured behavioral mapping. A mapping indicates that the simulated behavior is consistent with a technique; it is not proof that a real adversary used it. See [MITRE ATT&CK](https://attack.mitre.org/).

## Repository structure

~~~text
SOC-DFIR-Investigations-/
├── .github/workflows/evidence-pack.yml
├── README.md
├── detections/incident-02-encoded-powershell.yml
├── evidence/
│   ├── README.md
│   └── events.csv
├── incidents/
│   ├── 01-phishing-account-compromise.md
│   ├── 02-ransomware-investigation.md
│   └── 03-network-intrusion-data-exfiltration.md
├── queries/README.md
├── scripts/summarize_case.py
└── tests/test_evidence_pack.py
~~~

## Scope and responsible use

These are defensive, educational case studies. They focus on detection, investigation, evidence handling, containment, and recovery. Synthetic indicators must not be treated as live threat intelligence. No real personal data, credentials, malware samples, or victim information are included.

## Author

**Denis Dallas**  
GitHub: [@denisdallas](https://github.com/denisdallas)


## Reproduce a case timeline

From the repository root, render the synthetic timeline for any case:

~~~sh
python scripts/summarize_case.py INC-01
~~~

Use `INC-02` or `INC-03` for the other scenarios. The command uses only the Python standard library and prints the fictional events, sources, and assessment labels. Run `python -m unittest discover -s tests -v` for regression checks on the dataset and renderer; GitHub Actions runs those checks and renders all three cases.

Explore the [evidence pack](evidence/README.md), [investigation queries](queries/README.md), and [defensive Sigma example](detections/incident-02-encoded-powershell.yml). The dataset is a readable summary of the published timelines, not raw telemetry or real incident evidence.
