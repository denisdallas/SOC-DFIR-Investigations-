# Incident 02 — Ransomware Incident and Digital Forensics

> © 2026 Denis Dallas. Licensed under [CC BY 4.0](../LICENSE-CC-BY-4.0). For reuse, credit Denis Dallas, SOC & DFIR Investigations, link to the repository and license, and indicate changes.
<sub>Fictional portfolio simulation · DFIR investigation · Severity: Critical (simulated)</sub>

> **Disclaimer:** This is a fictional defensive training scenario. No real organization, victim, malware sample, or threat actor is represented. IP addresses use RFC 5737 documentation ranges; domains use reserved example domains. No operational malware or valid threat-intelligence hashes are provided.

## 1. Executive summary

A fictional organization reports that several Windows workstations have become unavailable and display ransom-note-style messages. Endpoint telemetry indicates suspicious script execution followed by rapid file modification activity on a subset of hosts. File-server monitoring records a concurrent increase in write operations from one affected workstation.

The simulated evidence supports a ransomware-like event affecting multiple endpoints. The exact initial access vector, malware family, operator identity, and whether data was stolen before encryption are **not established**. The investigation therefore separates observed encryption-like behavior from unverified claims that may appear in a ransom note.

**Severity rationale:** Critical, because multiple business endpoints and shared data availability are affected.

## 2. Scope and objectives

**In-scope assets**
- Fictional workstation `FIN-WS-022`
- Fictional workstation `OPS-WS-008`
- Fictional file server `FS-01`
- Endpoint detection and response (EDR) alerts
- Windows event logs, file-system metadata, and network telemetry

**Objectives**
- Establish affected systems and the incident time window.
- Preserve volatile and non-volatile evidence where safe and feasible.
- Reconstruct the observed execution and file-impact sequence.
- Determine whether lateral movement or data staging is evidenced.
- Contain spread and support safe recovery.

## 3. Simulated timeline

All timestamps are illustrative UTC.

| Time (UTC) | Event | Evidence / confidence |
|---|---|---|
| 02:13 | Unusual PowerShell process starts on `FIN-WS-022` | EDR process telemetry; observed |
| 02:14 | Script launches child process with encoded command-line content | Process telemetry; observed |
| 02:16 | High-volume file rename/write activity begins | File-server and endpoint telemetry; observed |
| 02:19 | Ransom-note-style text file appears in affected directories | File-system artifact; observed |
| 02:22 | Similar file modification behavior appears on `OPS-WS-008` | EDR telemetry; observed |
| 02:27 | File server records abnormal write volume from `FIN-WS-022` | Server audit telemetry; observed |
| 02:31 | SOC isolates affected workstations from the network | Response action |
| 02:45 | File-server write access from affected endpoints is restricted | Response action |
| 03:10 | Backup integrity and isolation checks begin | Recovery action |

The timeline establishes a sequence of suspicious execution and file-impact events. It does not independently establish how the initial code reached the first endpoint.

## 4. Evidence sources and forensic methodology

| Evidence ID | Source | Investigative value |
|---|---|---|
| R-01 | EDR process tree and alert metadata | Parent-child process relationships, command lines, timestamps |
| R-02 | Windows Security and PowerShell logs | Logon, process, script-block, and policy events where enabled |
| R-03 | File-system metadata and selected samples | Rename/write patterns, timestamps, ransom-note artifacts |
| R-04 | File-server audit and access logs | Source host, account, share access, write activity |
| R-05 | DNS, firewall, and proxy logs | External communications and unusual internal connections |
| R-06 | Backup platform audit records | Backup availability, deletion attempts, and restore-point integrity |

**Forensic workflow**
1. Declare the incident and establish a UTC-normalized timeline.
2. Isolate affected endpoints using EDR or network controls while preserving evidence where operationally safe.
3. Capture volatile data when feasible and authorized; document any delay or destructive containment action.
4. Acquire forensic images or targeted collections using approved tooling and write-protection procedures.
5. Calculate cryptographic hashes of acquired evidence and verify working-copy integrity.
6. Analyze process execution, persistence locations, scheduled tasks, services, logons, and file-system artifacts.
7. Correlate endpoint events with server, identity, DNS, firewall, and backup logs.
8. Maintain a chain-of-custody record for every evidence item.

Do not power off a system reflexively if volatile evidence is important and safe isolation is available. Follow the incident commander and forensic lead's approved playbook.

## 5. Simulated indicators

| Type | Value | Context |
|---|---|---|
| Host | `FIN-WS-022` | Fictional affected workstation |
| Host | `OPS-WS-008` | Fictional affected workstation |
| Server | `FS-01` | Fictional file server |
| Process | `powershell.exe` | Legitimate binary observed in suspicious execution context |
| File artifact | `RECOVERY_INSTRUCTIONS.txt` | Synthetic ransom-note-style filename |
| IPv4 | `203.0.113.77` | Documentation-only address; unverified simulated network lead |

No malware hash is included. A placeholder hash is not a real sample fingerprint and must never be used as an operational blocklist entry.

## 6. Analysis and findings

### Observed in the simulation
- Suspicious PowerShell execution occurred on `FIN-WS-022`.
- The process tree included encoded command-line content.
- A high rate of file writes and renames followed.
- A ransom-note-style artifact appeared in affected directories.
- Similar file-impact behavior was recorded on a second workstation.
- The file server recorded abnormal write activity associated with an affected endpoint.

### Assessment
The combined endpoint and file-server telemetry is consistent with ransomware-like activity. Multiple affected systems and shared-storage write activity justify a Critical severity classification in this simulated environment.

### Not established
- The initial access mechanism.
- Whether the PowerShell process was the original payload or a later-stage component.
- The malware family or operator.
- Whether credentials were stolen or used for lateral movement.
- Whether the documentation-only IP was actually contacted by the suspicious process.
- Whether data was exfiltrated before encryption.
- Whether backups were accessed or tampered with absent corroborating backup audit records.

A ransom note is an attacker-controlled claim and must not be treated as proof of data theft.

## 7. MITRE ATT&CK mapping

| Technique | ID | Simulated relevance |
|---|---|---|
| PowerShell | T1059.001 | Suspicious PowerShell execution |
| Obfuscated Files or Information | T1027 | Encoded command-line content; requires deeper validation |
| Data Encrypted for Impact | T1486 | File modification pattern consistent with encryption impact |
| Inhibit System Recovery | T1490 | Investigative check for shadow-copy or backup deletion; not confirmed |
| Network Share Discovery | T1135 | Relevant check if discovery commands or telemetry are found |
| Lateral Tool Transfer | T1570 | Not established; investigate before mapping as executed |

Technique mapping reflects observed behavior and investigative leads. It does not imply every listed technique was confirmed.

## 8. Containment, eradication, and recovery

### Containment
- Isolate affected endpoints from wired and wireless networks.
- Restrict affected accounts and revoke sessions if credential compromise is suspected.
- Temporarily disable or tightly restrict affected file shares.
- Block verified malicious indicators only after validating them against trusted evidence.
- Protect backup infrastructure from affected networks and identities.
- Preserve logs and evidence before retention windows expire.

### Eradication
- Identify and remove the initial access mechanism once established.
- Rebuild compromised endpoints from known-good, trusted images where appropriate.
- Rotate credentials and service secrets that may have been exposed.
- Review privileged access, scheduled tasks, services, startup locations, and remote-management tooling.
- Patch exploited vulnerabilities and close exposed remote-access paths.
- Validate that persistence and unauthorized access paths have been removed before reconnection.

### Recovery
- Restore from offline or immutable backups that have passed integrity checks.
- Prioritize critical business services and validate restored data with system owners.
- Reconnect systems in controlled stages with heightened EDR and network monitoring.
- Monitor for renewed encryption-like activity, suspicious authentication, and unexpected share writes.
- Maintain a documented decision log for restoration and business sign-off.

Do not pay a ransom or communicate with an extortion operator without executive, legal, law-enforcement, and specialist incident-response guidance.

## 9. Remediation and lessons learned

**Preventive controls**
- Enforce least privilege and separate workstation and server administration.
- Restrict PowerShell and script execution using application control and appropriate logging.
- Deploy EDR with tamper protection and behavioral detections.
- Segment user endpoints from critical servers and backup networks.
- Require MFA for remote access and privileged identities.
- Patch internet-facing systems and remove unnecessary remote services.

**Resilience controls**
- Maintain offline or immutable backups with separate administrative credentials.
- Test restoration regularly, including application and business-process validation.
- Monitor backup deletion, retention-policy changes, and unusual restore activity.
- Maintain a current asset inventory and recovery priority list.

**Detection opportunities**
- Sudden high-rate file rename/write behavior across many directories.
- Script interpreters spawning unusual child processes.
- One workstation writing to many shared folders in a short interval.
- Unexpected changes to shadow copies, backup services, or recovery configuration.
- New remote logons or administrative share access preceding file-impact events.

## 10. Conclusion

The simulated evidence supports a multi-endpoint ransomware-like incident with impact to shared storage. Network isolation, access restriction, evidence preservation, credential review, and validated restoration are the principal response priorities. Initial access, actor attribution, and data exfiltration remain unconfirmed and require additional evidence.

## 11. Evidence limitations

This report contains no real disk image, memory capture, malware sample, or production log export. The scenario is designed to demonstrate defensible DFIR reasoning, evidence handling, and recovery planning—not to represent a completed real-world investigation.

## Reproducible sample evidence

The corresponding fictional timeline is available in the [normalized sample events](../evidence/events.csv) and [evidence guide](../evidence/README.md). From the repository root, run `python scripts/summarize_case.py INC-02` to review it. The [defensive Sigma example](../detections/incident-02-encoded-powershell.yml) is illustrative and should be tuned for a real environment; see the [query examples](../queries/README.md).
