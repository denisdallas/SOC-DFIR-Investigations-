# Incident 01 — Phishing and Account Compromise

<sub>Fictional portfolio simulation · SOC investigation · Severity: High (simulated)</sub>

> **Disclaimer:** This is a fictional training scenario. All entities, accounts, events, timestamps, and indicators are synthetic. IP addresses are from RFC 5737 documentation ranges; domains are reserved examples. Any hash value would be a placeholder, not a valid IoC.

## 1. Executive summary

A simulated employee reports receiving a convincing credential-harvesting email and subsequently noticing an unfamiliar sign-in notification. The SOC correlates the email artifact with identity-provider sign-in records and endpoint browser activity. The simulated evidence supports that the user interacted with a phishing link and that a suspicious authentication session was established from an unfamiliar source address.

The investigation treats the account compromise as **confirmed within the simulation**, while the extent of mailbox access, message collection, and downstream access remains subject to the evidence available. No evidence in this scenario establishes that sensitive files were downloaded or that the activity was attributable to a specific threat actor.

**Severity rationale:** High, because a valid user identity appears to have been compromised and could provide access to internal resources.

## 2. Incident scope and objectives

**In-scope assets**
- One fictional employee identity: `alex.morgan@example.com`
- One managed workstation: `WS-014`
- Corporate email and identity-provider audit records
- Browser history and endpoint security telemetry relevant to the reported time window

**Objectives**
- Establish whether the message was malicious.
- Determine whether the user interacted with the link and submitted credentials.
- Identify suspicious authentication and session activity.
- Determine the known scope of account access.
- Recommend containment, recovery, and control improvements.

**Out of scope:** Attribution, access to unrelated employee accounts, and claims of data theft without supporting telemetry.

## 3. Simulated incident timeline

All times are illustrative UTC timestamps.

| Time (UTC) | Event | Assessment |
|---|---|---|
| 08:42 | Employee receives an unexpected document-sharing notification | Reported / email artifact |
| 08:47 | Message link redirects to `https://login-check.example.com/` | Suspicious URL observed |
| 08:49 | Browser telemetry records navigation to the example domain | Interaction observed |
| 08:51 | Identity logs record a successful sign-in from `198.51.100.24` | Suspicious authentication |
| 08:54 | New session token issued for the account | Session activity observed |
| 09:06 | User reports an unfamiliar sign-in notification | User report |
| 09:12 | SOC disables active sessions and begins account containment | Response action |
| 09:25 | Password reset and MFA re-registration initiated | Response action |

The sequence is consistent with credential phishing followed by unauthorized account access. Exact credential-submission mechanics are not asserted unless supported by a captured form submission or equivalent evidence.

## 4. Evidence sources and forensic methodology

| Evidence ID | Source | Purpose | Handling |
|---|---|---|---|
| E-01 | Original email with headers | Sender, routing, authentication results, URL extraction | Preserve original message and calculate hash on acquisition |
| E-02 | Identity-provider sign-in and audit logs | Authentication outcome, source IP, device, session events | Export read-only; retain provider timestamps |
| E-03 | Endpoint/browser history | Confirm navigation and local artifacts | Acquire through approved endpoint collection |
| E-04 | Email security gateway logs | Delivery, URL rewriting, verdict, other recipients | Export relevant time range |
| E-05 | Endpoint detection telemetry | Browser process and suspicious follow-on activity | Preserve alert details and raw event records |

**Method**
1. Establish the incident window from the user report and earliest related alert.
2. Preserve the original email, headers, and provider audit records.
3. Extract URLs and sender metadata without opening suspicious content on a production endpoint.
4. Correlate identity events with endpoint and gateway timestamps.
5. Review session creation, MFA events, mailbox rules, delegated access, and OAuth consent changes.
6. Record findings with evidence references and confidence levels.

A production investigation should record collector identity, acquisition method, system clock/timezone, file hashes, storage location, and every evidence transfer in a chain-of-custody log.

## 5. Simulated IoCs

| Type | Value | Context |
|---|---|---|
| URL | `https://login-check.example.com/` | Simulated credential-harvesting landing page |
| Domain | `login-check.example.com` | Reserved example domain |
| IPv4 | `198.51.100.24` | Documentation-only source address |
| Email subject | `Shared document requires verification` | Synthetic lure subject |
| Account | `alex.morgan@example.com` | Fictional identity |

**Hash note:** No real malware or message hash is supplied. Any hash placeholder added to a training dataset must be labelled non-operational and must not be ingested as a threat indicator.

## 6. Analysis and findings

### Confirmed within the simulation
- A suspicious email was delivered to the fictional user.
- The message contained a link to a reserved example domain.
- Browser telemetry records navigation to that domain.
- Identity logs record a successful sign-in from a documentation-only IP address that is unfamiliar in the scenario.
- The user reported an unexpected sign-in notification.

### Assessment
The correlation between the phishing message, browser navigation, and unfamiliar successful authentication supports a high-confidence simulated account-compromise finding.

### Not established
- Whether the user entered credentials into the landing page, absent direct form telemetry or equivalent corroboration.
- Whether the mailbox contents were read, searched, or exported.
- Whether the session accessed other applications or resources.
- Whether any data was exfiltrated.
- The identity or geographic location of an actual operator.

### Additional checks recommended
- Inbox rules, forwarding addresses, delegates, and mailbox access logs.
- MFA method registration, authentication fatigue events, and recovery changes.
- OAuth application grants and refresh-token activity.
- Sign-ins to cloud storage, collaboration, VPN, and administrative portals.
- Similar messages delivered to other users.

## 7. MITRE ATT&CK mapping

| Technique | ID | Simulated relevance |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Email delivers a credential-harvesting link |
| User Execution: Malicious Link | T1204.001 | User navigates to the link |
| Valid Accounts | T1078 | Stolen or exposed credentials may enable access |
| Steal Web Session Cookie | T1539 | Relevant investigative hypothesis if session-token theft is evidenced |

Mappings are analytic references, not proof of technique execution. T1539 is a hypothesis to investigate, not a confirmed finding in this scenario.

## 8. Containment, eradication, and recovery

### Immediate containment
- Disable or temporarily restrict the affected identity according to business continuity requirements.
- Revoke active sessions, refresh tokens, and remembered sessions.
- Reset the password using a trusted channel.
- Re-register MFA after verifying the user's identity and checking for attacker-added methods.
- Block the phishing URL/domain in mail and web controls where appropriate.
- Search for and quarantine matching messages across the tenant.

### Eradication
- Remove unauthorized inbox rules, forwarding settings, delegates, and OAuth grants.
- Review and remove unrecognized authentication methods and recovery contacts.
- Investigate endpoint persistence or malware indicators before declaring the device clean.
- Rotate any secrets that may have been exposed through the compromised identity.

### Recovery and validation
- Restore access only after identity verification and control checks.
- Confirm MFA works and sessions originate from expected devices.
- Monitor sign-in risk, mailbox access, forwarding changes, and OAuth consent.
- Notify affected stakeholders under the organization's incident and privacy procedures.

## 9. Remediation and lessons learned

**Priority 1**
- Enforce phishing-resistant MFA for privileged and high-risk accounts.
- Apply conditional access based on device compliance, sign-in risk, and session context.
- Revoke sessions rapidly when compromise is suspected.
- Ensure identity and mailbox audit logging is enabled and retained.

**Priority 2**
- Deploy URL detonation and time-of-click protection.
- Improve external sender indicators and impersonation protection.
- Alert on suspicious inbox rules, forwarding, MFA registration, and OAuth grants.
- Conduct targeted phishing-awareness training using safe simulations.

**Detection opportunities**
- Successful sign-in from a new device or anomalous source shortly after a phishing URL click.
- New inbox forwarding rule or delegate after unusual authentication.
- MFA method registration followed by access from a new source.
- Unusual mailbox access volume or atypical cloud application consent.

## 10. Conclusion

The simulated evidence supports a phishing-led account compromise. The response prioritizes session revocation, credential and MFA recovery, mailbox configuration review, and identity telemetry monitoring. Claims of mailbox data theft or broader compromise are deliberately withheld because the scenario does not establish them.

## 11. Evidence limitations

This case study uses synthetic records and does not include raw email files, actual identity-provider exports, endpoint disk images, or independently verifiable forensic artifacts. The findings demonstrate an investigation method rather than a real-world forensic conclusion.

## Reproducible sample evidence

The corresponding fictional timeline is available in the [normalized sample events](../evidence/events.csv) and [evidence guide](../evidence/README.md). From the repository root, run `python scripts/summarize_case.py INC-01` to review it. The [query examples](../queries/README.md) show how to investigate the sequence in a lab.
