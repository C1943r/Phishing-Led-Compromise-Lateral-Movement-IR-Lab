# Incident Response Lab: Phishing-Led Compromise with Lateral Movement

A tabletop incident analysis from a Cyber Incident Response Team course lab. Working from three pieces of provided evidence (an endpoint alert, network activity, and authentication activity), I identified the compromised host, scoped the affected systems, recommended response actions, and built the incident timeline and record.

**Skills demonstrated:** log correlation, indicator identification, scoping, containment planning, timeline reconstruction, incident documentation, evidence handling.

## Contents

- [Evidence](#evidence)
- [Part 1: Incident Analysis](#part-1-incident-analysis)
- [Part 2: Initial Response Actions](#part-2-initial-response-actions)
- [Part 3: Incident Timeline](#part-3-incident-timeline)
- [Part 4: Incident Record](#part-4-incident-record)
- [Part 5: Business Impact and Response Plan](#part-5-business-impact-and-response-plan)
- [Part 6: Policy and Compliance Considerations](#part-6-policy-and-compliance-considerations)

## Evidence

### Evidence 1: Endpoint Alert

```text
HOST: FINANCE-PC07
USER: jsmith
PROCESS: powershell.exe
PARENT PROCESS: WINWORD.EXE
COMMAND: powershell.exe -WindowStyle Hidden -EncodedCommand [REDACTED]

SEVERITY: HIGH
STATUS: Suspicious PowerShell activity detected
```

### Evidence 2: Network Activity

```text
10:18:14  FINANCE-PC07  ->  192.168.10.15   TCP 445
10:18:22  FINANCE-PC07  ->  192.168.10.21   TCP 445
10:18:31  FINANCE-PC07  ->  192.168.10.25   TCP 445
10:19:03  FINANCE-PC07  ->  185.82.219.44   TCP 443
10:19:16  FINANCE-PC07  ->  185.82.219.44   TCP 443
10:20:02  FINANCE-PC07  ->  185.82.219.44   TCP 443
```

### Evidence 3: Authentication Activity

```text
10:18:18  jsmith  -> FILESERVER01   SUCCESS
10:18:25  jsmith  -> HR-SERVER01    FAILURE
10:18:28  jsmith  -> HR-SERVER01    FAILURE
10:18:35  jsmith  -> APP-SERVER02   SUCCESS
10:18:41  jsmith  -> DB-SERVER01    FAILURE
```

## Part 1: Incident Analysis

### Indicators of potentially malicious activity

1. The workstation became unusually slow after the user opened an email attachment.
2. `powershell.exe` was launched by an unusual parent process (`WINWORD.EXE`).
3. The workstation made repeated outbound connections to an external IP (`185.82.219.44`).

### Initial compromised endpoint

**FINANCE-PC07**

### Other systems requiring investigation

| System | Priority | Reason |
|---|---|---|
| FILESERVER01 | High | Successful authentication |
| APP-SERVER02 | High | Successful authentication |
| HR-SERVER01 | Low | Authentication failed |
| DB-SERVER01 | Low | Authentication failed |

### External address to investigate

`185.82.219.44`

### What the combined evidence indicates

The evidence points to a single attack chain:

1. A phishing email attachment is opened on FINANCE-PC07.
2. The attachment launches a hidden, encoded PowerShell command from `WINWORD.EXE`.
3. The attacker moves laterally over SMB using the `jsmith` account.
4. The workstation connects to an external address over TCP 443, indicating possible C2 or data exfiltration.

## Part 2: Initial Response Actions

### Containment priority

**FINANCE-PC07** is the first system to contain.

### User account

The `jsmith` account should be disabled, its password reset, and its active sessions terminated.

### Network activity to block or monitor

- Block `185.82.219.44` at the firewall.
- Search logs for any other system or service reaching out to that IP.
- Search email logs for anyone else who opened the attachment.
- Monitor `jsmith` authentications.
- Monitor all SMB authentications.

### Additional logs and evidence to collect

- Volatile memory and a disk image of FINANCE-PC07, with chain of custody.
- PowerShell logs.
- Firewall and DNS logs.
- Data transfer volumes to the external IP, to determine whether the traffic is C2 or data exfiltration.

### Effect on normal business operations

- `jsmith` cannot work until a new workstation and new account credentials are issued.
- FILESERVER01 and APP-SERVER02 would be unavailable to the personnel who rely on them.

## Part 3: Incident Timeline

| Time | System / Account | Activity | Why It Matters |
|---|---|---|---|
| 10:18:14 | FINANCE-PC07 | Initiates SMB traffic to 192.168.10.15 over TCP 445 | First SMB connection; lateral movement begins |
| 10:18:18 | jsmith | Authenticates to FILESERVER01 | The file server is successfully accessed |
| 10:18:22 | FINANCE-PC07 | Initiates SMB traffic to 192.168.10.21 over TCP 445 | A second internal host is contacted |
| 10:18:25 | jsmith | Authentication fails on HR-SERVER01 | Fails, but shows system probing |
| 10:18:28 | jsmith | Second authentication failure on HR-SERVER01 | Fails, but shows system probing; the speed suggests a script is running |
| 10:18:31 | FINANCE-PC07 | Initiates SMB traffic to 192.168.10.25 over TCP 445 | A third internal host is contacted |
| 10:18:35 | jsmith | Authenticates to APP-SERVER02 | Second successful access to a server |
| 10:18:41 | jsmith | Authentication fails on DB-SERVER01 | Fails, but shows system probing |
| 10:19:03 | FINANCE-PC07 | Outbound connection to 185.82.219.44 over TCP 443 | First contact with the external IP; C2 or data exfiltration |
| 10:19:16 | FINANCE-PC07 | Second outbound connection to 185.82.219.44 over TCP 443 | Second contact with the external IP; C2 or data exfiltration |
| 10:20:02 | FINANCE-PC07 | Third outbound connection to 185.82.219.44 over TCP 443 | Third contact with the external IP; C2 or data exfiltration |

## Part 4: Incident Record

| Field | Details |
|---|---|
| **Incident title** | Successful Phishing with Server Access and Lateral Movement |
| **Time of observed activity** | 10:18:14 – 10:20:02 |
| **Affected user/account** | `jsmith` |
| **Known or suspected affected systems** | FINANCE-PC07, FILESERVER01, APP-SERVER02, HR-SERVER01, DB-SERVER01 |
| **Indicators of compromise** | `WINWORD.EXE` spawning PowerShell with a hidden window and encoded commands; subsequent lateral movement and probing; external connection to `185.82.219.44` |
| **Evidence reviewed** | Endpoint alert, network activity, authentication activity |
| **Individuals or groups to notify** | SOC lead, CISO, CFO, Legal |
| **Current status** | Open |

### Recommended containment actions

- Prioritize FINANCE-PC07 for containment; capture volatile memory and a disk image with chain of custody.
- Disable the `jsmith` account, reset its password, and terminate its active sessions.
- Block `185.82.219.44` at the firewall.
- Search logs for any other system or service reaching out to that IP.
- Search email logs for anyone else who opened the attachment.
- Monitor `jsmith` authentications and all SMB authentications.
- Collect PowerShell, firewall, and DNS logs.
- Review data transfer volumes to the external IP to determine whether the traffic is C2 or data exfiltration.

## Part 5: Business Impact and Response Plan

| Phase | Recommendation |
|---|---|
| **Immediate containment** | Isolate the workstation and the affected servers; block the sender's email address and delete its messages from inboxes; block the external IP. |
| **Potential business impact** | `jsmith` cannot work until a new workstation and credentials are issued; FILESERVER01 and APP-SERVER02 would be unavailable to the personnel who rely on them. |
| **Evidence preservation** | Image volatile memory and disk while maintaining chain of custody. |
| **Eradication** | Reimage the endpoint, remove the email from all inboxes, and reset credentials. |
| **Recovery** | Restore affected devices from clean images. |
| **Post-incident monitoring** | Monitor for connection attempts to the external IP; watch `jsmith` and other users for activity that deviates from baseline; watch SMB activity. |

### Reducing risk while minimizing disruption

The response is scoped to what the evidence supports. Isolating FINANCE-PC07, disabling `jsmith`, and blocking `185.82.219.44` remove the attacker's foothold, the stolen credentials, and the external channel. Server isolation is limited to FILESERVER01 and APP-SERVER02, where authentication succeeded; HR-SERVER01 and DB-SERVER01, where it failed, stay online under monitoring. Evidence is imaged before anything is reimaged, so the investigation is preserved without delaying containment.

## Part 6: Policy and Compliance Considerations

**Guiding policy or procedure.** The organization's incident response playbook for this type of incident.

**Why evidence handling and chain of custody matter.** Evidence should be handled by a team trained in DFIR to prevent the loss of evidence or of its integrity.

**Stakeholder for legal, regulatory, contractual, or compliance review.** The Legal department.

**Information to retain in the final incident documentation.** The timeline, IOCs, hashed evidence and chain of custody log, business impact, root cause, and lessons learned.
