# Incident Report: [Malware Family / Incident Name]

![Status](https://img.shields.io/badge/status-open-yellow) ![Severity](https://img.shields.io/badge/severity-TBD-lightgrey) ![Malware](https://img.shields.io/badge/family-UNKNOWN-lightgrey)

## Overview

| Field | Detail |
|---|---|
| **Incident Date** | YYYY-MM-DD |
| **Alert Date** | YYYY-MM-DD |
| **Malicious IP** | `x.x.x.x` |
| **Malicious Domain** | `example.tld` |
| **Internal Host** | `x.x.x.x` |
| **MAC Address** | `xx:xx:xx:xx:xx:xx` |
| **Hostname** | `HOSTNAME` |
| **User Account** | Full Name (`username`) |
| **Triggering Alert** | [SIEM/IDS rule name] |

## Summary

<!-- 2-4 sentences: what triggered the investigation, what host/user was involved, and the high-level conclusion (confirmed infection, false positive, etc.) -->

The endpoint `[IP]` triggered an alert for **[alert name]**. Analysis of [PCAP/logs/EDR telemetry] confirmed/ruled out [a successful infection / malicious activity] originating from [source].

## Investigation Steps

### 1. Asset Identification
<!-- How did you tie the alert to a specific host and user? -->
- Correlated the triggering IP (`[IP]`) with internal logs.
- Identified user account `[username]` via [Kerberos AS-REQ / DHCP logs / etc.].
- Confirmed identity as [Full Name] via [SMB Query User Info / AD lookup / HR mapping].

### 2. Domain / Infrastructure Attribution
<!-- How did you tie the malicious domain/IP to the activity? -->
- Correlated DNS request timing at `[timestamp]` with the initial TCP connection to the malicious IP at `[timestamp]`.
- Identified `[domain]` as the [C2 entry point / delivery source].

### 3. Payload & Execution Analysis

**Reconnaissance**
<!-- Any fingerprinting, environment checks, sandbox evasion observed -->
- [Description of recon/fingerprinting behavior observed]

**Delivery**
<!-- How was the payload delivered? File type, hex header, hosting infra -->
- [Payload type] downloaded via [delivery mechanism] (identified by hex header `[XX XX XX XX]`).

**Activation**
<!-- Evidence of execution and C2 establishment -->
- Observed a `[GET/POST]` request containing [parameters].
- Followed by [subsequent request/behavior], confirming [execution / C2 establishment].

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|---|---|---|
| [Tactic] | [T-code] | [Description] |
| [Tactic] | [T-code] | [Description] |
| [Tactic] | [T-code] | [Description] |
| [Tactic] | [T-code] | [Description] |

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| IP | `x.x.x.x` |
| Domain | `example.tld` |
| File Hash (SHA256) | `[hash]` |
| URI Pattern | `[pattern]` |

## Detection Recommendation

<!-- The specific, actionable detection rule or logic you'd push to SIEM/IDS -->
Create a SIEM detection rule to alert on [specific behavior/pattern], as this is a specific footprint of [malware family/technique].

```
# Example pseudo-rule
alert http any any -> any any (
    msg:"[Rule Name]";
    http.method; content:"[METHOD]";
    http.uri; content:"[pattern]";
    classtype:trojan-activity;
    sid:[SID]; rev:1;
)
```

## Lessons Learned

<!-- 3-6 takeaways framed as reusable defensive insight, not just a recap of what happened -->

1. **[Insight title].** [What you learned and why it generalizes beyond this one incident.]

2. **[Insight title].** [What you learned and why it generalizes beyond this one incident.]

3. **[Insight title].** [What you learned and why it generalizes beyond this one incident.]

4. **[Insight title].** [What you learned and why it generalizes beyond this one incident.]

## Recommended Next Steps

- [ ] Isolate/re-image affected host
- [ ] Reset credentials for affected user account
- [ ] Hunt for IOCs across the broader environment
- [ ] Deploy detection rule to SIEM
- [ ] [Additional environment-specific follow-up]
- [ ] [Additional environment-specific follow-up]

---
*This report is provided for educational and defensive security purposes.*