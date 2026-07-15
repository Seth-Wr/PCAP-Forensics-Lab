# Incident Report: C2 Potential RAT
![Status](https://img.shields.io/badge/status-closed-red) ![](https://img.shields.io/badge/severity-high-red) ![Malware](https://img.shields.io/badge/family-UNKNOWN-lightgrey)

## Overview
| Field | Detail |
|---|---|
| **Incident Date** | 2026-02-28 |
| **Alert Date** | 2026-02-28 |
| **Malicious IP** | `45.131.214.85` |
| **Malicious Domain** | `vadusa.xyz` |
| **Internal Host** | `10.2.28.88` |
| **MAC Address** | `00:19:d1:b2:4d:ad` |
| **Hostname** | `DESKTOP-TEYQ2NR` |
| **User Account** | Becka Rolf (`brolf`) |
| **Triggering Alert** | NetSupport Manager RAT Signature detected |

## Summary
The endpoint `10.2.28.88` triggered a SIEM alert for a **NetSupport Manager RAT signature**. Packet capture analysis confirmed a successful outbound C2 channel to `45.131.214.85` (domain `vadusa.xyz`), consisting of HTTP (not TLS) traffic on port 443 with a `CMD=POLL` heartbeat repeating at ~1-minute intervals, followed by gzip-encoded data exfiltration/command traffic. The infection was already active at the start of capture, so the initial access vector could not be determined from network evidence alone.

## Investigation Steps

### 1. Asset Identification
- Correlated the triggering IP (`45.131.214.85`) from the SIEM RAT signature hit against internal traffic to isolate the client that initiated the connection.
- Identified the internal source as MAC `00:19:d1:b2:4d:ad` / IP `10.2.28.88`.
- Filtered port 88 (Kerberos) traffic — TGS-REQ/TGS-REP traffic was noisy and inconclusive, so the analysis dropped to the AS-REQ exchange. Using `kerberos.CNameString`, the associated user principal was identified as `brolf`.
- Filtered LDAP traffic for hostname/identity leakage — no useful results.
- Checked SMB and DNS packets for hostname info — no useful results.
- Filtered NBNS traffic and found a name registration for `DESKTOP-TEYQ2NR`, confirming the hostname.
- Checked DHCP Discover traffic (Option 12) and found a hostname of `brads-MBP` — this was determined to be an **unrelated host** present in the same capture, not the infected client, and was ruled out.
- Since `brolf` appeared to follow a first-initial/last-name convention, performed a case-sensitive string search for "Rolf" across packet details and located it in a SAMR packet, confirming the full identity as **Becka Rolf**.

### 2. Domain / Infrastructure Attribution
- Correlated the DNS response for `vadusa.xyz` at `14:55:51.371555` with a TCP SYN to `45.131.214.85` occurring immediately after (`14:55:51`), tying the domain directly to the C2 IP.
- Confirmed via `dns` record lookups that `vadusa.xyz` resolves to `45.131.214.85`.
- Applied `tls.handshake.type == 1` (Client Hello) filtered to the infected host — **no TLS Client Hello was found** for traffic to the malicious IP, despite the traffic occurring on port 443. This indicates the C2 channel is plaintext HTTP tunneled over the port normally reserved for HTTPS, not actual TLS.
- **Timeline note (observed, not conclusively causal):** A DNS query to `www.fmcsa.dot.gov` was seen at `14:55:50`, immediately followed by the `vadusa.xyz` resolution and SYN to the malicious IP at `14:55:51`, and then a query to `fd-api-iris.trafficmanager.net` at `14:55:59`. The CNAME chain for the `.gov`-looking query resolved through a `.net` (Azure Traffic Manager) record. This sequence is flagged as a possible masquerading/decoy pattern worth further review, but process-to-socket correlation (host-based telemetry) would be required to confirm it's related to the malware rather than coincidental legitimate background traffic.

### 3. Payload & Execution Analysis
**Reconnaissance**
- No distinct sandbox-evasion or environment-fingerprinting traffic was identified prior to C2 activation; the malware appears to have already been resident and running at the start of the capture window.

**Delivery**
- No delivery/drop event (initial payload download) was captured in the PCAP — the infection predates the capture window, so delivery mechanism and file hash could not be recovered from this data source.

**Activation**
- First observed POST request contained a form body:
  `CMD=POLL`
  `INFO=1`
  `ACK=1`
- Subsequent POST requests contained a URL-encoded binary blob consistent with gzip-compressed data (non-printable/encoded content, not human-readable parameters).
- POST requests to the C2 IP repeated at approximately 1-minute intervals — a consistent, automated beaconing cadence consistent with RAT/backdoor check-in behavior rather than normal application traffic.

## MITRE ATT&CK Mapping
| Tactic | Technique | Description |
|---|---|---|
| Command and Control | T1071.001 – Web Protocols | Confirmed use of HTTP POST requests over port 443 to communicate with the remote C2 server (no TLS handshake present despite the port). |
| Command and Control | T1071.003 – Beaconing | `CMD=POLL` heartbeat repeating at ~1-minute intervals is an aggressive, automated beaconing pattern. |
| Execution / Persistence | T1547.001 – Boot or Logon Autostart Execution | *Inferred, not directly observed.* Beaconing was already active at capture start with no user-driven trigger seen; host-based artifacts (registry/startup items) would be needed to confirm an autostart mechanism. |
| Exfiltration | T1041 – Exfiltration Over C2 Channel | Gzip-encoded binary blobs sent via POST body are consistent with data exfiltration or delivery of command payloads over the same channel. |
| Discovery | T1082 – System Information Discovery | `INFO=1` / `ACK=1` parameters in the beacon suggest the implant is reporting status/environment data to the C2 server. |

## Indicators of Compromise (IOCs)
| Type | Value |
|---|---|
| IP | `45.131.214.85` |
| Domain | `vadusa.xyz` |
| Domain (unconfirmed / needs validation) | `fd-api-iris.trafficmanager.net` |
| File Hash (SHA256) | Not recovered — payload delivery not present in capture window |
| URI / Body Pattern | `CMD=POLL` / `INFO=1` / `ACK=1` beacon body; gzip-encoded POST body on follow-up requests |
| Behavioral | HTTP POST beacon on port 443 with no TLS Client Hello, ~1-minute interval |

## Detection Recommendation
Create SIEM/IDS detections for (1) the specific beacon body signature, and (2) the broader behavioral pattern of plaintext HTTP masquerading on port 443, since the exact C2 body pattern may change across campaigns but the protocol mismatch and cadence are harder for an attacker to disguise.

```
# Example pseudo-rule 1: known beacon body pattern
alert http any any -> any any (
    msg:"C2 Beacon - CMD=POLL heartbeat pattern (vadusa.xyz cluster)";
    http.method; content:"POST";
    http.request_body; content:"CMD=POLL"; content:"INFO=1"; content:"ACK=1";
    classtype:trojan-activity;
    sid:1000001; rev:1;
)

# Example pseudo-rule 2: behavioral - HTTPS port, no TLS handshake
alert tcp any any -> any 443 (
    msg:"Possible C2 - plaintext HTTP on port 443 (no TLS ClientHello)";
    flow:established,to_server;
    content:"POST"; http_method;
    content:!"|16 03|"; depth:2; # no TLS record header at session start
    classtype:trojan-activity;
    sid:1000002; rev:1;
)

# Example pseudo-rule 3: fixed-interval beaconing (tune threshold to environment baseline)
alert tcp $HOME_NET any -> 45.131.214.85 any (
    msg:"C2 Beaconing - consistent ~1m interval to known bad IP";
    threshold:type threshold, track by_src, count 5, seconds 300;
    classtype:trojan-activity;
    sid:1000003; rev:1;
)
```

## Lessons Learned
1. **Beacon cadence is a strong, durable signal.** Fixed-interval traffic (here, ~1 minute) is unusual for legitimate applications and is often more reliable to detect than payload content, which attackers rotate more frequently. Build interval-based anomaly rules, not just signature/IOC rules.
2. **Protocol-port mismatches are high-value detections.** Traffic on port 443 with no TLS Client Hello is a strong indicator of plaintext C2 tunneling through a "trusted" port. This generalizes to any well-known port being used for a different protocol than expected.
3. **Don't trust a single identity-correlation source.** DHCP Option 12 returned an unrelated hostname (`brads-MBP`) for a different host in the same capture. Triangulating identity across Kerberos, NBNS, and SAMR traffic prevented misattributing the incident to the wrong asset.
4. **Network evidence alone can't establish causality for adjacent events.** The `.gov`-styled DNS query occurring seconds before the malicious resolution is suspicious but not proof of a masquerading technique without host-based (process/socket) correlation. Reports should flag such timing correlations as leads, not conclusions.
5. **Retrospective PCAP has a visibility gap for "left of boom."** The malware was already beaconing at the start of capture, so initial access (phishing, drive-by, shadow IT-installed remote access tool, etc.) could not be determined. This is a case for expanding EDR/host telemetry retention so initial execution isn't lost.

## Recommended Next Steps
- [ ] Isolate/re-image affected host (`DESKTOP-TEYQ2NR` / `10.2.28.88`)
- [ ] Reset credentials for affected user account (`brolf`)
- [ ] Hunt for IOCs across the broader environment (IP, domain, beacon body pattern, port-443-no-TLS behavior)
- [ ] Deploy detection rules to SIEM/IDS
- [ ] Detonate the recovered gzip-encoded payload in an isolated sandbox environment to identify the malware family and confirm capabilities
- [ ] Pull EDR/host logs (if available) for `10.2.28.88` to identify initial access vector and any autostart/persistence artifacts, since this could not be confirmed from PCAP alone

---
*This report is provided for educational and defensive security purposes.*
