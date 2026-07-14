# Incident Report: Lumma Stealer Infection Analysis

![Status](https://img.shields.io/badge/status-closed-red) ![Severity](https://img.shields.io/badge/severity-high-critical) ![Malware](https://img.shields.io/badge/family-LummaC2%20Stealer-orange)

## Overview

| Field | Detail |
|---|---|
| **Incident Date** | 2026-01-27 |
| **Alert Date** | 2026-01-31 |
| **Malicious IP** | `153.92.1.49` |
| **Malicious Domain** | `whitepepper.su` |
| **Internal Host** | `10.1.21.58` |
| **MAC Address** | `00:21:5d:c8:0e:f2` |
| **Hostname** | `DESKTOP-ES9F3ML` |
| **User Account** | Gabriel Wyatt (`gwyatt`) |
| **Triggering Alert** | ET MALWARE Lumma Stealer Victim Fingerprinting Activity |

## Summary

The endpoint `10.1.21.58` triggered an alert for **ET MALWARE Lumma Stealer Victim Fingerprinting Activity**. PCAP analysis confirmed a successful multi-stage infection originating from the malicious domain `whitepepper.su`, consistent with LummaC2 Stealer tradecraft.

## Investigation Steps

### 1. Asset Identification
- Correlated the triggering IP (`10.1.21.58`) with internal logs.
- Identified the user account `gwyatt` via Kerberos `AS-REQ`.
- Confirmed the identity as **Gabriel Wyatt** via SMB `Query User Info` responses over port 445.

### 2. Domain Attribution
- Correlated DNS request timing (`92.310018s`) with the initial TCP connection to the malicious IP (`92.344626s`).
- Identified `whitepepper.su` as the C2 entry point based on this timing correlation.

### 3. Payload & Execution Analysis

**Reconnaissance**
- Initial HTTP response contained a malicious JavaScript payload leveraging `RTCPeerConnection` for WebRTC-based de-anonymization and network environment/sandbox profiling.

**Delivery**
- A custom-wrapped binary (identified by hex header `63 61 6e 74`) was downloaded via Nginx.

**Activation**
- Observed a `GET` request containing victim UID, session token, and browser agent parameters.
- Followed by a `POST` request (`act=log`), confirming successful payload execution and C2 channel establishment.

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|---|---|---|
| Discovery | T1082 / T1217 | WebRTC/JS-based fingerprinting for environment/sandbox profiling |
| Execution | T1204.002 | Confirmed execution of malicious binary (`act=log` signature) |
| Command & Control | T1071.001 | Use of HTTP/POST for beaconing and command heartbeat |
| Collection | T1005 | Malware established on host; high probability of data exfiltration |

## Detection Recommendation

Create a SIEM detection rule to alert on any HTTP `POST` request containing the URI parameters `id=`, `token=`, and `act=log`, as this combination is a specific footprint of the LummaC2 staging process.

```
# Example pseudo-rule
alert http any any -> any any (
    msg:"LummaC2 Staging - Beacon POST Signature";
    http.method; content:"POST";
    http.uri; content:"id="; content:"token="; content:"act=log";
    classtype:trojan-activity;
    sid:1000001; rev:1;
)
```

## Lessons Learned

1. **Timing correlation is a reliable pivot for attribution.** Aligning DNS resolution timestamps with the subsequent TCP handshake was the key step that tied `whitepepper.su` to the malicious IP — this technique should be a standard part of C2 attribution workflows, not a one-off.

2. **Browser fingerprinting via WebRTC is an underused early-warning signal.** The `RTCPeerConnection`-based reconnaissance stage occurred *before* payload delivery. Detection rules tuned to catch anomalous WebRTC calls from JavaScript served by non-standard domains could catch this class of infection at the discovery stage, before execution.

3. **Non-standard binary headers evade extension-based filtering.** The payload used a custom hex header (`63 61 6e 74`) instead of a standard executable signature, which would bypass naive file-type filtering. File inspection controls should validate based on magic bytes/behavior, not just extension or a small allowlist of known headers.

4. **URI parameter patterns are high-fidelity IOCs.** The `id=`, `token=`, and `act=log` parameter combination proved to be a specific, low-noise fingerprint for LummaC2 staging — a good reminder that URI-parameter-based detections can outperform domain/IP blocklists, which age quickly as infrastructure rotates.

5. **Identity correlation via Kerberos + SMB strengthens attribution confidence.** Cross-referencing `AS-REQ` account activity with SMB `Query User Info` gave two independent data sources confirming the same user, reducing the chance of misattributing the incident to the wrong person or a shared/service account.

## Recommended Next Steps

- [ ] Isolate and re-image `DESKTOP-ES9F3ML`
- [ ] Force credential reset for `gwyatt` (local + any cached/synced credentials)
- [ ] Hunt for `whitepepper.su` and `153.92.1.49` across the broader environment
- [ ] Deploy the URI parameter detection rule above to SIEM
- [ ] Review browser/EDR telemetry for other hosts exhibiting WebRTC fingerprinting behavior
- [ ] Assess scope of potential data exfiltration (browser-stored credentials, cookies, crypto wallets — typical LummaC2 targets)

---
*This report is provided for educational and defensive security purposes.*
