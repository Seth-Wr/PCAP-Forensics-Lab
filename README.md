# PCAP-Forensics-Lab

This repository contains documentation, artifacts, and methodologies for network forensic investigations. The focus is on the end-to-end process of analyzing PCAP files to identify threats, reconstruct attack chains, and generate actionable incident response reports.

## Objective
To develop and demonstrate proficiency in:
* **Network Forensics:** Extracting data and identifying patterns within packet captures.
* **Threat Identification:** Detecting C2 beaconing, malware delivery, and exfiltration.
* **Attack Reconstruction:** Correlating network events to map adversary activity to the MITRE ATT&CK framework.
* **Reporting:** Translating raw network data into concise, high-fidelity Incident Reports (IR).

## Methodology
Every investigation in this lab follows a standardized pipeline:
1. **Ingestion & Scoping:** Importing PCAP/pcapng files into analysis tools (Wireshark, Zeek, Brim, or Tshark).
2. **Traffic Analysis:** Identifying anomalous protocols, unexpected DNS queries, and unauthorized connections.
3. **Correlation:** Aligning network timestamps with endpoint logs to establish context.
4. **Reporting:** Documentation of IOCs (Indicators of Compromise) and remediation steps.

## Repository Structure
```text
/
├── TEMPLATE.md       # Standardized template for Incident Reports
├── README.md         # This file
└── cases/            # Root directory for all investigations
    └── [Case-Name]/
        ├── README.md # Specific Incident Report for the case
        ├── PCAPs/     # Captured traffic files for the case
        └── images/   # Visual evidence, flow diagrams, and screenshots
