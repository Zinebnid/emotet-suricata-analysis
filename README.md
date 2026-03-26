## Network Intrusion Detection with Suricata + Malware PCAP Analysis

## 1.Objective 

This project demonstrates intrution dectection and traffic analysis workfow using Suricata and Wireshark
Analyzed a malicious PCAP file to detect Command & Control (C2) communication,extract IOCs using tshark and Map activity to MITTRE ATT&CK

## 2.Lab Setup

The analysis was performed in a Kali Linux virtual machine running in VirtualBox, Suricata was installed and updated on the Kali system, ten usd to inspect a malware PCAP offline. the PCAP used in this project contained Emotet infection traffic, which was analysed to identify beaconing activity, suspiciois HTTP requests, external IP communication ...

## 3.Tools 

Kali Linux (VirtualBox)
Suricata (IDS
Wireshark
Tshark
VirusTotal
AbuseIPDB
Detection with Suricata

## 4.Attack Overview

Emotet is a banking trojan and malware strain first appeard in 2014, spreads via phishing emails containing malicoious attachments or links, it steals credentials, doawnload other malware, beacon to C2, Emotet often uses HTTP-based C2 traffic, repeated beaconing.This makes it a strong case study for intrusion detection and packet analysis.  

## 5.Analysis Process

1. Installing and updating suricata on kali linux
2. Run suricata IDS against the PCAP to generate alerts 
3. analyse HTTP traffic using tshark to identidy C2 communication patterns
4. Observed POST requests to random URLs , identified as C2 beaconing
5. write a custom suricata rule targeting the C2 URL pattern
6. Rule fired 19 alerts and confirm allerts appers in fast-log
8. Extract all IPs origin and destination using tshark
9. validate suspicious ips using totalvirus and abuse ipdb

## 6.Custom suricata rule 

alert http any any -> any any (
  msg:"CUSTOM - Emotet C2 POST Beacon Detected";
  flow:established,to_server;
  content:"POST";
  http_method;
  pcre:"/^\/[a-z0-9]{4,20}\/[a-z0-9]{4,20}\//Ui";
  sid:9000001;
  rev:1;
)

The goal from this rule is to detect suspicious and reppeated HTTP POST requests related to C2 beaconing, and the Emotet genarates random URLs which resulted to 19 alerts  against it.

## 7. IOCs 

![tshark extracting all destination IPs from the PCAP](screenshots/03_tcp_stream.png)


| Type | Value | Source | Notes |
|------|------|------|-----|
| malicious IP | 5.2.136.90 | VirusTotal 6/94, AbuseIPDB | External C2 Communication |
| malicoius IP | 167.71.4.0 | VirusTotal 10/94 | External C2 communication over port 8080 |
| malicoius IP | 103.92.235.25 | Suspected C2 | PCAP Analysis |
| URL/Path | /7u0e9j2avwlvnuynyo/szcm27k/fzb067wy/ | C2 endpoint | Suspicious HTTP POST path observed in stream |

![VirusTotal confirming 5.2.136.90 as malicious — 6/94 vendors](screenshots/04_virustotal.png)

![VirusTotal confirming 167.71.4.0 as malicious — 10/94 vendors](screenshots/05_abuseipdb.png)

![AbuseIPDB confirming 5.2.136.90 found in abuse database](screenshots/06_tshark_iocs.png)

## 8. MITTRE ATT&CK Maping: 5 Techniques

| Technique ID | Name | Evidence | 
|------|------|------|
| T1071.001 | Application Layer Protocol : Web Protocols | Emotet used HTTP post requests for c2 communication|
| T1571 | Non-Standart Port | C2 Traffic observed on port 8080 instead of port 80 | 
| T1036 | Masquerading | Fake internet Explorer used a browser like user-agent string |
| T1102 | Web Service:  one way communication | C2 traffic routed through compromised WordPress sites |
| T1041 | Exfiltration Over C2 Channel | Binary data sent to C2 server via HTTP POST | 

## 9. Incident Report 

Victim Information

Victim IP: 10.1.6.206
Operating Context: Internal host observed generating suspicious outbound traffic
Detection Source: Suricata alerts, Wireshark traffic analysis, tshark IOC extraction

Timeline of Events

Suricata analysis identified repeated suspicious outbound traffic from 10.1.6.206.
Multiple alerts in fast.log showed recurring communication with external IPs.
Wireshark TCP stream analysis revealed HTTP POST requests carrying suspicious payload data.
IOC extraction confirmed repeated communication with 5.2.136.90 and 167.71.4.0.
VirusTotal and AbuseIPDB validation supported the classification of those destinations as malicious or suspicious.

Malware Activity Observed

The infected host showed repeated outbound beaconing behavior consistent with Emotet command and control communication. The malware used HTTP POST requests to send data to remote systems, including communication over a non-standard web port. The observed traffic pattern suggests an active infection maintaining contact with attacker-controlled infrastructure, which could enable additional payload delivery or follow-on malicious actions.

Recommendations

Isolate the infected host immediately from the network.
Block the malicious IP addresses at firewall or perimeter security controls.
Hunt across the environment for similar outbound connections or Suricata alerts.
Review endpoint logs and process activity on the victim machine.
Deploy tuned IDS signatures to improve detection of similar HTTP beaconing behavior.
Reset credentials and assess whether additional malware or lateral movement occurred.
   
## 10. Key skills demonstrated 

- PCAP analysis and forensic investigation using wireshark
- Suricata custom rule creation and firing it against emotet
- Incident Detection by finding indicators or compromise using tshark
- Malware C2 traffic identification
- VirusTotal and AbuseIPDb investigation 
- MITTRE ATT&CK Mapping




























