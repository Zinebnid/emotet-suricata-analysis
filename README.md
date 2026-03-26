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
7. Extract all IPs origin and destination using tshark
8. validate suspicious ips using totalvirus and abuse ipdb

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













