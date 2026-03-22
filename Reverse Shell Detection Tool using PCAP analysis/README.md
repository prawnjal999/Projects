# Reverse Shell Detection Tool

## Overview
This project demonstrates the detection of reverse shell activity from network traffic using PCAP analysis.

A custom Python tool was developed to automate detection by combining:
- Signature-based detection (known reverse shell ports)
- Behavioral analysis (connection frequency and patterns)
- TCP handshake analysis (identifying connection initiator)

---

## Objectives
- Simulate a reverse shell attack in a controlled lab
- Capture network traffic using Wireshark
- Analyze PCAP data manually and programmatically
- Build an automated detection tool using Python + tshark

---

## Lab Environment
            
* Attacker-   Kali Linux VM                
* Victim-     Ubuntu VM                    
* Network-    VirtualBox Bridge Network  
* IP Range-   192.168.1.x                  

---

## Features
- Accepts any PCAP file as input
- Identifies likely victim and attacker
- Detects known reverse shell ports (e.g., 4444)
- Detects abnormal communication patterns
- Generates structured detection output

---

## Usage
"```bash"
python3 detect_reverse_shell.py <pcap_file>

---

## Sample Output
============================================================
        Reverse Shell Detection Report
============================================================

[!] Suspicious Activity Detected:

   Connection: 192.168.1.9 ↔ 192.168.1.10

      [HIGH] Known reverse shell port
         Victim   : 192.168.1.9
         Attacker : 192.168.1.10
         Port     : 4444

============================================================
[!] Verdict: HIGH confidence of reverse shell activity
============================================================

---

## Detection Approach
1. TCP SYN Analysis
  *Identifies the initiator of the connection
  *Used to determine victim vs attacker
2. Port-Based Detection
  *Flags commonly used reverse shell ports
  *Provides quick identification of suspicious activity
3. Behavioral Analysis
  *Detects repeated communication between hosts  
  *Identifies potential beaconing or persistent sessions

---   

## Key Learnings
* TCP handshake fundamentals and role identification
* Reverse shell behavior in network traffic
* Practical Wireshark and tshark usage
* Detection engineering concepts
