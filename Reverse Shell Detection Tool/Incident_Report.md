# Incident Report: Reverse Shell Detection

---

## Summary

A reverse shell connection was successfully simulated and detected within a controlled lab environment.

The analysis identified suspicious communication between two internal hosts, indicating a likely reverse shell session.

---

## Environment Details

- Network Range: 192.168.1.0/24
- Attacker Machine: Kali Linux (192.168.1.10)
- Victim Machine: Ubuntu (192.168.1.9)
- Tools Used:
  - Wireshark
  - tshark
  - Python

---

## Detection Findings

### 1. Suspicious Connection
192.168.1.9 → 192.168.1.10 (Port 4444)

- Victim initiated connection to attacker
- Port 4444 identified as reverse shell port

---

### 2. TCP Handshake Analysis

- SYN packet observed:
- 192.168.1.9 → 192.168.1.10 [SYN]

  <img width="1546" height="546" alt="01-handshake" src="https://github.com/user-attachments/assets/3ffde90c-4f93-4da9-8642-17ecf98587b5" />


- Confirms:
  - Victim = 192.168.1.9
  - Attacker = 192.168.1.10

---

### 3. Interactive Traffic Pattern

- Continuous TCP session observed
- PSH, ACK packets indicate active command exchange
- TCP stream shows shell-like interaction

  <img width="1198" height="829" alt="image" src="https://github.com/user-attachments/assets/94686e78-8529-421d-a26b-f14c974c34f0" />

---

### 4. Behavioral Indicators

- Repeated communication between same hosts
- Persistent session
- Small packet sizes (command-response pattern)

---

## Investigation Steps

1. Opened PCAP in Wireshark
2. Applied filters:
   - "tcp.port == 4444"
3. Identified TCP handshake
4. Followed TCP stream
5. Observed command execution patterns
6. Extracted IP and port information
7. Automated detection using Python tool

Ouptut:

<img width="515" height="415" alt="image" src="https://github.com/user-attachments/assets/7006ac34-15c4-46da-ba74-657de01a5b50" />

---

## Detection Logic (Automation)

The custom script performed:

- TCP SYN analysis → role identification
- Port-based detection → known indicators
- Frequency analysis → behavioral detection
- Flow correlation → grouping connections

---

##  Limitations

- Detection depends on visibility of SYN packets
- Encrypted traffic may limit inspection
- False positives possible on uncommon ports
- The script finds frequent communication but cannot find a SYN packet(a fall back can be added using a "Most Likely Attacker" logic to handle a missing SYN packet.).

---

## Conclusion

The system at IP "192.168.1.9" was identified as compromised.

It established a reverse shell connection to "192.168.1.10" over TCP port 4444.

This activity strongly indicates command-and-control behavior.

---

## Recommendations

- Monitor outbound connections on uncommon ports
- Implement network-based detection rules
- Use IDS/IPS for real-time detection
- Inspect long-lived TCP sessions

---
