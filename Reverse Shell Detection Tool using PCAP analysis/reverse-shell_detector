import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime

# ARGUMENT CHECK
if len(sys.argv) != 2:
    print("\nUsage: python3 detect_reverse_shell.py <pcap_file>\n")
    sys.exit(1)

pcap = sys.argv[1]

# HEADER
print("\n" + "="*60)
print("        Reverse Shell Detection Report")
print("="*60)

print(f"\n[+] File : {pcap}")
print(f"[+] Time : {datetime.now()}\n")

# STEP 1: GET INITIATORS (SYN PACKETS)
syn_cmd = f'tshark -r {pcap} -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e ip.dst -e tcp.dstport'
syn_output = subprocess.getoutput(syn_cmd)

initiators = {}  # (src, dst, port) → victim/attacker mapping

for line in syn_output.split("\n"):
    parts = line.split()
    if len(parts) == 3:
        src, dst, port = parts
        initiators[(src, dst, port)] = (src, dst)  # src = victim, dst = attacker

# STEP 2: GET ALL TCP TRAFFIC
cmd = f'tshark -r {pcap} -Y "tcp" -T fields -e ip.src -e ip.dst -e tcp.dstport'
output = subprocess.getoutput(cmd)

connections = []
port_counter = Counter()
flow_counter = Counter()

for line in output.split("\n"):
    parts = line.split()
    if len(parts) == 3:
        src, dst, port = parts
        
        # Normalize connection (avoid duplicates)
        pair = tuple(sorted([src, dst]))
        connections.append(pair)
        
        port_counter[port] += 1
        flow_counter[pair] += 1

# DETECTION LOGIC
suspicious_ports = {"4444", "5555", "6666", "9001", "1337"}
results = defaultdict(list)

for (src, dst, port), (victim, attacker) in initiators.items():
    pair = tuple(sorted([src, dst]))

    # Known ports
    if port in suspicious_ports:
        results[pair].append(("HIGH", port, "Known reverse shell port"))

    # Uncommon ports
    elif int(port) > 1024 and port_counter[port] < 20:
        results[pair].append(("MEDIUM", port, "Uncommon port usage"))

# Behavioral detection
for pair, count in flow_counter.items():
    if count > 10:
        results[pair].append(("MEDIUM", "-", f"Frequent communication ({count} packets)"))

# OUTPUT
if results:
    print("[!] Suspicious Activity Detected:\n")

    for (ip1, ip2), issues in results.items():

        # Find correct victim/attacker from SYN
        victim, attacker = None, None

        for (s, d, p), (v, a) in initiators.items():
            if set([s, d]) == set([ip1, ip2]):
                victim, attacker = v, a
                break

        print(f"   Connection: {ip1} ↔ {ip2}\n")

        for severity, port, reason in issues:
            print(f"      [{severity}] {reason}")
            print(f"         Victim   : {victim}")
            print(f"         Attacker : {attacker}")
            if port != "-":
                print(f"         Port     : {port}")
            print()

else:
    print("[+] No suspicious activity detected\n")

# VERDICT
print("="*60)

if any(sev == "HIGH" for issues in results.values() for sev, _, _ in issues):
    print("[!] Verdict: HIGH confidence of reverse shell activity")
elif results:
    print("[!] Verdict: MEDIUM confidence (suspicious behavior detected)")
else:
    print("[+] Verdict: LOW confidence (no strong indicators)")

print("="*60 + "\n")
