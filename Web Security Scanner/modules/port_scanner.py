import socket

COMMON_PORTS = [21, 22, 80, 443]

def scan_ports(target):
    open_ports = []

    print("\n[+] Scanning ports...")

    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((target, port))

            if result == 0:
                print(f"[+] Port {port} is OPEN")
                open_ports.append(port)

            sock.close()

        except Exception as e:
            print(f"[!] Error scanning {port}: {e}")

    return open_ports
