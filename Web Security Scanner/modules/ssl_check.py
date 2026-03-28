import socket
import ssl

def check_ssl(target):
    print("\n[+] Checking SSL...")

    try:
        context = ssl.create_default_context()

        with socket.create_connection((target, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                
                print("[+] SSL is ENABLED")
                return True

    except Exception as e:
        print(f"[!] SSL not available or error: {e}")
        return False
