import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "Protects against XSS attacks",
    "Strict-Transport-Security": "Forces HTTPS (prevents MITM)",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Stops MIME sniffing"
}

def check_headers(target):
    print("\n[+] Checking security headers...")

    url = f"http://{target}"
    missing_headers = []

    try:
        try:
            response = requests.get(url, timeout=5)
        except requests.exceptions.RequestException:
            print("[!] Could not connect to target (timeout/blocking)")
            return []

        headers = response.headers

        for header, description in SECURITY_HEADERS.items():
            if header not in headers:
                print(f"[!] Missing: {header} -> {description}")
                missing_headers.append(header)
            else:
                print(f"[+] {header} is PRESENT")

    except Exception as e:
        print(f"[!] Error checking headers: {e}")

    return missing_headers
