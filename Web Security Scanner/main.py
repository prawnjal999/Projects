import re
import os
from modules.port_scanner import scan_ports
from modules.ssl_check import check_ssl
from modules.headers_check import check_headers


def clean_target(target):
    target = re.sub(r'^https?://', '', target)
    target = target.strip('/')
    return target


def generate_report(target, open_ports, ssl_enabled, missing_headers, risk_level):
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/{target}_report.txt"

    with open(filename, "w") as f:
        f.write("=== Web Security Scan Report ===\n\n")
        f.write(f"Target: {target}\n\n")

        f.write("Open Ports:\n")
        if open_ports:
            for port in open_ports:
                f.write(f" - {port}\n")
        else:
            f.write(" None\n")

        f.write(f"\nSSL Enabled: {ssl_enabled}\n")

        f.write("\nMissing Security Headers:\n")
        if missing_headers:
            for header in missing_headers:
                f.write(f" - {header}\n")
        else:
            f.write(" None\n")

        f.write(f"\nRisk Level: {risk_level}\n")

    print(f"\n[+] Report saved to {filename}")


def main():
    print("=== Web Security Scanner ===")

    target = input("Enter target URL (e.g. example.com): ").strip()
    cleaned_target = clean_target(target)

    print(f"\n[+] Target set to: {cleaned_target}")

    # Port Scan
    open_ports = scan_ports(cleaned_target)
    print(f"\n[+] Open Ports: {open_ports}")

    # SSL Check
    ssl_enabled = check_ssl(cleaned_target)

    # Header Check
    missing_headers = check_headers(cleaned_target)

    # Risk Scoring
    risk_score = 0

    if not ssl_enabled:
        risk_score += 2

    if len(open_ports) > 2:
        risk_score += 1

    if len(missing_headers) >= 2:
        risk_score += 2

    # Risk Level
    if risk_score <= 1:
        risk_level = "LOW"
    elif risk_score <= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    print(f"\n[!] Risk Level: {risk_level}")

    # Generate Report
    generate_report(cleaned_target, open_ports, ssl_enabled, missing_headers, risk_level)


if __name__ == "__main__":
    main()
