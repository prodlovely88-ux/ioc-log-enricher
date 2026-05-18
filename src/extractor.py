import argparse
import csv
import ipaddress
import re
from collections import defaultdict
from pathlib import Path


IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


HIGH_KEYWORDS = [
    "failed password",
    "invalid user",
    "authentication failure",
    "bruteforce",
    "brute force",
]


SUSPICIOUS_KEYWORDS = [
    "failed",
    "denied",
    "unauthorized",
    "login",
    "ssh",
    "rdp",
]


def is_valid_ipv4(candidate: str) -> bool:
    """
    Checks if a string is a valid IPv4 address.
    """
    try:
        ip = ipaddress.ip_address(candidate)
        return ip.version == 4
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    """
    Checks if an IP address is globally routable.

    This filters out private, loopback, link-local, multicast,
    reserved and other non-public addresses.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version == 4 and ip_obj.is_global
    except ValueError:
        return False


def extract_ips_from_line(line: str) -> list[str]:
    """
    Extracts valid IPv4 addresses from one log line.
    """
    candidates = IP_REGEX.findall(line)
    return [ip for ip in candidates if is_valid_ipv4(ip)]


def classify_context(lines: list[str], count: int) -> tuple[str, str]:
    """
    Builds a basic SOC verdict based on log context and IP frequency.
    """
    joined = " ".join(lines).lower()

    has_high_context = any(keyword in joined for keyword in HIGH_KEYWORDS)
    has_suspicious_context = any(keyword in joined for keyword in SUSPICIOUS_KEYWORDS)

    if has_high_context and count >= 3:
        return "HIGH", "Multiple failed login or invalid user events"

    if has_high_context:
        return "SUSPICIOUS", "Failed login or invalid user context"

    if has_suspicious_context and count >= 3:
        return "SUSPICIOUS", "Repeated suspicious authentication or network activity"

    if has_suspicious_context:
        return "CHECK", "Suspicious keyword found, check surrounding log context"

    if count >= 5:
        return "CHECK", "Repeated public IP activity without strong attack keywords"

    return "INFO", "Public IP found without suspicious context"


def analyze_log(log_path: Path) -> dict:
    """
    Reads a log file, extracts IPs, keeps context lines and line numbers.
    """
    findings = defaultdict(lambda: {
        "count": 0,
        "lines": [],
        "line_numbers": [],
    })

    with log_path.open("r", encoding="utf-8", errors="ignore") as file:
        for line_number, line in enumerate(file, start=1):
            clean_line = line.strip()
            ips = extract_ips_from_line(clean_line)

            for ip in ips:
                if not is_public_ip(ip):
                    continue

                findings[ip]["count"] += 1
                findings[ip]["lines"].append(clean_line)
                findings[ip]["line_numbers"].append(line_number)

    return findings


def build_report(findings: dict) -> list[dict]:
    """
    Builds a CSV-ready report with frequency, verdict, reason and evidence.
    """
    report = []

    sorted_findings = sorted(
        findings.items(),
        key=lambda item: item[1]["count"],
        reverse=True,
    )

    for ip, data in sorted_findings:
        verdict, reason = classify_context(
            lines=data["lines"],
            count=data["count"],
        )

        report.append({
            "ip": ip,
            "count": data["count"],
            "verdict": verdict,
            "reason": reason,
            "line_numbers": ",".join(map(str, data["line_numbers"])),
            "sample_line": data["lines"][0] if data["lines"] else "",
        })

    return report


def save_report(report: list[dict], output_path: Path) -> None:
    """
    Saves the report to CSV.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "ip",
                "count",
                "verdict",
                "reason",
                "line_numbers",
                "sample_line",
            ],
        )

        writer.writeheader()
        writer.writerows(report)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and triage public IPv4 indicators from log files."
    )

    parser.add_argument(
        "log_path",
        help="Path to input log file",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="reports/ip_report.csv",
        help="Path to output CSV report",
    )

    args = parser.parse_args()

    log_path = Path(args.log_path)
    output_path = Path(args.output)

    if not log_path.exists():
        print(f"[ERROR] Log file not found: {log_path}")
        return

    findings = analyze_log(log_path)
    report = build_report(findings)
    save_report(report, output_path)

    print(f"[OK] Public IP indicators: {len(report)}")
    print(f"[OK] Report saved to: {output_path}")


if __name__ == "__main__":
    main()
