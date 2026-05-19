import os 
import time
import urllib.parse
import urllib.request
import urllib.error

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


ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"


def load_env_file(env_path: Path = Path(".env")) -> None:
    """
    Loads simple KEY=VALUE pairs from .env into os.environ.
    Does not overwrite already existing environment variables.
    """
    if not env_path.exists():
        return

    with env_path.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            os.environ.setdefault(key, value)


def query_abuseipdb(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    """
    Queries AbuseIPDB for IP reputation data.
    Returns normalized enrichment fields.
    """
    params = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": str(max_age_days),
    })

    url = f"{ABUSEIPDB_API_URL}?{params}"

    request = urllib.request.Request(
        url,
        headers={
            "Key": api_key,
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = response.read().decode("utf-8", errors="ignore")

        import json
        payload = json.loads(data)
        result = payload.get("data", {})

        return {
            "abuse_confidence_score": result.get("abuseConfidenceScore", ""),
            "abuse_total_reports": result.get("totalReports", ""),
            "abuse_country": result.get("countryCode", ""),
            "abuse_usage_type": result.get("usageType", ""),
            "abuse_isp": result.get("isp", ""),
            "abuse_domain": result.get("domain", ""),
            "enrichment_source": "abuseipdb",
        }

    except urllib.error.HTTPError as error:
        return {
            "abuse_confidence_score": "",
            "abuse_total_reports": "",
            "abuse_country": "",
            "abuse_usage_type": "",
            "abuse_isp": "",
            "abuse_domain": "",
            "enrichment_source": f"abuseipdb_http_error_{error.code}",
        }

    except Exception as error:
        return {
            "abuse_confidence_score": "",
            "abuse_total_reports": "",
            "abuse_country": "",
            "abuse_usage_type": "",
            "abuse_isp": "",
            "abuse_domain": "",
            "enrichment_source": f"abuseipdb_error_{type(error).__name__}",
        }


def empty_enrichment() -> dict:
    """
    Returns empty enrichment fields when no external API key is configured.
    """
    return {
        "abuse_confidence_score": "",
        "abuse_total_reports": "",
        "abuse_country": "",
        "abuse_usage_type": "",
        "abuse_isp": "",
        "abuse_domain": "",
        "enrichment_source": "local_only",
    }


def build_report(findings: dict) -> list[dict]:
    """
    Builds a CSV-ready report with frequency, verdict, reason, evidence and enrichment.
    """
    load_env_file()

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    max_age_days = int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90"))
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

        if api_key:
            enrichment = query_abuseipdb(ip, api_key, max_age_days)
            time.sleep(1.5)
        else:
            enrichment = empty_enrichment()

        row = {
            "ip": ip,
            "count": data["count"],
            "verdict": verdict,
            "reason": reason,
            "line_numbers": ",".join(map(str, data["line_numbers"])),
            "sample_line": data["lines"][0] if data["lines"] else "",
        }

        row.update(enrichment)
        report.append(row)

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
                "abuse_confidence_score",
                "abuse_total_reports",
                "abuse_country",
                "abuse_usage_type",
                "abuse_isp",
                "abuse_domain",
                "enrichment_source",
            ],
        )

        writer.writeheader()
        writer.writerows(report)



def short_text(value: str, max_length: int = 120) -> str:
    """
    Truncates long text for readable console output.
    """
    value = str(value or "")

    if len(value) <=max_length:
        return value
    
    return value[: max_length - 3] + "..."
    

def display_value(value, default: str = "N/A") -> str:
    """
    Converts empty values to a readable default while preserving 0.
    """
    if value is None:
        return default

    if value == "":
        return default

    return str(value)



def print_console_report(report: list[dict]) -> None:
    """
    Prints a human-readable IOC report to the terminal.
    """
    if not report:
        print("[OK] No public IP indicators found.")
        return

    print()
    print("=== IOC Enrichment Report ===")
    print(f"Total indicators: {len(report)}")

    for index, row in enumerate(report, start=1):
        ip = row.get("ip", "")
        verdict = row.get("verdict", "")
        count = row.get("count", "")
        reason = row.get("reason", "")
        line_numbers = row.get("line_numbers", "")

        abuse_score = display_value(row.get("abuse_confidence_score"))
        abuse_reports = display_value(row.get("abuse_total_reports"))
        abuse_country = display_value(row.get("abuse_country"))
        abuse_usage_type = short_text(display_value(row.get("abuse_usage_type")), 35)
        abuse_isp = short_text(display_value(row.get("abuse_isp")), 45)
        abuse_domain = short_text(display_value(row.get("abuse_domain")), 35)
        enrichment_source = display_value(row.get("enrichment_source"))

        reason = short_text(reason, 100)
        sample_line = short_text(row.get("sample_line", ""), 100)

        print()
        print(f"[{index}] {ip}")
        print(f"    Verdict: {verdict}")
        print(f"    Count: {count}")
        print(f"    Reason: {reason}")
        print(f"    Lines: {line_numbers}")
        print(f"    AbuseIPDB: score={abuse_score}, reports={abuse_reports}, country={abuse_country}")
        print(f"    Network:")
        print(f"        Usage: {abuse_usage_type}")
        print(f"        ISP: {abuse_isp}")
        print(f"        Domain: {abuse_domain}")
        print(f"    Source: {enrichment_source}")
        print(f"    Sample: {sample_line}")


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

    print_console_report(report)

    print()
    print(f"[OK] CSV report saved to: {output_path}")


if __name__ == "__main__":
    main()
