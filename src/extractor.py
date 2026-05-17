import re
import csv
import ipaddress
from collections import Counter
from pathlib import Path


IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ips_from_file(log_path: Path) -> list[str]:
    """
    Reads a log file and extracts valid IPv4 addresses.
    """
    ips = []

    with log_path.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            candidates = IP_REGEX.findall(line)

            for candidate in candidates:
                try:
                    ip = ipaddress.ip_address(candidate)

                    if ip.version == 4:
                        ips.append(str(ip))

                except ValueError:
                    continue

    return ips


def build_report(ips: list[str]) -> list[dict]:
    """
    Builds a report with IP frequency, private/public classification and basic risk hint.
    """
    counter = Counter(ips)
    report = []

    for ip, count in counter.most_common():
        ip_obj = ipaddress.ip_address(ip)

        is_private = ip_obj.is_private
        is_public = not is_private

        if is_private:
            risk_hint = "INTERNAL"
            triage_note = "Private/internal IP. Usually normal, check context."
        elif count >= 2:
            risk_hint = "CHECK"
            triage_note = "Repeated public IP. Good candidate for enrichment."
        else:
            risk_hint = "INFO"
            triage_note = "Single public IP. Enrich if investigation requires it."

        report.append({
            "ip": ip,
            "count": count,
            "is_private": is_private,
            "is_public": is_public,
            "risk_hint": risk_hint,
            "triage_note": triage_note,
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
		"is_private",
		"is_public",
		"risk_hint",
		"triage_note",
	])
	
        writer.writeheader()
        writer.writerows(report)


def main():
    log_path = Path("/run/media/lowborn/Storage/ioc-log-enricher/logs/sample.log")
    output_path = Path("/run/media/lowborn/Storage/ioc-log-enricher/reports/ip_report.csv")

    if not log_path.exists():
        print(f"[ERROR] Log file not found: {log_path}")
        return

    ips = extract_ips_from_file(log_path)
    report = build_report(ips)
    save_report(report, output_path)

    print(f"[OK] Extracted IPs: {len(ips)}")
    print(f"[OK] Unique IPs: {len(report)}")
    print(f"[OK] Report saved to: {output_path}")


if __name__ == "__main__":
    main()
