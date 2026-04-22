#!/usr/bin/env python3
"""
log-parser - Security Log Parser & SIEM Integration Toolkit
Parses Apache, Nginx, SSH, and Windows Event logs for threats
"""
import argparse
from modules.apache_parser import ApacheParser
from modules.ssh_parser import SSHParser
from modules.threat_detector import ThreatDetector
from modules.report import LogReport

def main():
    parser = argparse.ArgumentParser(description="Security Log Parser")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--type", choices=["apache", "nginx", "ssh", "auto"], default="auto")
    parser.add_argument("--output", default="log_report.html")
    args = parser.parse_args()

    print(f"[*] Parsing log file: {args.logfile}")

    if args.type in ["apache", "nginx", "auto"]:
        p = ApacheParser(args.logfile)
        entries = p.parse()
    elif args.type == "ssh":
        p = SSHParser(args.logfile)
        entries = p.parse()
    else:
        entries = []

    detector = ThreatDetector(entries)
    threats = detector.analyze()

    report = LogReport(args.logfile, entries, threats)
    report.save(args.output)
    print(f"[+] Found {len(threats)} threats. Report: {args.output}")

if __name__ == "__main__":
    main()
