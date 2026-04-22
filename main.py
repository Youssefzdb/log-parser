#!/usr/bin/env python3
"""log-parser - Security Log Parser & SIEM Integration Toolkit"""
import argparse
from modules.parser import LogParser
from modules.analyzer import ThreatAnalyzer
from modules.report import Report

def main():
    parser = argparse.ArgumentParser(description="Security Log Parser")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--format", choices=["apache", "nginx", "syslog", "auth"], default="apache")
    parser.add_argument("--output", default="log_report.html")
    args = parser.parse_args()

    print(f"[*] Parsing {args.format} logs: {args.logfile}")
    lp = LogParser(args.logfile, args.format)
    entries = lp.parse()
    print(f"[+] Parsed {len(entries)} entries")

    analyzer = ThreatAnalyzer(entries)
    threats = analyzer.analyze()
    print(f"[!] Found {len(threats)} threat indicators")

    Report(args.logfile, entries, threats).save(args.output)
    print(f"[+] Report: {args.output}")

if __name__ == "__main__":
    main()
