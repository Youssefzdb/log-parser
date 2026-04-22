#!/usr/bin/env python3
"""log-parser - Security Log Parser & SIEM Integration Toolkit"""
import argparse
from modules.parser import LogParser
from modules.analyzer import ThreatAnalyzer
from modules.exporter import SIEMExporter

def main():
    parser = argparse.ArgumentParser(description="Security Log Parser")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--type", choices=["apache", "nginx", "ssh", "syslog"], default="apache")
    parser.add_argument("--output", default="siem_export.json")
    parser.add_argument("--threshold", type=int, default=10, help="Alert threshold")
    args = parser.parse_args()

    print(f"[*] Parsing {args.type} log: {args.logfile}")
    lp = LogParser(args.logfile, args.type)
    entries = lp.parse()
    
    analyzer = ThreatAnalyzer(entries, args.threshold)
    threats = analyzer.analyze()
    
    exporter = SIEMExporter(entries, threats)
    exporter.export(args.output)
    print(f"[+] Exported {len(entries)} entries, {len(threats)} threats to {args.output}")

if __name__ == "__main__":
    main()
