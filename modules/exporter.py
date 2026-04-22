#!/usr/bin/env python3
"""SIEM Exporter - Export to JSON/CEF format"""
import json
from datetime import datetime

class SIEMExporter:
    def __init__(self, entries, threats):
        self.entries = entries
        self.threats = threats

    def export(self, filename):
        data = {
            "generated": datetime.now().isoformat(),
            "total_entries": len(self.entries),
            "total_threats": len(self.threats),
            "threats": self.threats,
            "sample_entries": self.entries[:100]
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] SIEM export saved: {filename}")
