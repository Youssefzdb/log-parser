#!/usr/bin/env python3
"""Threat Analyzer - Detect brute force, scanners, anomalies"""
from collections import Counter

SUSPICIOUS_PATHS = ["/admin", "/wp-login", "/.env", "/phpmyadmin", "/etc/passwd", "/../", "/shell", "/cmd"]
SCANNER_UAS = ["sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster"]

class ThreatAnalyzer:
    def __init__(self, entries):
        self.entries = entries
        self.threats = []

    def _detect_brute_force(self):
        ip_counts = Counter(e.get("ip","") for e in self.entries if e.get("status","") in ["401","403"])
        for ip, count in ip_counts.items():
            if count > 10:
                self.threats.append({"type": "Brute Force", "ip": ip, "count": count, "severity": "HIGH"})
                print(f"[!] Brute force: {ip} ({count} attempts)")

    def _detect_scanners(self):
        for e in self.entries:
            path = e.get("path", "").lower()
            for sus in SUSPICIOUS_PATHS:
                if sus in path:
                    self.threats.append({"type": "Path Scan", "ip": e.get("ip",""), "path": path, "severity": "MEDIUM"})
                    break

    def _detect_errors(self):
        error_ips = Counter(e.get("ip","") for e in self.entries if e.get("status","").startswith("5"))
        for ip, count in error_ips.items():
            if count > 20:
                self.threats.append({"type": "High Error Rate", "ip": ip, "count": count, "severity": "MEDIUM"})

    def analyze(self):
        self._detect_brute_force()
        self._detect_scanners()
        self._detect_errors()
        return self.threats
