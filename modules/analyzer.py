#!/usr/bin/env python3
"""Threat Analyzer Module"""
from collections import Counter

SUSPICIOUS_PATHS = ["/admin", "/wp-login", "/phpmyadmin", "/.env", "/etc/passwd", "/cmd", "/shell"]
SUSPICIOUS_AGENTS = ["sqlmap", "nikto", "nmap", "masscan", "zgrab"]

class ThreatAnalyzer:
    def __init__(self, entries, threshold=10):
        self.entries = entries
        self.threshold = threshold
        self.threats = []

    def analyze(self):
        ip_counter = Counter()
        
        for entry in self.entries:
            ip = entry.get("ip", "")
            path = entry.get("path", "")
            status = entry.get("status", "")
            
            ip_counter[ip] += 1
            
            # Detect path traversal
            if "../" in path or "/etc/passwd" in path:
                self.threats.append({"type": "Path Traversal", "ip": ip, "path": path})
            
            # Detect suspicious paths
            for sp in SUSPICIOUS_PATHS:
                if sp in path:
                    self.threats.append({"type": "Suspicious Access", "ip": ip, "path": path})
                    break
            
            # Detect brute force (401/403 storms)
            if status in ["401", "403"]:
                ip_counter[f"auth_fail_{ip}"] += 1

        # Flag IPs exceeding threshold
        for ip, count in ip_counter.items():
            if not ip.startswith("auth_fail_") and count > self.threshold:
                self.threats.append({"type": "High Request Rate", "ip": ip, "count": count})

        print(f"[+] Detected {len(self.threats)} threat indicators")
        return self.threats
