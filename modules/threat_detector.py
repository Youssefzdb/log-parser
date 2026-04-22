from collections import Counter

SUSPICIOUS_PATHS = ["/etc/passwd", "/wp-admin", "/../", "/shell", "cmd=", "exec(", "<script>", "union select"]

class ThreatDetector:
    def __init__(self, entries):
        self.entries = entries
        self.threats = []

    def analyze(self):
        ip_counts = Counter(e.get("ip") for e in self.entries)
        
        for ip, count in ip_counts.items():
            if count > 100:
                self.threats.append({
                    "type": "Brute Force / DDoS",
                    "ip": ip,
                    "count": count,
                    "severity": "HIGH"
                })
                print(f"[!] HIGH: {ip} made {count} requests (possible brute force)")

        for entry in self.entries:
            path = entry.get("path", "")
            for susp in SUSPICIOUS_PATHS:
                if susp.lower() in path.lower():
                    self.threats.append({
                        "type": "Suspicious Path",
                        "ip": entry.get("ip"),
                        "path": path,
                        "pattern": susp,
                        "severity": "MEDIUM"
                    })
                    print(f"[!] MEDIUM: Suspicious path from {entry.get('ip')}: {path}")
                    break

            if entry.get("type") == "failed":
                self.threats.append({
                    "type": "SSH Failed Login",
                    "ip": entry.get("ip"),
                    "user": entry.get("user"),
                    "severity": "MEDIUM"
                })

        return self.threats
