import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\S+)'
)

class ApacheParser:
    def __init__(self, logfile):
        self.logfile = logfile

    def parse(self):
        entries = []
        try:
            with open(self.logfile, "r", errors="ignore") as f:
                for line in f:
                    m = LOG_PATTERN.match(line)
                    if m:
                        entries.append({
                            "ip": m.group("ip"),
                            "time": m.group("time"),
                            "method": m.group("method"),
                            "path": m.group("path"),
                            "status": int(m.group("status")),
                            "raw": line.strip()
                        })
        except FileNotFoundError:
            print(f"[-] Log file not found: {self.logfile}")
        print(f"[+] Parsed {len(entries)} log entries")
        return entries
