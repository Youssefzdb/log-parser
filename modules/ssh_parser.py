import re

class SSHParser:
    def __init__(self, logfile):
        self.logfile = logfile

    def parse(self):
        entries = []
        patterns = {
            "failed": re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
            "accepted": re.compile(r"Accepted password for (\S+) from (\S+)"),
            "invalid": re.compile(r"Invalid user (\S+) from (\S+)"),
        }
        try:
            with open(self.logfile, "r", errors="ignore") as f:
                for line in f:
                    for event_type, pattern in patterns.items():
                        m = pattern.search(line)
                        if m:
                            entries.append({
                                "type": event_type,
                                "user": m.group(1),
                                "ip": m.group(2),
                                "raw": line.strip()
                            })
        except FileNotFoundError:
            print(f"[-] Log file not found: {self.logfile}")
        return entries
