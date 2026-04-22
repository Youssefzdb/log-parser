#!/usr/bin/env python3
"""Log Parser Module"""
import re
from datetime import datetime

PATTERNS = {
    "apache": r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\S+)',
    "nginx": r'(?P<ip>\S+) - \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\d+)',
    "ssh": r'(?P<time>\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: (?P<event>.*)',
    "syslog": r'(?P<time>\w+ \d+ \d+:\d+:\d+) (?P<host>\S+) (?P<process>\S+): (?P<message>.*)',
}

class LogParser:
    def __init__(self, filepath, log_type="apache"):
        self.filepath = filepath
        self.pattern = re.compile(PATTERNS.get(log_type, PATTERNS["apache"]))

    def parse(self):
        entries = []
        try:
            with open(self.filepath, "r", errors="ignore") as f:
                for line in f:
                    m = self.pattern.match(line.strip())
                    if m:
                        entries.append(m.groupdict())
        except FileNotFoundError:
            print(f"[-] File not found: {self.filepath}")
        print(f"[+] Parsed {len(entries)} log entries")
        return entries
