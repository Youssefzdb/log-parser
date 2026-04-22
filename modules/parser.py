#!/usr/bin/env python3
"""Log Parser - Supports Apache, Nginx, Syslog, Auth logs"""
import re
from datetime import datetime

PATTERNS = {
    "apache": r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\S+)',
    "nginx":  r'(?P<ip>\S+) - \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\d+)',
    "auth":   r'(?P<time>\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: (?P<message>.+)',
    "syslog": r'(?P<time>\w+ \d+ \d+:\d+:\d+) (?P<host>\S+) (?P<process>\S+): (?P<message>.+)',
}

class LogParser:
    def __init__(self, filepath, fmt="apache"):
        self.filepath = filepath
        self.pattern = re.compile(PATTERNS.get(fmt, PATTERNS["apache"]))
        self.fmt = fmt

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
        return entries
