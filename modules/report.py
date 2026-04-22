#!/usr/bin/env python3
from datetime import datetime
from collections import Counter

class Report:
    def __init__(self, source, entries, threats):
        self.source = source
        self.entries = entries
        self.threats = threats

    def save(self, filename):
        top_ips = Counter(e.get("ip","") for e in self.entries).most_common(10)
        top_html = "".join(f"<tr><td>{ip}</td><td>{c}</td></tr>" for ip,c in top_ips)
        threat_html = "".join(f"<tr><td>{t.get('type')}</td><td>{t.get('ip','')}</td><td>{t.get('severity')}</td></tr>" for t in self.threats)
        html = f"""<!DOCTYPE html><html><head><title>Log Report</title>
<style>body{{font-family:monospace;background:#0d0d0d;color:#00ff41;padding:20px}}
h1{{color:#00ff41}}table{{width:100%;border-collapse:collapse}}td,th{{padding:6px;border:1px solid #003300}}
th{{background:#003300}}.high{{color:#ff4444}}.medium{{color:#ffaa00}}</style></head>
<body><h1>Security Log Analysis</h1>
<p>Source: {self.source} | Entries: {len(self.entries)} | Threats: {len(self.threats)} | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<h2>Top IPs</h2><table><tr><th>IP</th><th>Requests</th></tr>{top_html}</table>
<h2>Threat Indicators</h2><table><tr><th>Type</th><th>IP</th><th>Severity</th></tr>{threat_html}</table>
</body></html>"""
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] Saved: {filename}")
