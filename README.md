# log-parser 🔍

Security Log Parser & SIEM Integration Toolkit

## Features
- Parse Apache, Nginx, SSH, and Syslog formats
- Detect brute force attacks, path traversal, suspicious access
- Export threat data to JSON for SIEM integration

## Usage
```bash
pip install -r requirements.txt
python main.py /var/log/apache2/access.log --type apache --threshold 100
```

## Output
- Parsed log entries
- Detected threats with IP, type, and context
- JSON export compatible with Splunk/ELK
