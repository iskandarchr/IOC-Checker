IOC Investigator
A small, easy-to-run Python utility for quick IOC triage. Queries VirusTotal, AbuseIPDB, AlienVault OTX and urlscan.io to produce a concise investigation report (also appended to results.txt) for IPs, domains and file hashes.

Features

Fast summary: vendor positives, top 3 detections, basic file metadata.
IP/domain enrichment: AbuseIPDB, OTX context, urlscan screenshots.
Handles multiple IOCs (args or comma/space/semicolon-separated).
Simple VT rate-limiting to avoid API throttling.
Appends human-readable reports to results.txt.
Requirements

Python 3.8+
Dependencies: requests, OTXv2 (add to requirements.txt)
Configuration

Edit ioc_checker.py and set your API keys:
VT_API_KEY, ABUSE_IPDB_KEY, OTX_API_KEY, URLSCAN_API_KEY

Quick start
git clone https://github.com/iskandarchr/IOC-Checker/.git
cd IOC-Checker
python -m pip install -r requirements.txt
python ioc_checker.py 8.8.8.8 1.1.1.1 d41d8cd98f00b204e9800998ecf8427e

or interactive:
python ioc_checker.py
Enter IOC(s) comma/space/semicolon-separated

Notes
VirusTotal rate-limiter: the tool enforces 4 VT requests/min; you can enable caching to reduce pauses.
AbuseIPDB is IP-only; hashes skip AbuseIPDB output.
API keys are stored in the script for now — consider using environment variables for production.



threat-intel, ioc, python, virustotal, otx, abuseipdb, urlscan
