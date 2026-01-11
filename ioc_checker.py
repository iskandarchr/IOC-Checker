
import ipaddress
import re
import sys
import requests
import time
from collections import deque
from OTXv2 import OTXv2, IndicatorTypes
import os
from dotenv import load_dotenv

# --- CONFIGURATION (INPUT KEYS BELOW) ---
load_dotenv()  # optional: reads .env for local development

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_IPDB_KEY = os.getenv("ABUSE_IPDB_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
if not VT_API_KEY:
    print("Warning: VT_API_KEY not set")
# ----------------------------------------

# Override built-in print to also append to results.txt when printing to stdout
import builtins
_orig_print = builtins.print
def print(*args, sep=' ', end='\n', file=None, flush=False):
    _orig_print(*args, sep=sep, end=end, file=file, flush=flush)
    try:
        # Only append when printing to stdout (file is None or sys.stdout)
        if file is None or file is sys.stdout:
            with open('results.txt', 'a', encoding='utf-8') as f:
                f.write(sep.join(map(str, args)) + ('' if end == '' else end))
    except Exception:
        pass

def get_virustotal_data(ioc, ioc_type):
    """Reputation Check with simple rate limiting and retry-on-429.

    Returns (summary_dict or None, gui_link)
    """
    url = "https://www.virustotal.com/api/v3/"
    headers = {"x-apikey": VT_API_KEY}

    endpoints = {
        "IP": ("ip_addresses", "ip-address"),
        "DOMAIN": ("domains", "domain"),
        "HASH": ("files", "file")
    }

    if ioc_type not in endpoints:
        return None, None
    api_endpoint, gui_path = endpoints[ioc_type]

    # Initialize request timestamp deque for rate limiting (4 requests per 60s)
    global _vt_request_times
    try:
        _vt_request_times
    except NameError:
        _vt_request_times = deque()

    # Purge entries older than 60 seconds
    now = time.time()
    while _vt_request_times and now - _vt_request_times[0] > 60:
        _vt_request_times.popleft()

    # If we've reached the limit, wait until earliest timestamp expires
    if len(_vt_request_times) >= 4:
        wait = 60 - (now - _vt_request_times[0])
        wait = max(1, int(wait) + 1)
        print(f"VirusTotal rate limit reached (4/min). Sleeping {wait} seconds...")
        time.sleep(wait)

    full_url = f"{url}{api_endpoint}/{ioc}"
    try:
        # Try the request, retry once on 429 and respect Retry-After header
        for attempt in range(2):
            response = requests.get(full_url, headers=headers)
            if response.status_code == 429:
                ra = response.headers.get('Retry-After')
                try:
                    sleep_for = int(ra) if ra else 60
                except Exception:
                    sleep_for = 60
                print(f"VirusTotal returned 429; sleeping {sleep_for} seconds before retry...")
                time.sleep(sleep_for)
                continue
            break

        if response.status_code == 200:
            # record timestamp
            _vt_request_times.append(time.time())
            data = response.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            total = sum(stats.values()) if stats else 0

            # Top detections: engines with category malicious or suspicious
            top = []
            results = data.get('last_analysis_results', {}) or {}
            for eng, info in results.items():
                cat = info.get('category')
                if cat in ('malicious', 'suspicious'):
                    top.append((eng, info.get('result')))
            # if none flagged, show up to 3 engines that have any non-empty result
            if not top:
                for eng, info in results.items():
                    res = info.get('result')
                    if res:
                        top.append((eng, res))
            top = top[:3]

            summary = {
                'malicious': int(stats.get('malicious', 0)),
                'total': int(total),
                'top_detections': top,
                'type_description': data.get('type_description'),
                'size': data.get('size'),
                'first_submission_date': data.get('first_submission_date'),
                'meaningful_name': data.get('meaningful_name')
            }
            return summary, f"https://www.virustotal.com/gui/{gui_path}/{ioc}"
        else:
            # Non-200 (and non-429 after retry) — return None but keep GUI link
            return None, f"https://www.virustotal.com/gui/{gui_path}/{ioc}"
    except Exception:
        pass
    return None, f"https://www.virustotal.com/gui/{gui_path}/{ioc}"

def get_abuseipdb_data(ip):
    """ISP & Reputation Check (IP ONLY)."""
    # The AbuseIPDB API strictly requires an IP address. 
    # For domains, we will just generate the link in the main function.
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': ABUSE_IPDB_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                "isp": data.get("isp", "Unknown ISP"),
                "country": data.get("countryCode", "Unknown Location"),
                "score": data.get("abuseConfidenceScore", 0),
                "ip": ip
            }
    except:
        pass
    return None

def get_otx_data(ioc, ioc_type):
    """Context Check (Campaigns)."""
    if "YOUR_ALIENVAULT" in OTX_API_KEY: return None
    
    try:
        otx = OTXv2(OTX_API_KEY)
        if ioc_type == "IP":
            details = otx.get_indicator_details_full(IndicatorTypes.IPv4, ioc)
        elif ioc_type == "DOMAIN":
            details = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, ioc)
        elif ioc_type == "HASH":
            details = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, ioc)
        else:
            return None
        
        pulses = details.get('general', {}).get('pulse_info', {}).get('pulses', [])
        return {"found": len(pulses) > 0, "count": len(pulses), "names": [p['name'] for p in pulses[:3]]}
    except:
        return {"error": True}

def get_urlscan_data(ioc, ioc_type):
    """Evidence Check (Screenshots)."""
    if "YOUR_URLSCAN" in URLSCAN_API_KEY: return None
    if ioc_type == "HASH": return None

    headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
    search_url = f"https://urlscan.io/api/v1/search/?q={ioc}"
    
    try:
        response = requests.get(search_url, headers=headers)
        if response.status_code == 200:
            results = response.json().get('results', [])
            if results:
                last_scan = results[0]
                return {
                    "found": True,
                    "screenshot": last_scan.get('screenshot', 'N/A'),
                    "report_link": last_scan.get('result', 'N/A')
                }
    except:
        pass
    return {"found": False}

def analyze_ioc(ioc):
    # 1. Detect Type
    try:
        ipaddress.ip_address(ioc)
        ioc_type = "IP"
    except ValueError:
        if re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
            ioc_type = "HASH"
        else:
            ioc_type = "DOMAIN"

    print(f"\n--- Investigating: {ioc} ({ioc_type}) ---")

    # 2. Gather Intelligence
    vt_stats, vt_link = get_virustotal_data(ioc, ioc_type)
    
    # Check AbuseIPDB API only if it is an IP
    abuse_data = None
    if ioc_type == "IP":
        abuse_data = get_abuseipdb_data(ioc)
    
    otx_data = get_otx_data(ioc, ioc_type)
    urlscan_data = get_urlscan_data(ioc, ioc_type)

    # 3. Report Generation
    
    # Header Info
    if abuse_data:
        isp_info = abuse_data['isp']
        loc_info = abuse_data['country']
        print(f"\nProvider is by {isp_info} located in {loc_info}\n")
    else:
        # For Domains, we rely on the user checking the AbuseIPDB link manually
        print(f"\nTarget Entity: {ioc}\n")

    # --- VirusTotal ---
    if vt_stats:
        print(f"VirusTotal: {vt_stats['malicious']}/{vt_stats['total']} vendors flagged this.")
    else:
        print("VirusTotal: Data unavailable.")
    print(f"{vt_link}\n")

    # --- AbuseIPDB ---
    # Skip AbuseIPDB reporting entirely for file hashes
    if ioc_type == "HASH":
        pass
    else:
        if abuse_data:
            # IP Case: Show API Data
            status = f"Found (Confidence: {abuse_data['score']}%)" if abuse_data['score'] > 0 else "Clean / Not Found"
            print(f"AbuseIPDB: {status}")
            print(f"https://www.abuseipdb.com/check/{abuse_data['ip']}\n")
        else:
            # Domain Case: Show Link Only (Website will auto-translate)
            print(f"AbuseIPDB: Click to view (Auto-resolves on site)")
            print(f"https://www.abuseipdb.com/check/{ioc}\n")

    # --- AlienVault OTX ---
    otx_link = f"https://otx.alienvault.com/indicator/{ioc_type.lower()}/{ioc}"
    if otx_data and otx_data.get("found"):
        print(f"AlienVault OTX: Found in {otx_data['count']} campaigns (Context):")
        for name in otx_data['names']:
            print(f" - {name}")
    else:
        print("AlienVault OTX: No active campaigns found.")
    print(f"{otx_link}\n")

    # --- URLScan.io ---
    if urlscan_data and urlscan_data.get("found"):
        print(f"URLScan.io: Evidence Found")
        print(f" - Screenshot: {urlscan_data['screenshot']}")
        print(f" - Full Report: {urlscan_data['report_link']}\n")
    else:
        print("URLScan.io: No recent visual evidence found.\n")

    # --- Verdict ---
    malicious_count = vt_stats['malicious'] if vt_stats else 0
    otx_confirmed = otx_data and otx_data.get("found", False)
    abuse_confirmed = abuse_data and abuse_data['score'] > 50
    
    if malicious_count > 2 or abuse_confirmed:
        verdict = "True Positive (Malicious)"
        action = "IOC confirmed malicious. Block immediately."
    elif malicious_count > 0 or otx_confirmed:
        verdict = "Suspicious"
        action = "Review OTX context and URLScan evidence before blocking."
    else:
        verdict = "Clean"
        action = "False positive, IOC will be removed from IOC management."

    print(f"Verdict: {verdict}, {action}\n")

if __name__ == "__main__":
    def _run_list(iocs):
        for itm in iocs:
            i = itm.strip()
            if not i:
                continue
            analyze_ioc(i)

    if len(sys.argv) > 1:
        # Accept multiple command-line IOCs: either separate args or a single
        # arg containing comma/space/semicolon/newline-separated values.
        args = sys.argv[1:]
        if len(args) == 1 and any(sep in args[0] for sep in [',', ';', '\n', ' ']):
            items = [s for s in re.split(r'[\s,;]+', args[0]) if s]
            _run_list(items)
        else:
            _run_list(args)
    else:
        user_input = input("Enter IOC(s) (comma/space/semicolon separated): ").strip()
        items = [s for s in re.split(r'[\s,;]+', user_input) if s]
        _run_list(items)