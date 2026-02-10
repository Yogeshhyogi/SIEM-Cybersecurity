import time
import re
import os
import csv

# --- CONFIGURATION ---
LOG_FILE = os.path.join('logs', 'syslog.log')
CSV_DB = os.path.join('database', 'events.csv')
DB_DIR = 'database'

# Ensure the database directory exists
if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

# Initialize CSV with GSS Standard Headers
if not os.path.exists(CSV_DB) or os.stat(CSV_DB).st_size == 0:
    with open(CSV_DB, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'Source_IP', 'Target_Victim', 'Event', 'Status', 'Risk_Level'])

def parse_log(line):
    # 1. Extract Target Victim IP (The IP appearing BEFORE the '|')
    victim_match = re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
    target_victim = victim_match.group(1) if victim_match else "Unknown_VM"

    source_ip = "Internal/System"
    event_type, status, risk = "General Log", "Info", "Low"
    line_lower = line.lower()

    # --- 2. DETECTION LOGIC BY ATTACK VECTOR ---

    # A. WEB ATTACK & SCANNER DETECTION
    if "web_server:" in line:
        try:
            web_part = line.split("web_server:")[1]
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', web_part)
            source_ip = ip_match.group(1) if ip_match else "Unknown"
        except IndexError:
            source_ip = "Unknown"
        
        # Attack Signatures
        sqli_patterns = ["union", "select", "null", "--", "%27", "concat", "information_schema"]
        xss_patterns = ["<script>", "script", "%3cscript%3e", "alert(", "onload", "onerror"]
        scanner_patterns = ["nmap", "nikto", "dirb", "sqlmap", "gss-test-agent"]

        if any(x in line_lower for x in sqli_patterns) and "select" in line_lower:
            event_type, status, risk = "SQL Injection Attempt", "Exploit Attempt", "High"
        elif any(x in line_lower for x in xss_patterns):
            event_type, status, risk = "Cross-Site Scripting (XSS)", "Exploit Attempt", "High"
        elif any(x in line_lower for x in scanner_patterns):
            event_type, status, risk = "Nmap/Recon Scan", "Scanning", "Medium"
        else:
            event_type, status, risk = "Web Traffic", "Access", "Low"

    # B. SSH BRUTE FORCE DETECTION
    elif any(x in line for x in ["Failed password", "authentication failure", "connection dropped", "MaxStartups"]):
        attacker_match = re.search(r'(?:rhost=|from\s|from\s\[)([\d\.]+)', line)
        source_ip = attacker_match.group(1) if attacker_match else "Unknown"
        
        if "MaxStartups" in line or "connection dropped" in line:
            event_type = "SSH Denial of Service"
        else:
            event_type = "SSH Brute Force"
        status, risk = "Auth Failure", "High"

    # C. SUCCESSFUL LOGIN DETECTION
    elif "Accepted password" in line or "session opened" in line:
        if "cron" not in line:
            attacker_match = re.search(r'(?:rhost=|from\s)([\d\.]+)', line)
            source_ip = attacker_match.group(1) if attacker_match else "Internal"
            event_type, status, risk = "System Login", "Access Granted", "Medium"

    return [time.strftime("%Y-%m-%d %H:%M:%S"), source_ip, target_victim, event_type, status, risk]

def monitor():
    print(f"--- 🛡️ GATE (GSS) ---")
    print(f"[*] Multi-Threat Engine Active. Monitoring: {LOG_FILE}")
    
    if not os.path.exists(LOG_FILE):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        open(LOG_FILE, 'a').close()

    with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(0, 2) 
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            alert = parse_log(line)
            
            if alert[5] in ["Medium", "High"]:
                print(f"🚨 ALERT: {alert[3]} from {alert[1]} against {alert[2]}")
                with open(CSV_DB, 'a', newline='', encoding='utf-8') as db:
                    csv.writer(db).writerow(alert)

if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n[!] GSS Detection Engine Stopped.")