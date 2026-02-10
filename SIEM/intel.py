import requests
import pandas as pd
import time
import os

# --- CONFIGURATION ---
# Replace with your actual VT Key
API_KEY = "65a4b40683eca72bac8d125e82f2d4c61f5512c7f9e26d806dea2ad1126dbe62"
CSV_DB = os.path.join('database', 'events.csv')
INTEL_DB = os.path.join('database', 'intel_enriched.csv')

def get_geo_intel(ip):
    """Fetches Reputation from VirusTotal and Geo-Location from IP-API"""
    # Default values for internal traffic
    isp, score, country, lat, lon = "Internal Network", 0, "Private", 0.0, 0.0
    
    # 1. Skip enrichment for private IP ranges and internal placeholders
    if ip.startswith(('192.168.', '127.', '10.', '172.16.', '169.254.')) or ip in ["Internal/System", "Unknown", "Internal"]:
        return isp, score, country, lat, lon

    # 2. Reputation Check (VirusTotal)
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        # VT Free Tier: 4 requests/min. 
        resp = requests.get(vt_url, headers={"x-apikey": API_KEY}, timeout=5)
        if resp.status_code == 200:
            data = resp.json()['data']['attributes']
            isp = data.get('as_owner', 'Public Provider')
            score = data['last_analysis_stats']['malicious']
        elif resp.status_code == 429:
            print(f"[!] VT Rate limit hit for {ip}. Skipping reputation.")
    except Exception as e:
        print(f"[-] VT Error for {ip}: {e}")

    # 3. Geo-Location Check (IP-API)
    try:
        geo_resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        if geo_resp.get('status') == 'success':
            country = geo_resp.get('country', 'Unknown')
            lat = geo_resp.get('lat', 0.0)
            lon = geo_resp.get('lon', 0.0)
            if isp == "Public Provider":
                isp = geo_resp.get('isp', 'Public Provider')
    except:
        pass

    # Wait 15 seconds ONLY after processing a public IP to respect VT limits
    time.sleep(15) 
    return isp, score, country, lat, lon

def run_intel_engine():
    print("--- 🛡️ GSS Intel Engine: ENRICHMENT ACTIVE ---")
    processed_count = 0
    
    # Define Column Structure (Must match app.py expectations)
    cols = ['Timestamp', 'Source_IP', 'Target_Victim', 'Event', 'Status', 'Risk_Level', 
            'ISP_Owner', 'Threat_Score', 'Country', 'Latitude', 'Longitude']

    if not os.path.exists('database'):
        os.makedirs('database')

    # Initialize file with headers if it doesn't exist
    if not os.path.exists(INTEL_DB):
        pd.DataFrame(columns=cols).to_csv(INTEL_DB, index=False)
    else:
        # Load existing count to prevent re-processing the whole file on restart
        try:
            processed_count = len(pd.read_csv(CSV_DB))
        except:
            processed_count = 0

    while True:
        if os.path.exists(CSV_DB):
            try:
                df = pd.read_csv(CSV_DB)
                if len(df) > processed_count:
                    # Identify new alerts only
                    new_rows = df.iloc[processed_count:].copy()
                    
                    enriched_list = []
                    for ip in new_rows['Source_IP']:
                        print(f"[*] Processing Attacker: {ip}...")
                        intel = get_geo_intel(str(ip))
                        enriched_list.append(intel)
                    
                    # Create DF for enrichment data
                    enrich_df = pd.DataFrame(enriched_list, columns=['ISP_Owner', 'Threat_Score', 'Country', 'Latitude', 'Longitude'])
                    
                    # Merge and append
                    final_rows = pd.concat([new_rows.reset_index(drop=True), enrich_df], axis=1)
                    final_rows.to_csv(INTEL_DB, mode='a', index=False, header=False)
                    
                    processed_count = len(df)
                    print(f"✅ GSS: {len(final_rows)} alerts enriched.")
            except Exception as e:
                print(f"[-] Loop Error: {e}")
        
        time.sleep(5) 

if __name__ == "__main__":
    try:
        run_intel_engine()
    except KeyboardInterrupt:
        print("\n[!] GSS Intel Engine Shutting Down.")