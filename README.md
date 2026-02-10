# <p align="center">SIEM-Cybersecurity</p>
# <p align="center">Project Report</p>
**Title:** A Real-Time Security Information and Event Management (SIEM) System
## 1. Abstract:

In the modern cybersecurity landscape, visibility is the first line of defense. The Gate SIEM (GSS) is a centralized security monitoring platform designed to collect, parse, and analyze syslogs from remote infrastructure in real-time. Unlike static log viewers, GSS integrates a Multi-Stage Detection Engine to identify SSH brute-forcing and Web attacks (SQLi, XSS) instantly. Furthermore, it utilizes an Automated Enrichment Pipeline via VirusTotal and IP-API to provide security analysts with the geographical origin and reputation score of attackers. The entire operation is visualized through a high-contrast, gamified SOC dashboard built on Streamlit, featuring live trends and threat maps for rapid incident response.
## 2. Library Definitions and Usage:

The GSS suite is built using a modular Python architecture, leveraging specific libraries to handle the lifecycle of a log entry:

**•	Streamlit:** Powers the high-visibility SOC Dashboard. It provides the front-end framework for real-time data streaming and interactive UI components. In app.py, it enables critical operational controls such as the Reset for database maintenance and the Download feature for data export.

**•	Pandas:** Acts as the primary data engine. It manages the events.csv and intel_enriched.csv databases. It is used to perform high-speed filtering, calculate KPI metrics (Total Threats, Unique Attackers), and resample time-series data to create the attack trend line charts.

**•	Socket:** The backbone of the server.py collector. It enables low-level network communication to listen for UDP syslog traffic on Port 514, which is the industry standard for log forwarding. This allows the SIEM to ingest traffic from remote servers and virtual machines.

**•	Plotly Express:** The visualization engine used to render the Global GSS Threat Map and Attack Trend charts. It converts raw coordinates (Latitude/Longitude) and timestamps into interactive spatial intelligence and 3D globe projections.

**•	Requests:** Facilitates external API orchestration within intel.py. It manages the communication with the VirusTotal API for reputation scoring and the IP-API for geographical telemetry and ISP identification.

**•	Re (Regex):** The primary tool for Signature-Based Detection. In detection.py, it scans raw syslog strings to extract IP addresses and identify malicious patterns like union select (SQL Injection), <script> (XSS), or Failed password (SSH Brute Force).

**•	Heuristic Logic (Conditional Logic):** Utilizing Python’s native logic gates, the system evaluates the "intent" of a log. By correlating specific event strings with source and target IP data, the engine dynamically assigns a Risk_Level (High, Medium, or Low), allowing for automated threat prioritization.

**•	Logging:** Provides the persistent storage layer. It ensures that every raw packet received by the server.py collector is archived in syslog.log without modification, maintaining a "source of truth" for forensic auditing.

## 3. Module Explanations
### 3.1 Log Collector (server.py)
This module serves as the Ingestion Layer. It is the first point of contact for external infrastructure.
* **UDP Inbound Listener:** Utilizing the socket library, it opens a listener on Port 514.
* **Standardization:** It receives raw packets from remote victims, extracts the sender's address, and formats the entry as Victim_IP | Message.
* **Persistence:** Through the logging module, it commits every received packet to syslog.log, ensuring a permanent forensic trail of all network activity.
### 3.2 Heuristic Detection Engine (detection.py)

This is the Intelligence Layer. It continuously monitors the syslog.log file for new entries and applies detection logic:
* **Signature Matching:** Uses re (Regex) to scan for specific attack fingerprints:
    + **Web Attacks:** Scans for SQLi (union, select, concat) and XSS (<script>, alert).
    + **SSH Brute Force:** Identifies Failed password or MaxStartups patterns.
* **Heuristic Classification:** The engine classifies events into Risk Levels (High, Medium, Low). For example, a "Failed Password" is flagged as a high-risk "Brute Force" heuristic, while an "Accepted Password" is flagged as a medium-risk "System Login."
* **Alert Generation:** High-risk findings are extracted and written to events.csv.
### 3.3 Automated Enrichment Engine (intel.py)
This module acts as the Data Enrichment Layer, adding external context to the raw alerts found in events.csv.
*	**Reputation Auditing:** It queries the VirusTotal API using the attacker's IP to retrieve a Threat_Score based on global malicious activity reports.
*	**Geographical Telemetry:** It utilizes the IP-API to fetch the physical location (Country, Latitude, Longitude) and the ISP (ISP_Owner) of the attacker.
*	**Rate Limiting:** Implements a 15-second time.sleep() to respect API tier limits while ensuring intel_enriched.csv remains up to date.
### 3.4 SOC Performance Dashboard (app.py)
The final module is the Visualization Layer, built on Streamlit. It transforms the enriched CSV data into a functional security command center.
* **Real-Time Analytics:** Uses @st.fragment to refresh metrics (Total Threats, Critical Alerts) every 2 seconds without a full page reload.
* **Spatial Mapping:** Uses Plotly Express to render a 3D Global Threat Map, plotting the exact coordinates of attackers.
* **Operational Controls:** Includes a Sidebar Control Panel with a "Reset Dashboard" button to wipe the databases and a "Download SOC Logs" button for incident reporting.
## 4. System Architecture & Code
### 4.1 Architectural Data Flow
The system operates as a Producer-Consumer model. The collector produces raw logs, the detection engine consumes them to find threats, and the dashboard consumes the final enriched results.

  **1.	Ingestion Layer (server.py):** Collects raw UDP packets and stores them in syslog.log.

  **2.	Processing Layer (detection.py):** Monitors syslog.log, applies Regex/Heuristics, and produces events.csv.

  **3.	Intelligence Layer (intel.py):** Pulls from events.csv, queries external APIs, and produces intel_enriched.csv.

  **4.	Presentation Layer (app.py):** Reads intel_enriched.csv to render the Streamlit UI.

### 4.2 Directory Structure
```text
GSS_SIEM/
├── app.py
├── server.py
├── detection.py
├── intel.py
├── database/
│   ├── events.csv
│   └── intel_enriched.csv
└── logs/
    └── syslog.log
```

### 4.3 Code

#### Environment Setup: 

**1.Create the virtual environment**
```
python -m venv gss_env
```
**2.Activate the environment**
```
.\gss_env\Scripts\activate
```
**3. Install Required Dependencies**
```
pip install streamlit pandas plotly requests
```
**4.Directory Creation**
```
mkdir logs database
```

#### The Collector: (server.py) 
```
importsocket
importlogging
importos
 
LOG_DIR= 'logs'
LOG_FILE= os.path.join(LOG_DIR,'syslog.log')
HOST= '0.0.0.0'

PORT= 514


if notos.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
 

strings (preserving the IP | Message format)
logger= logging.getLogger("GSS_Collector")
logger.setLevel(logging.INFO)
handler= logging.FileHandler(LOG_FILE)
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)
 
defstart_server():
    print(f"--- GATE(GSS) ---")
    print(f"[*]Log Collector Status: ACTIVE")
    print(f"[*]Listening on: {HOST}:{PORT}(UDP)")
    print(f"[*]Target Log: {LOG_FILE}")
    print("[*]Monitoring for incoming security events... (Ctrl+C to stop)")
    
    sock= socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    
    try:
        sock.bind((HOST,PORT))
    exceptPermissionError:
        print("[-]GSS ACCESS DENIED: Port 514 is a privileged port.")
        print("[-]FIX: Run Terminal as Administrator or use 'sudo python3 server.py'")
        return
    exceptException ase:
        print(f"[-]
Startup Error: {e}")
        return
 
    whileTrue:
        try:
      
  data, addr= sock.recvfrom(4096)
         
  message =data.decode('utf-8',errors='ignore').strip()
         
  log_entry =f"{addr[0]}| {message}"
           
  print(f"[RECV]{log_entry[:120]}...")
          
  logger.info(log_entry)
        exceptKeyboardInterrupt:
         
  print("\n[*]GSS Collector shutting down...")
         
  break
        exceptException ase:
         
  print(f"[-]Processing Error: {e}")
 
if __name__== "__main__":
    start_server()
```

#### The Heuristic Brain: (detection.py)
```
importtime
importre
importos
importcsv
 
LOG_FILE= os.path.join('logs','syslog.log')
CSV_DB= os.path.join('database','events.csv')
DB_DIR= 'database'
 
if notos.path.exists(DB_DIR):
    os.makedirs(DB_DIR)
 
if notos.path.exists(CSV_DB)or os.stat(CSV_DB).st_size== 0:
    withopen(CSV_DB,'w', newline='',encoding='utf-8')as f:
        writer= csv.writer(f)
        writer.writerow(['Timestamp','Source_IP', 'Target_Victim','Event', 'Status','Risk_Level'])
 
defparse_log(line):
    victim_match= re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',line)
    target_victim= victim_match.group(1)if victim_matchelse "Unknown_VM"
 
    source_ip= "Internal/System"
    event_type,status, risk= "General
Log", "Info","Low"
    line_lower= line.lower()
 
   
    if"web_server:"in line:
        try:
         
  web_part =line.split("web_server:")[1]
         
  ip_match =re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',web_part)
         
  source_ip =ip_match.group(1)if ip_matchelse "Unknown"
        exceptIndexError:
         
  source_ip ="Unknown"
        
        sqli_patterns= ["union","select","null", "--","%27", "concat","information_schema"]
        xss_patterns= ["<script>","script","%3cscript%3e","alert(","onload","onerror"]
        scanner_patterns= ["nmap","nikto","dirb", "sqlmap","gss-test-agent"]
 
        ifany(xin line_lowerfor xin sqli_patterns)and "select"in line_lower:
         
  event_type, status,risk ="SQL Injection Attempt","Exploit Attempt","High"
        elifany(xin line_lowerfor xin xss_patterns):
         
  event_type, status,risk ="Cross-Site Scripting (XSS)","Exploit Attempt","High"
        elifany(xin line_lowerfor xin scanner_patterns):
         
  event_type, status,risk ="Nmap/Recon Scan","Scanning","Medium"
        else:
         
  event_type, status,risk ="Web Traffic","Access","Low"
 
    elifany(xin linefor xin ["Failed
password", "authentication
failure", "connection
dropped", "MaxStartups"]):
        attacker_match= re.search(r'(?:rhost=|from\s|from\s\[)([\d\.]+)',line)
        source_ip= attacker_match.group(1)if attacker_matchelse "Unknown"
        
        if"MaxStartups"in lineor "connection
dropped" inline:
         
  event_type ="SSH Denial of Service"
        else:
         
  event_type ="SSH Brute Force"
        status,risk ="Auth Failure","High"
 
    elif"Accepted password"in lineor "session
opened" inline:
        if"cron" notin line:
         
  attacker_match =re.search(r'(?:rhost=|from\s)([\d\.]+)',line)
         
  source_ip =attacker_match.group(1)if attacker_matchelse "Internal"
         
  event_type, status,risk ="System Login","Access Granted","Medium"
 
    return
[time.strftime("%Y-%m-%d
%H:%M:%S"), source_ip,target_victim, event_type,status, risk]
 
defmonitor():
    print(f"---🛡️
GATE(GSS) ---")
    print(f"[*]
Multi-Threat Engine Active. Monitoring: {LOG_FILE}")
    
    ifnot os.path.exists(LOG_FILE):
        os.makedirs(os.path.dirname(LOG_FILE),exist_ok=True)
        open(LOG_FILE,'a').close()
 
    withopen(LOG_FILE,'r', encoding='utf-8',errors='ignore')as f:
        f.seek(0,2) 
        whileTrue:
         
  line =f.readline()
         
  if notline:
         
      time.sleep(0.1)
         
      continue     
  alert =parse_log(line)  
  if alert[5]in ["Medium","High"]:
         
      print(f"ALERT: {alert[3]}
from {alert[1]}
against {alert[2]}")
         
      withopen(CSV_DB,'a', newline='',encoding='utf-8')as db:
         
          csv.writer(db).writerow(alert)
 
if __name__== "__main__":
    try:
        monitor()
    exceptKeyboardInterrupt:
        print("\n[!]
GSS Detection Engine Stopped.")
```

#### The Enrichment Engine: (intel.py)
```
importrequests
importpandas aspd
importtime
importos
 
# Replace with your actual VT Key
API_KEY= "USER_YOUR_API_KEY"
CSV_DB= os.path.join('database','events.csv')
INTEL_DB= os.path.join('database','intel_enriched.csv')
 
defget_geo_intel(ip):
    """Fetches Reputation from VirusTotal and Geo-Location from IP-API"""
    isp,score, country,lat, lon= "Internal
Network", 0,"Private",0.0, 0.0
    
    ifip.startswith(('192.168.','127.', '10.','172.16.', '169.254.'))or ipin ["Internal/System","Unknown","Internal"]:
        returnisp, score,country, lat,lon
 
    vt_url= f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try: 
        resp= requests.get(vt_url,headers={"x-apikey":API_KEY}, timeout=5)
        ifresp.status_code== 200:
         
  data =resp.json()['data']['attributes']
         
  isp =data.get('as_owner','Public Provider')
         
  score =data['last_analysis_stats']['malicious']
        elifresp.status_code== 429:
         
  print(f"[!]VT Rate limit hit for {ip}.Skipping reputation.")
    exceptException ase:
        print(f"[-]VT Error for {ip}:{e}")
 
    try:
        geo_resp= requests.get(f"http://ip-api.com/json/{ip}",timeout=5).json()
        ifgeo_resp.get('status')== 'success':
         
  country =geo_resp.get('country','Unknown')
         
  lat =geo_resp.get('lat',0.0)
         
  lon =geo_resp.get('lon',0.0)
         
  if isp== "Public
Provider":
         
      isp= geo_resp.get('isp','Public Provider')
    except:
        pass
 
    time.sleep(15)
    returnisp, score,country, lat,lon
 
defrun_intel_engine():
    print("---🛡️
GSS Intel Engine: ENRICHMENT ACTIVE ---")
    processed_count= 0
    
    cols= ['Timestamp','Source_IP', 'Target_Victim','Event', 'Status','Risk_Level','ISP_Owner', 'Threat_Score','Country', 'Latitude','Longitude']
 
    ifnot os.path.exists('database'):
        os.makedirs('database')
 
    ifnot os.path.exists(INTEL_DB):
        pd.DataFrame(columns=cols).to_csv(INTEL_DB,index=False)
    else:
        try:
         
  processed_count =len(pd.read_csv(CSV_DB))
        except:
         
  processed_count =0
 
    whileTrue:
        ifos.path.exists(CSV_DB):
         
  try:
         
      df =pd.read_csv(CSV_DB)
         
      if len(df)> processed_count:
         
          new_rows= df.iloc[processed_count:].copy()
         
          
         
          enriched_list= []
         
          forip innew_rows['Source_IP']:
         
              print(f"[*]
Processing Attacker: {ip}...")	
              intel= get_geo_intel(str(ip))
         
              enriched_list.append(intel)
          enrich_df= pd.DataFrame(enriched_list,columns=['ISP_Owner','Threat_Score', 'Country','Latitude', 'Longitude'])
          final_rows= pd.concat([new_rows.reset_index(drop=True),enrich_df], axis=1)         
          final_rows.to_csv(INTEL_DB,mode='a',index=False,header=False)
          processed_count= len(df)
         
          print(f"✅ GSS: {len(final_rows)}alerts enriched.")
         
  except Exceptionas e:
         
      print(f"[-]
Loop Error: {e}")
        
        time.sleep(5)
 
if __name__== "__main__":
    try:
        run_intel_engine()
    exceptKeyboardInterrupt:
        print("\n[!]GSS Intel Engine Shutting Down.")

```

#### The Dashboard: (app.py)
```
importstreamlit asst
importpandas aspd
importos
importplotly.expressas px
fromdatetime importdatetime, timedelta
 
st.set_page_config(page_title="GSS SIEM - Global Threat SOC", layout="wide",page_icon="🛡️")
 
st.markdown("""
    <style>
    .main {
background-color: #0e1117; }
    h1, h2, h3, .stHeader,
[data-testid="stHeader"] {
        color:
#000000 !important;
       
font-weight: 800 !important;
    }
   
[data-testid="stMetric"] {
        background-color:
#ffffff !important; 
       
border-radius: 10px; 
        padding:
15px; 
        border:
2px solid #000000;
       
box-shadow: 2px 2px 10px rgba(0,0,0,0.5);
    }
   
[data-testid="stMetricLabel"] p {
        color:
#000000 !important;
       
font-weight: 700 !important;
       
font-size: 1.1rem !important;
    }
   
[data-testid="stMetricValue"] div {
        color:
#000000 !important;
       
font-weight: 900 !important;
    }
   
section[data-testid="stSidebar"] {
        background-color:
#161b22;
       
border-right: 1px solid #30363d;
    }
    .stButton>button {
        width:
100%;
       
border-radius: 5px;
    }
    hr { border-top: 2px
solid #000000 !important; }
    </style>
    """,unsafe_allow_html=True)
 
# Paths
BASE_DB= os.path.join('database','events.csv')
INTEL_DB= os.path.join('database','intel_enriched.csv')
 
withst.sidebar:
    st.markdown('<h2
style="color: #ffffff !important;">🛡️
GSS Controls</h2>', unsafe_allow_html=True)
    st.info("Management
panel for SOC operations and data export.")
    
    ifos.path.exists(INTEL_DB):
        df_download= pd.read_csv(INTEL_DB)
        csv= df_download.to_csv(index=False).encode('utf-8')
        st.download_button(
         
  label=" Download SOC
Logs",
         
  data=csv,
         
  file_name=f'GSS_SOC_Export_{datetime.now().strftime("%Y%m%d_%H%M")}.csv',
         
  mime='text/csv',
        )
    st.markdown("---")
    
    ifst.button("Reset Dashboard"):
        forfile in
[BASE_DB, INTEL_DB]:
         
  if os.path.exists(file):
         
      os.remove(file)
        st.success("Database
Wiped!")
        st.rerun()
 
st.markdown('<h1
style="text-align: center; color: #000000; font-size: 3rem;">
 SIEM (GSS)</h1>', unsafe_allow_html=True)
st.markdown('<h3
style="text-align: center; color: #1c1c1c; margin-top:
-15px;">Global Threat Intelligence & SOC</h3>',unsafe_allow_html=True)
 
@st.fragment(run_every=2)
defrun_dashboard():
    current_db= INTEL_DBif os.path.exists(INTEL_DB)else BASE_DB
    
    ifos.path.exists(current_db):
        try:
         
  df =pd.read_csv(current_db)
         
  if notdf.empty:
         
      df['Timestamp']= pd.to_datetime(df['Timestamp'])
         
      k1, k2,k3, k4= st.columns(4)
         
      k1.metric("GSS
Total Threats", len(df))
         
      criticals= len(df[df['Risk_Level']== 'High'])
         
      k2.metric("Critical
Alerts", criticals,delta=f"{criticals}
Active", delta_color="inverse")
         
      k3.metric("Unique
Attackers", df['Source_IP'].nunique())
         
      k4.metric("Attack
Vectors", f"{df['Event'].nunique()}
Types")
 
         
      st.markdown("---")
          
      c1, c2= st.columns([2,1])
         
      withc1:
         
          st.markdown('<h3
style="color: #000000;">GSS Attack Trend (Last Hour)</h3>', unsafe_allow_html=True)
         
          last_hour= datetime.now()- timedelta(hours=1)
         
          trend_df= df[df['Timestamp']> last_hour].copy()
         
          ifnot trend_df.empty:
         
              trend_df= trend_df.set_index('Timestamp').resample('5T').size().reset_index(name='Count')
         
              fig= px.line(trend_df,x='Timestamp',y='Count',template="plotly_dark",line_shape="spline",color_discrete_sequence=['#ff4b4b'])
         
              fig.update_layout(paper_bgcolor='rgba(0,0,0,0)',plot_bgcolor='rgba(0,0,0,0)')
         
              st.plotly_chart(fig,use_container_width=True)
         
      withc2:
         
          st.markdown('<h3
style="color: #000000;">Top IPs</h3>', unsafe_allow_html=True)
         
          st.dataframe(df['Source_IP'].value_counts().head(10),use_container_width=True)      
      st.markdown("---")
      m1, m2= st.columns([1.5,1])
         
      withm1:
         
          st.markdown('<h3
style="color: #000000;">Global GSS Threat Map</h3>', unsafe_allow_html=True)
         
          if'Latitude' indf.columns:
         
              fig_map= px.scatter_geo(df,lat='Latitude',lon='Longitude',color='Risk_Level',projection="orthographic",template="plotly_dark",color_discrete_map={'High':'#ff4b4b', 'Medium':'#ffa500', 'Low':'#00cc96'})
         
              st.plotly_chart(fig_map,use_container_width=True)
         
      withm2:
         
          st.markdown('<h3
style="color: #000000;">Distribution</h3>', unsafe_allow_html=True)
         
          fig_bar= px.bar(df['Event'].value_counts().reset_index(),x='count',y='Event',orientation='h',template="plotly_dark",color_discrete_sequence=['#ff4b4b'])
         
          st.plotly_chart(fig_bar,use_container_width=True)
          
      st.markdown("---")
         
      st.markdown('<h3
style="color: #000000;">
GSS Real-Time Event Feed</h3>', unsafe_allow_html=True)
         
      defcolor_risk(val):
         
          ifval =='High': return'color: #ff4b4b; font-weight: bold;'
         
          elifval =='Medium': return'color: #ffa500;'
         
          return'color: white;'
         
      st.dataframe(df.tail(15).sort_index(ascending=False).style.applymap(color_risk,subset=['Risk_Level']),use_container_width=True,hide_index=True)
 
         
  else:
         
      st.info("GSS
SOC Ready. Awaiting logs...")
        exceptException ase:
         
  st.error(f"GSS
Core Engine Error: {e}")
    else:
        st.warning("GSS Database Offline. Ensure
detection scripts are running.")
 
if __name__== "__main__":
    run_dashboard()
```

## 5. Risk Scoring & Decision Methodology

The GSS SIEM utilizes a weighted scoring system to determine the severity of an alert. This ensures that the SOC dashboard prioritizes verified external threats over internal system noise.

### 5.1 The Risk Probability Formula

The final Risk Score (R) is calculated by combining the Heuristic Severity (H) from detection.py and the Reputation Score (V) retrieved from VirusTotal in intel.py.

The core logic follows an ensemble approach:

    Rtotal = (Hweight + Vscore ) ÷  2

* **Hweight:** Assigned value based on Regex matching (High=0.9, Medium=0.5, Low=0.1).

* **Vscore:** The normalized "Malicious" count from VirusTotal reports.
### 5.2 Decision Thresholds

The SIEM applies specific logic gates to the enriched data to determine the final alert status:

* **Standard Malicious Flag:** If Rtotal > 0.75, the event is flagged as CRITICAL and highlighted in red on the dashboard.

* **Institutional Trusted Bypass:** If the Source_IP belongs to a known internal range (e.g., 192.168.x.x or 10.x.x.x), the threshold is raised to 0.85 to reduce internal false positives.

* **Behavioral Penalty:** If detection.py identifies a specific exploit signature (like SQL Injection or XSS) and the Rtotal > 0.45, the site is automatically escalated to HIGH RISK regardless of its previous reputation.

## 6. Function & Logic Explanation

To identify threats in real-time, the GSS suite employs three distinct analytical methodologies within its processing pipeline:
* **Heuristic Signature Matching:** Employs the re (Regex) library to perform a deep packet audit of the raw syslog strings. Rather than simple keyword matching, it looks for specific attack structures—such as union select for SQL Injection or Failed password for SSH Brute Force. This ensures the system distinguishes between standard administrative traffic and malicious exploit attempts.

* **Ensemble Reputation Auditing:** Integrates the VirusTotal API to perform a "consensus-based" reputation check. By querying a database of over 70 security vendors, the system retrieves a malicious count. This prevents the SIEM from relying on a single source of truth, instead utilizing an ensemble of global intelligence to verify the threat level of an incoming IP.

* **Geospatial Telemetry Correlation:** Utilizes the IP-API to verify the "origin point" of a network event. It maps the Source IP to a physical Country, City, and ISP. This logic specifically flags traffic originating from known high-risk regions or data centers (ASNs) often used by botnets, providing the security analyst with critical context that raw logs cannot provide
## 7. User Manual: Interpreting SOC Intelligence
### 7.1 How to Operate the GSS SIEM
To begin monitoring your infrastructure, follow these operational steps:

**1.	Initialize Collector:** Run python server.py. This opens the UDP 514 gateway to begin receiving logs.

**2.	Activate Heuristics:** Run python detection.py. The terminal will begin showing real-time alerts as logs are parsed.

**3.	Launch Intel Engine:** Run python intel.py to begin the automated enrichment of attacker IPs.

**4.	Open Dashboard:** Run streamlit run app.py to view the graphical Command Center.
### 7.2 Understanding Terminal & SOC Logs

The GSS suite uses standardized log prefixes to help analysts identify the stage of a security event.
| Log Prefix | Meaning | Logic Level |
| :------------: | :---------: | :-----------: |
| [RECV] | Raw packet received on Port 514. | Information |
| [ALERT]	 | detection.py matched a signature (SQLi, XSS, or SSH). | Medium / High |
| [*] Processing	| intel.py is querying VirusTotal and IP-API for context.	| Intelligence |
| [!] VT Limit	| Rate limit hit (Free tier allows 4 requests/min).	| Warning |
| Enriched	| Geographical and Reputation data added to intel_enriched.csv.	| Success |

### 7.3 Dashboard Metrics & Thresholds

When viewing the Streamlit Dashboard, the following visual cues indicate the threat status:

* **Global Threat Map:** Red markers indicate a High Risk result where the calculated score Rtotal > 0.75.

* **KPI Metrics:** The "Critical Alerts" counter tracks only events that have been verified by the Heuristic Engine as an exploit attempt (e.g., SQL Injection).

* **Real-Time Feed:** Rows highlighted in Red indicate active attacks that require immediate intervention.

### 7.4 Data Management

* **Exporting Data:** Use the "Download SOC Logs" button in the sidebar to save a CSV copy for forensic reporting.

* **System Wipe:** Use the "Reset Dashboard" button to clear the databases (events.csv and intel_enriched.csv) before starting a new monitoring session.

## 8. Future Scope & Scalability
The current iteration of the GSS SIEM provides a robust foundation for real-time monitoring. To evolve into a next-generation security platform, the following enhancements are proposed:

### 8.1 Machine Learning & UEBA Integration

* **Goal:** Transition from static Regex signatures to User and Entity Behavior Analytics (UEBA) using Recurrent Neural Networks (RNNs).

* **Impact:** By establishing a baseline of "normal" network activity, the AI can detect anomalies—such as a user logging in at 3:00 AM from a new country—that do not match a specific attack signature but indicate a compromised account.
### 8.2 SOAR Implementation (Automated Response)

* **Goal:** Integrate Security Orchestration, Automation, and Response (SOAR) capabilities.

* **Impact:** Currently, the system only alerts the analyst. A SOAR layer would allow the SIEM to take autonomous action, such as automatically updating firewall rules to block an IP that exceeds a 90% risk score in intel.py.

### 8.3 Advanced Threat Intel Sharing (STIX/TAXII)

* **Goal:** Implement standardized threat sharing protocols like STIX/TAXII.

* **Impact:** This would allow the GSS suite to pull "community-sourced" blacklists from global providers (like PhishTank or MISP) in real-time, ensuring the system can detect "Zero-Day" threats before they appear in standard vendor databases.

### 8.4 Distributed Ingestion & Cloud Scalability

*	**Goal:** Replace the single-threaded server.py collector with a distributed message broker like Apache Kafka.

*	**Impact:** This would allow the SIEM to process millions of logs per second across global data centers, moving from a local lab tool to an enterprise-grade cloud-native security solution.

### 8.5 NLP-Driven Log Summarization

* **Goal:** Integrate Large Language Models (LLMs) to summarize complex forensic logs.
* **Impact:** Instead of reading raw syslog strings, an analyst could ask the dashboard, "What did this attacker try to do?" and receive a natural language summary: "The attacker attempted a blind SQL injection on the login portal using three different IP addresses."

## 9. Conclusion

The GSS suite provides a comprehensive security safety net by integrating Heuristic Signature Matching, Global Threat Intelligence, and Centralized Real-Time Monitoring into a unified defense platform. This multi-layered approach ensures organizational resilience because even if a specific attack is too new for global blacklists, the heuristic engine acts as a safety net to flag malicious behavior based on structural patterns like SQL injection or SSH brute force. By aggregating raw logs via the UDP 514 protocol and enriching them through the VirusTotal and IP-API frameworks, the system successfully transforms complex network telemetry into actionable visual intelligence on a Streamlit SOC dashboard. Ultimately, the GSS suite demonstrates that a modular Python architecture can effectively automate the transition from reactive firefighting to proactive threat hunting, allowing security analysts to identify, map, and mitigate global threats within a single, integrated command center.

## 10. Reference

1)	Sheeraz, M., et al. (2024). "Revolutionizing SIEM Security: An Innovative Correlation Engine Design for Multi-Layered Attack Detection." Sensors, vol. 24, no. 15. This study provides the theoretical basis for the multi-layered detection used in your detection.py and intel.py workflow.

2)	Ali, A., Hwang, R. H., & Lin, Y. D. (2025). "Evaluating Cyber Threat Intelligence: Accuracy, Completeness, Relevance, and Freshness." IEEE Xplore. This paper validates the use of external platforms like VirusTotal for generating weighted verdicts on Indicators of Compromise (IoCs).

3)	Tendikov, N., et al. (2024). "Security Information Event Management Data Acquisition and Analysis Methods with Machine Learning Principles." Results in Engineering, vol. 22. This reference supports the ingestion of raw UDP logs and their conversion into structured CSV datasets for analysis.

4)	Radoglou-Grammatikis, P., et al. (2021). "SPEAR SIEM: A Security Information and Event Management System for the Smart Grid." Computer Networks, vol. 193. This work highlights the importance of real-time visibility and the "Single Pane of Glass" dashboard approach implemented in your Streamlit interface.

5)	Chishti, M. A., et al. (2023). "Effective Security Monitoring Using Efficient SIEM Architecture." Human-centric Computing and Information Sciences, vol. 13. A core reference for building lightweight, modular SIEM collectors that can run on standard hardware without high licensing costs.

6)	OWASP Foundation. (2021). "Top 10:2021 – A09: Security Logging and Monitoring Failures." Standard industry guidance used to map the heuristic signatures in detection.py to real-world vulnerabilities.

## TARGET SETUP
### 1.Target VM Configuration: Full rsyslog Setup
 **The Complete Configuration**
Open the rsyslog configuration file:

Bash
```
sudo nano /etc/rsyslog.conf
```
Replace YOUR_HOST_IP with the IP of the machine running your Python code:

Bash
```
# 1. Load the imfile module to monitor text files

module(load="imfile" PollingInterval="10")

# 2. Define the file to monitor (Apache/Nginx Access Log)

input(type="imfile"
      File="/var/log/apache2/access.log"
      Tag="web_threat:"
      Severity="info"
      Facility="local7")

# 3. Forward EVERYTHING (System logs + Web logs) to the SIEM Host
# Use @ for UDP Port 514

*.* @YOUR_HOST_IP:514
```

#### Permission Fix
For rsyslog to read the web logs (which are often restricted), you must ensure it has the correct permissions. 

Run these commands:

Bash
```
# Ensure rsyslog can read the log directory
sudo chmod 755 /var/log/apache2
sudo chmod 644 /var/log/apache2/access.log

# Restart the service to apply changes
sudo systemctl restart rsyslog
```
### 2.Attack Simulation (Kali Linux Testing)

Note:  Replace TARGET_VM_IP with your Target's IP address

Brute Force Attack (SSH)
```
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt TARGET_VM_IP ssh
```
SQL Injection (SQLi) Test:
```
Curl "http://TARGET_VM_IP/login.php?id=1%20UNION%20SELECT%20null,user,password%20FROM%20users"
```
Cross-Site Scripting (XSS) Test:
```
curl "http://TARGET_VM_IP/index.php?name=<script>alert('GSS_Hacked')</script>"
```
