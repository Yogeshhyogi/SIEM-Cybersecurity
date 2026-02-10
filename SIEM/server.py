import socket
import logging
import os

# --- CONFIGURATION ---
LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'syslog.log')
HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 514        # Standard Syslog Port (Requires sudo/Admin)

# Ensure GSS log directory exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Configure the Logger to write raw strings (preserving the IP | Message format)
logger = logging.getLogger("GSS_Collector")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(LOG_FILE)
handler.setFormatter(logging.Formatter('%(message)s')) # No extra timestamp here, we add it in detection
logger.addHandler(handler)

def start_server():
    print(f"--- 🛰️ GATE (GSS) ---")
    print(f"[*] Log Collector Status: ACTIVE")
    print(f"[*] Listening on: {HOST}:{PORT} (UDP)")
    print(f"[*] Target Log: {LOG_FILE}")
    print("[*] Monitoring for incoming security events... (Ctrl+C to stop)")
    
    # Initialize UDP Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        sock.bind((HOST, PORT))
    except PermissionError:
        print("[-] GSS ACCESS DENIED: Port 514 is a privileged port.")
        print("[-] FIX: Run Terminal as Administrator or use 'sudo python3 server.py'")
        return
    except Exception as e:
        print(f"[-] Startup Error: {e}")
        return

    while True:
        try:
            # Receive data from victims (VMs, Servers, Firewalls)
            data, addr = sock.recvfrom(4096)
            message = data.decode('utf-8', errors='ignore').strip()
            
            # Format: Victim_IP | Original_Syslog_Message
            log_entry = f"{addr[0]} | {message}"
            
            # Console Preview
            print(f"[RECV] {log_entry[:120]}...") 
            
            # Write to central syslog.log
            logger.info(log_entry)
            
        except KeyboardInterrupt:
            print("\n[*] GSS Collector shutting down...")
            break
        except Exception as e:
            print(f"[-] Processing Error: {e}")

if __name__ == "__main__":
    start_server()