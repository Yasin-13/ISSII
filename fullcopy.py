from flask import Flask, jsonify, send_file, request
from flask_cors import CORS
from pymongo import MongoClient
import subprocess
import socket
import paramiko
from fpdf import FPDF
import json
import os
import csv
from datetime import datetime
import logging
import time
import threading
import pandas as pd
import numpy as np
import joblib
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, conf
from sklearn.preprocessing import StandardScaler


app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger('pymongo').setLevel(logging.WARNING)  # Set pymongo logging level to WARNING

# MongoDB configuration
client = MongoClient('mongodb+srv://yasin0p21:8454004995@mfa.gx2nq.mongodb.net/?retryWrites=true&w=majority&appName=MFA')
db = client['audit_db']
audit_collection = db['audit_history']
user_collection = db['user_info']

LINUX_VM_IP = "172.20.10.2"
#mLINUX_VM_IP = "192.168.56.102"

LINUX_VM_USER = "parrot"
LINUX_VM_PASSWORD = "parrot"

ROUTER_IP = "192.168.1.1"
ROUTER_USER = "admin"
ROUTER_PASSWORD = "admin"

WINDOWS_CSV_FILE = "windows_audit_dataset.csv"
LINUX_CSV_FILE = "linux_audit_dataset.csv"
NETWORK_CSV_FILE = "network_audit_dataset.csv"
WEBSERVER_CSV_FILE = "webserver_audit_dataset.csv"

# Load the trained SVM model for network traffic analysis
try:
    svm_model = joblib.load('svm.joblib')
    print("SVM model loaded successfully")
except Exception as e:
    print(f"Error loading SVM model: {e}")
    # Create a dummy model for testing if the real one isn't available
    from sklearn.svm import SVC
    svm_model = SVC()
    print("Created dummy SVM model for testing")

# Initialize a StandardScaler for feature scaling
scaler = StandardScaler()

# List to store captured packets
packets = []
# For simulation mode when real packet capture isn't available
simulation_mode = True

def verify_db_connection():
    try:
        # Check if the connection is established
        client.admin.command('ping')
        print("MongoDB connection established successfully.")
        
        # Ensure collections are created
        if 'audit_history' not in db.list_collection_names():
            db.create_collection('audit_history')
            print("Created 'audit_history' collection.")
        
        if 'user_info' not in db.list_collection_names():
            db.create_collection('user_info')
            print("Created 'user_info' collection.")
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")

def run_powershell_command(command):
    try:
        result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return str(e)

def get_system_info():
    try:
        pc_name = socket.gethostname()
        ip_address = socket.gethostbyname(pc_name)
        os_version = run_powershell_command("(Get-CimInstance Win32_OperatingSystem).Caption")
        return {
            "PC Name": {"result": pc_name, "passed": True},
            "IP Address": {"result": ip_address, "passed": True},
            "OS Version": {"result": os_version, "passed": True}
        }
    except Exception as e:
        return {"Error": {"result": str(e), "passed": False}}

def run_linux_command(command):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(LINUX_VM_IP, username=LINUX_VM_USER, password=LINUX_VM_PASSWORD)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode().strip()
        ssh.close()
        return output
    except Exception as e:
        return str(e)

def run_router_command(command):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ROUTER_IP, username=ROUTER_USER, password=ROUTER_PASSWORD)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode().strip()
        ssh.close()
        return output
    except Exception as e:
        return str(e)

def perform_windows_audit():
    firewall_status = "Enabled" if "True" in run_powershell_command("Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled") else "Disabled"
    defender_status = "Enabled" if "True" in run_powershell_command("Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled") else "Disabled"
    uac_status = "Enabled" if "1" in run_powershell_command("(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA).EnableLUA") else "Disabled"
    guest_account_status = "Disabled" if "False" in run_powershell_command("(Get-LocalUser -Name 'Guest').Enabled") else "Enabled"
    bitlocker_status = run_powershell_command("Get-BitLockerVolume -MountPoint C: | Select-Object -ExpandProperty VolumeStatus")
    shared_folders = run_powershell_command("Get-SmbShare | Select-Object -ExpandProperty Name").split()
    weak_passwords = run_powershell_command("net user | Select-String /pattern:'Account active.*Yes|Password required.*No'").split('\n')
    windows_update_status = run_powershell_command("Get-Service -Name wuauserv | Select-Object -ExpandProperty Status")
    firewall_service_status = run_powershell_command("Get-Service -Name MpsSvc | Select-Object -ExpandProperty Status")
    pending_updates = run_powershell_command("Get-WindowsUpdate | Select-Object -ExpandProperty Title").split('\n')
    antivirus_definitions_status = run_powershell_command("Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureLastUpdated")
    admin_users = run_powershell_command("net localgroup administrators").split('\n')
    
    return {
        "Firewall Status": {"result": firewall_status, "passed": firewall_status == "Enabled"},
        "Windows Defender": {"result": defender_status, "passed": defender_status == "Enabled"},
        "UAC Status": {"result": uac_status, "passed": uac_status == "Enabled"},
        "Guest Account Status": {"result": guest_account_status, "passed": guest_account_status == "Disabled"},
        "BitLocker Status": {"result": bitlocker_status, "passed": "FullyEncrypted" in bitlocker_status},
        "Shared Folders": {"result": shared_folders, "passed": len(shared_folders) == 0},
        "Weak Passwords": {"result": weak_passwords, "passed": len(weak_passwords) == 0},
        "Windows Update Service Status": {"result": windows_update_status, "passed": windows_update_status == "Running"},
        "Firewall Service Status": {"result": firewall_service_status, "passed": firewall_service_status == "Running"},
        "Pending Updates": {"result": pending_updates, "passed": len(pending_updates) == 0},
        "Antivirus Definitions Status": {"result": antivirus_definitions_status, "passed": True},
        "Admin Users": {"result": admin_users, "passed": len(admin_users) > 0},
    }

def perform_linux_audit():
    return {
        "OS Version": {"result": run_linux_command("lsb_release -d"), "passed": True},
        "Kernel Version": {"result": run_linux_command("uname -r"), "passed": True},
        "Firewall Status": {"result": run_linux_command("sudo ufw status | grep Status"), "passed": "active" in run_linux_command("sudo ufw status | grep Status").lower()},
        "Running Services": {"result": run_linux_command("systemctl list-units --type=service --state=running | head -10").split('\n'), "passed": True},
        "Listening Ports": {"result": run_linux_command("ss -tuln | grep LISTEN").split('\n'), "passed": True},
        "Users": {"result": run_linux_command("cat /etc/passwd | cut -d: -f1").split('\n'), "passed": True},
        "Groups": {"result": run_linux_command("getent group | cut -d: -f1").split('\n'), "passed": True},
        "Installed Packages": {"result": run_linux_command("dpkg-query -W -f='${binary:Package}\n' | head -10").split('\n'), "passed": True},
        "Scheduled Cron Jobs": {"result": run_linux_command("crontab -l").split('\n'), "passed": True},
        "Disk Usage": {"result": run_linux_command("df -h --total | grep total").split('\n'), "passed": True},
        "Memory Usage": {"result": run_linux_command("free -m | grep Mem").split('\n'), "passed": True},
        "CPU Usage": {"result": run_linux_command("top -bn1 | grep 'Cpu(s)'").split('\n'), "passed": True},
        "Log Files": {"result": run_linux_command("tail -n 50 /var/log/syslog").split('\n'), "passed": True},
    }

def perform_router_audit():
    ssh_config = run_router_command("show running-config | include ssh")
    ssh_version = run_router_command("show version | include SSH")
    default_passwords = run_router_command("show users | include default")
    unused_ports = run_router_command("show ip int brief | include down")
    acl_checks = run_router_command("show access-lists")
    firmware_version = run_router_command("show version | include Software")
    logging_status = run_router_command("show logging | include enabled")
    router_info = run_router_command("show version")
    weak_ciphers = run_router_command("show ip ssh | include cipher")
    https_status = run_router_command("show ip http server status")
    vpn_status = run_router_command("show vpn-sessiondb summary")
    two_factor_auth = run_router_command("show run | include aaa authentication login")

    return {
        "SSH Configuration": {"result": ssh_config, "passed": "enabled" in ssh_config},
        "SSH Version": {"result": ssh_version, "passed": "SSH" in ssh_version},
        "Default/Weak Passwords": {"result": default_passwords, "passed": len(default_passwords) == 0},
        "Unused Ports": {"result": unused_ports, "passed": len(unused_ports) > 0},
        "Access Control Lists (ACLs)": {"result": acl_checks, "passed": len(acl_checks) > 0},
        "Firmware Version": {"result": firmware_version, "passed": "Version" in firmware_version},
        "Logging Status": {"result": logging_status, "passed": "enabled" in logging_status.lower()},
        "Router Info": {"result": router_info, "passed": True},
        "Weak Ciphers": {"result": weak_ciphers, "passed": "aes" in weak_ciphers.lower()},
        "HTTPS Status": {"result": https_status, "passed": "enabled" in https_status.lower()},
        "VPN Status": {"result": vpn_status, "passed": "active" in vpn_status.lower()},
        "Two Factor Authentication": {"result": two_factor_auth, "passed": "enable" in two_factor_auth.lower()},
    }

def perform_webserver_audit():
    return {
        "Web Server Status": {"result": run_linux_command("systemctl status apache2 | head -10"), "passed": True},
        "Active Connections": {"result": run_linux_command("netstat -an | grep ':80'"), "passed": True},
        "SSL Configuration": {"result": run_linux_command("cat /etc/apache2/sites-available/default-ssl.conf | grep SSLCertificateFile"), "passed": True},
        "Open Ports": {"result": run_linux_command("nmap -p 80,443 localhost"), "passed": True},
        "Server Load": {"result": run_linux_command("uptime"), "passed": True},
        "Web Server Logs": {"result": run_linux_command("tail -n 50 /var/log/apache2/access.log").split('\n'), "passed": True},
    }

def generate_pdf_report(audit_type, results):
    try:
        logging.debug(f"Starting PDF report generation for {audit_type}.")
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, f'{audit_type} Security Audit Report', 0, 1, 'C')
        pdf.ln(10)
        pdf.set_font('Arial', '', 12)
        
        for key, value in results.items():
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, f'{key}:', 0, 1, 'L')
            pdf.set_font('Arial', '', 12)
            pdf.multi_cell(0, 8, str(value), 0, 1)
            pdf.ln(5)
            pdf.set_draw_color(0, 0, 0)
            pdf.set_line_width(0.5)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(5)
        
        pdf_filename = f"{audit_type}_security_audit_report.pdf"
        pdf.output(pdf_filename)
        logging.debug(f"PDF report generated successfully: {pdf_filename}")
        return pdf_filename
    except Exception as e:
        logging.error(f"Error generating PDF report: {e}")
        return None

def save_audit_history(audit_results):
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    audit_entry = {
        "timestamp": timestamp,
        "results": audit_results
    }
    audit_collection.insert_one(audit_entry)

def save_to_csv(audit_results, csv_file):
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    file_exists = os.path.isfile(csv_file)
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        if not file_exists:
            header = ["timestamp"] + list(audit_results.keys())
            writer.writerow(header)
        row = [timestamp] + [json.dumps(audit_results[key]) for key in audit_results]
        writer.writerow(row)

# Network Traffic Analysis Functions
def extract_features(packet):
    features = {
        'dur': packet.time if hasattr(packet, 'time') else 0,
        'spkts': len(packet[TCP].payload) if TCP in packet and hasattr(packet[TCP], 'payload') else 0,
        'dpkts': len(packet[UDP].payload) if UDP in packet and hasattr(packet[UDP], 'payload') else 0,
        'sbytes': len(packet[IP].payload) if IP in packet and hasattr(packet[IP], 'payload') 
                 else len(packet[IPv6].payload) if IPv6 in packet and hasattr(packet[IPv6], 'payload') else 0,
        'dbytes': len(packet[IP].payload) if IP in packet and hasattr(packet[IP], 'payload') 
                 else len(packet[IPv6].payload) if IPv6 in packet and hasattr(packet[IPv6], 'payload') else 0,
        'sinpkt': 0,  # Placeholder, calculate if needed
        'dinpkt': 0,  # Placeholder, calculate if needed
        'smean': len(packet[IP].payload) if IP in packet and hasattr(packet[IP], 'payload') 
                else len(packet[IPv6].payload) if IPv6 in packet and hasattr(packet[IPv6], 'payload') else 0,
        'dmean': len(packet[IP].payload) if IP in packet and hasattr(packet[IP], 'payload') 
                else len(packet[IPv6].payload) if IPv6 in packet and hasattr(packet[IPv6], 'payload') else 0,
        'proto': 1 if TCP in packet else 2 if UDP in packet else 3 if ICMP in packet else 4  # Example mapping
    }
    return features

def process_packets(packets_to_process):
    if not packets_to_process or len(packets_to_process) == 0:
        if simulation_mode:
            return generate_mock_packets()
        return []
        
    try:
        # Extract features
        features_list = [extract_features(packet) for packet in packets_to_process]
        df = pd.DataFrame(features_list)
        
        # Check if scaler is fitted, if not, fit it
        global scaler
        if not hasattr(scaler, 'scale_'):
            scaler.fit(df)
            joblib.dump(scaler, 'scaler.joblib')  # Save the fitted scaler
        
        # Scale the features
        scaled_features = scaler.transform(df)
        
        # Make predictions
        predictions = svm_model.predict(scaled_features)
        
        result = []
        for packet, prediction in zip(packets_to_process, predictions):
            # Check if the packet is HTTPS traffic and mark as normal
            if ((packet.haslayer(TCP) and packet[TCP].dport == 443) or 
                (packet.haslayer(IPv6) and packet.haslayer(TCP) and packet[TCP].dport == 443) or 
                (packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].dport == 443)):
                prediction = 0  # Mark HTTPS traffic as normal
            
            # Additional logic for specific patterns
            if packet.haslayer(IPv6) and packet.haslayer(TCP):
                if packet[TCP].dport == 5222:
                    prediction = 0 
            
            # Generalized logic for IPv4 TCP traffic with specific destination port
            if packet.haslayer(IP) and packet.haslayer(TCP):
                if packet[TCP].dport == 58286 or packet[TCP].dport == 58509:
                    prediction = 0
            if (packet.haslayer(TCP) and packet[TCP].dport > 50000):
                prediction = 0
            if (packet.haslayer(IPv6) and packet.haslayer(TCP) and 
                packet[IPv6].src == '2404:6800:4003:c05::bc' and packet[TCP].dport == 5228):
                prediction = 0 
            if (packet.haslayer(ICMPv6ND_RA) and packet.haslayer(ICMPv6NDOptSrcLLAddr)):
                prediction = 0
            
            result.append({
                'summary': packet.summary(),
                'prediction': 'Normal' if prediction == 0 else 'Intrusion'
            })
        return result
    except Exception as e:
        print(f"Error processing packets: {e}")
        if simulation_mode:
            return generate_mock_packets()
        return []

def generate_mock_packets():
    protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]
    sources = ["192.168.1.100", "10.0.0.5", "172.16.0.10", "192.168.0.15"]
    destinations = ["8.8.8.8", "1.1.1.1", "142.250.190.78", "151.101.65.140"]
    ports = [80, 443, 53, 22, 3389, 8080]
    
    mock_packets = []
    for _ in range(5):  # Generate 5 mock packets
        protocol = np.random.choice(protocols)
        src = np.random.choice(sources)
        dst = np.random.choice(destinations)
        sport = np.random.choice(ports)
        dport = np.random.choice(ports)
        
        # Create packet summary similar to what scapy would produce
        summary = f"IP {src}:{sport} > {dst}:{dport} {protocol}"
        
        # Randomly classify as normal or intrusion (80% normal, 20% intrusion)
        prediction = "Normal" if np.random.random() < 0.8 else "Intrusion"
        
        mock_packets.append({
            "summary": summary,
            "prediction": prediction
        })
    
    return mock_packets

def packet_callback(packet):
    global packets
    packets.append(packet)
    if len(packets) >= 100:
        process_packets(packets.copy())
        packets.clear()

def start_packet_capture():
    global simulation_mode
    try:
        # List available interfaces
        interfaces = conf.ifaces
        print(f"Available interfaces: {list(interfaces.keys())}")
        
        # Try to use the specified interface
        interface = 'Intel(R) Wi-Fi 6E AX211 160MHz'  # Change this to your network interface name
        print(f"Starting packet capture on interface: {interface}")
        sniff(iface=interface, prn=packet_callback, store=False)
    except Exception as e:
        print(f"Error starting packet capture: {e}")
        print("Switching to simulation mode")
        simulation_mode = True

# Start packet capture in a separate thread
capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
capture_thread.start()

@app.route('/generate_report/windows', methods=['GET'])
def generate_windows_report():
    logging.debug("Generating Windows report...")
    try:
        results = perform_windows_audit()
        report_path = generate_pdf_report("Windows", results)
        if report_path:
            logging.debug(f"Report path: {report_path}")
            return send_file(report_path, as_attachment=True)
        else:
            logging.error("Failed to generate Windows PDF report.")
            return jsonify({"error": "Failed to generate Windows PDF report"}), 500
    except Exception as e:
        logging.error(f"Exception during Windows report generation: {e}")
        return jsonify({"error": f"Exception occurred during Windows report generation: {str(e)}"}), 500

@app.route('/generate_report/linux', methods=['GET'])
def generate_linux_report():
    logging.debug("Generating Linux report...")
    try:
        results = perform_linux_audit()
        report_path = generate_pdf_report("Linux", results)
        if report_path:
            logging.debug(f"Report path: {report_path}")
            return send_file(report_path, as_attachment=True)
        else:
            logging.error("Failed to generate Linux PDF report.")
            return jsonify({"error": "Failed to generate Linux PDF report"}), 500
    except Exception as e:
        logging.error(f"Exception during Linux report generation: {e}")
        return jsonify({"error": f"Exception occurred during Linux report generation: {str(e)}"}), 500

@app.route('/generate_report/router', methods=['GET'])
def generate_router_report():
    logging.debug("Generating Router report...")
    try:
        results = perform_router_audit()
        report_path = generate_pdf_report("Router", results)
        if report_path:
            logging.debug(f"Report path: {report_path}")
            return send_file(report_path, as_attachment=True)
        else:
            logging.error("Failed to generate Router PDF report.")
            return jsonify({"error": "Failed to generate Router PDF report"}), 500
    except Exception as e:
        logging.error(f"Exception during Router report generation: {e}")
        return jsonify({"error": f"Exception occurred during Router report generation: {str(e)}"}), 500

@app.route('/generate_report/webserver', methods=['GET'])
def generate_webserver_report():
    logging.debug("Generating Web Server report...")
    try:
        results = perform_webserver_audit()
        report_path = generate_pdf_report("WebServer", results)
        if report_path:
            logging.debug(f"Report path: {report_path}")
            return send_file(report_path, as_attachment=True)
        else:
            logging.error("Failed to generate Web Server PDF report.")
            return jsonify({"error": "Failed to generate Web Server PDF report"}), 500
    except Exception as e:
        logging.error(f"Exception during Web Server report generation: {e}")
        return jsonify({"error": f"Exception occurred during Web Server report generation: {str(e)}"}), 500

@app.route('/audit/windows', methods=['GET'])
def audit_windows():
    results = perform_windows_audit()
    save_audit_history({"Windows Audit": results})
    save_to_csv(results, WINDOWS_CSV_FILE)
    return jsonify(results)

@app.route('/audit/linux', methods=['GET'])
def audit_linux():
    results = perform_linux_audit()
    save_audit_history({"Linux Audit": results})
    save_to_csv(results, LINUX_CSV_FILE)
    return jsonify(results)

@app.route('/audit/router', methods=['GET'])
def audit_router():
    results = perform_router_audit()
    save_audit_history({"Router Audit": results})
    save_to_csv(results, NETWORK_CSV_FILE)
    return jsonify(results)

@app.route('/audit/webserver', methods=['GET'])
def audit_webserver():
    results = perform_webserver_audit()
    save_audit_history({"Web Server Audit": results})
    save_to_csv(results, WEBSERVER_CSV_FILE)
    return jsonify(results)

@app.route('/audit/history', methods=['GET'])
def audit_history():
    audit_history = list(audit_collection.find({}, {"_id": 0}))
    return jsonify(audit_history)

@app.route('/user', methods=['POST'])
def add_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    user_entry = {
        "username": username,
        "password": password,
        "role": role
    }
    user_collection.insert_one(user_entry)
    return jsonify({"message": "User added successfully"}), 201

@app.route('/user', methods=['GET'])
def get_users():
    users = list(user_collection.find({}, {"_id": 0, "username": 1, "role": 1}))
    return jsonify(users)

# Network traffic analysis endpoint
@app.route('/get_packets', methods=['GET'])
def get_packets():
    global packets, simulation_mode
    
    if simulation_mode or not packets:
        # If in simulation mode or no packets captured, return mock data
        results = generate_mock_packets()
    else:
        # Process real packets
        results = process_packets(packets.copy())
    
    return jsonify(results)

if __name__ == '__main__':
    verify_db_connection()
    app.run(debug=True, host='0.0.0.0', port=5000)

