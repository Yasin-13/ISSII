from flask import Flask, jsonify, send_file, request, g
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

app = Flask(__name__)
CORS(app)

# MongoDB configuration
client = MongoClient('mongodb+srv://yasin0p21:8454004995@mfa.gx2nq.mongodb.net/?retryWrites=true&w=majority&appName=MFA')
db = client['audit_db']
audit_collection = db['audit_history']
user_collection = db['user_info']

LINUX_VM_IP = "172.20.10.3"
LINUX_VM_USER = "parrot"
LINUX_VM_PASSWORD = "parrot"

ROUTER_IP = "192.168.1.1"
ROUTER_USER = "admin"
ROUTER_PASSWORD = "admin"

WINDOWS_CSV_FILE = "windows_audit_dataset.csv"
LINUX_CSV_FILE = "linux_audit_dataset.csv"
NETWORK_CSV_FILE = "network_audit_dataset.csv"
WEBSERVER_CSV_FILE = "webserver_audit_dataset.csv"

# Middleware to log details of each request
@app.before_request
def log_request_info():
    g.request_start_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    g.request_ip = request.remote_addr
    g.request_protocol = request.environ.get('SERVER_PROTOCOL')
    g.request_method = request.method
    g.request_path = request.path
    g.request_query_string = request.query_string.decode('utf-8')
    g.request_data = request.get_json() if request.is_json else request.form.to_dict()

@app.after_request
def log_response_info(response):
    request_duration = (datetime.utcnow() - datetime.strptime(g.request_start_time, '%Y-%m-%d %H:%M:%S')).total_seconds()
    log_entry = {
        "timestamp": g.request_start_time,
        "source_ip": g.request_ip,
        "protocol": g.request_protocol,
        "request_type": g.request_method,
        "request_path": g.request_path,
        "query_string": g.request_query_string,
        "request_data": g.request_data,
        "response_status": response.status_code,
        "response_data": response.get_data(as_text=True),
        "duration": request_duration
    }
    # Save log to MongoDB
    db.request_logs.insert_one(log_entry)
    return response

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

def generate_pdf_report(results):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Security Audit Report', 0, 1, 'C')
    pdf.ln(10)
    pdf.set_font('Arial', '', 12)
    
    for key, value in results.items():
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, f'{key}:', 0, 1, 'L')
        pdf.set_font('Arial', '', 12)
        for subkey, subvalue in value.items():
            pdf.cell(0, 10, f'{subkey}:', 0, 1, 'L')
            pdf.multi_cell(0, 8, str(subvalue['result']), 0, 1)
            pdf.ln(5)
            pdf.set_draw_color(0, 0, 0)
            pdf.set_line_width(0.5)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(5)
    
    pdf_filename = "security_audit_report.pdf"
    pdf.output(pdf_filename)
    return pdf_filename

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

@app.route('/generate_report', methods=['GET'])
def generate_report():
    results = {
        "Windows Audit": perform_windows_audit(),
        "Linux Audit": perform_linux_audit(),
        "Router Audit": perform_router_audit(),
        "Web Server Audit": perform_webserver_audit()
    }
    save_audit_history(results)
    report_path = generate_pdf_report(results)
    return send_file(report_path, as_attachment=True)

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

if __name__ == '__main__':
    verify_db_connection()
    app.run(debug=True)