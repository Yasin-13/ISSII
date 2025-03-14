from flask import Flask, jsonify, send_file
from flask_cors import CORS
import subprocess
import socket
import paramiko
from fpdf import FPDF
import json
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

LINUX_VM_IP = "172.20.10.3"
LINUX_VM_USER = "parrot"
LINUX_VM_PASSWORD = "parrot"

ROUTER_IP = "192.168.1.1"
ROUTER_USER = "admin"
ROUTER_PASSWORD = "admin"

AUDIT_HISTORY_FILE = "audit_history.json"

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
    history_entry = {
        "timestamp": timestamp,
        "results": audit_results
    }
    
    if os.path.exists(AUDIT_HISTORY_FILE):
        with open(AUDIT_HISTORY_FILE, 'r') as file:
            audit_history = json.load(file)
    else:
        audit_history = []
    
    audit_history.append(history_entry)
    
    with open(AUDIT_HISTORY_FILE, 'w') as file:
        json.dump(audit_history, file, indent=4)

@app.route('/generate_report', methods=['GET'])
def generate_report():
    results = {
        "Windows Audit": perform_windows_audit(),
        "Linux Audit": perform_linux_audit(),
        "Router Audit": perform_router_audit()
    }
    save_audit_history(results)
    report_path = generate_pdf_report(results)
    return send_file(report_path, as_attachment=True)

@app.route('/audit/windows', methods=['GET'])
def audit_windows():
    results = perform_windows_audit()
    save_audit_history({"Windows Audit": results})
    return jsonify(results)

@app.route('/audit/linux', methods=['GET'])
def audit_linux():
    results = perform_linux_audit()
    save_audit_history({"Linux Audit": results})
    return jsonify(results)

@app.route('/audit/router', methods=['GET'])
def audit_router():
    results = perform_router_audit()
    save_audit_history({"Router Audit": results})
    return jsonify(results)

@app.route('/audit/history', methods=['GET'])
def audit_history():
    if os.path.exists(AUDIT_HISTORY_FILE):
        with open(AUDIT_HISTORY_FILE, 'r') as file:
            audit_history = json.load(file)
    else:
        audit_history = []
    return jsonify(audit_history)

if __name__ == '__main__':
    app.run(debug=True)