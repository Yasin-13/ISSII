from flask import Flask, jsonify, send_file
from flask_cors import CORS
import subprocess
import socket
from fpdf import FPDF
import os

app = Flask(__name__)
CORS(app)

# Function to run PowerShell command
def run_powershell_command(command):
    try:
        result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return str(e)

# Function to get system details
def get_system_info():
    try:
        pc_name = socket.gethostname()
        ip_address = socket.gethostbyname(pc_name)
        os_version = run_powershell_command("(Get-CimInstance Win32_OperatingSystem).Caption")
        return {
            "PC Name": pc_name,
            "IP Address": ip_address,
            "OS Version": os_version
        }
    except Exception as e:
        return {"Error": str(e)}

# Security audit function
def perform_audit():
    results = {
        "System Information": get_system_info(),
        "Firewall Status": "Enabled" if "True" in run_powershell_command("Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled") else "Disabled",
        "Windows Defender": "Enabled" if "True" in run_powershell_command("Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled") else "Disabled",
        "Automatic Updates": "Enabled" if any(x in run_powershell_command("Get-WindowsUpdateSetting | Select-Object -ExpandProperty AutomaticUpdateOption") for x in ["3", "4"]) else "Disabled",
        "UAC Status": "Enabled" if "1" in run_powershell_command("(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA).EnableLUA") else "Disabled",
        "Guest Account Status": "Enabled" if "True" in run_powershell_command("(Get-LocalUser -Name 'Guest').Enabled") else "Disabled",
        "Shared Folders": run_powershell_command("Get-SmbShare | Select-Object -ExpandProperty Name"),
        "User Accounts": run_powershell_command("Get-LocalUser | Select-Object Name,Enabled"),
        "Installed Antivirus": run_powershell_command("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName"),
        "BitLocker Status": run_powershell_command("Get-BitLockerVolume | Select-Object VolumeStatus"),
        "Running Services": run_powershell_command("Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name"),
        "Audit Policies": run_powershell_command("auditpol /get /category:*"),
        "Listening Ports": run_powershell_command("Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Select-Object LocalAddress,LocalPort"),
        "Admin Users": run_powershell_command("Get-LocalGroupMember -Group 'Administrators'"),
    }
    return results

# Generate formatted PDF Report
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
        pdf.multi_cell(0, 8, str(value), 0, 1)
        pdf.ln(5)
        pdf.set_draw_color(0, 0, 0)
        pdf.set_line_width(0.5)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
    
    pdf_filename = "security_audit_report.pdf"
    pdf.output(pdf_filename)
    return pdf_filename

@app.route('/audit', methods=['GET'])
def audit():
    results = perform_audit()
    return jsonify(results)

@app.route('/generate_report', methods=['GET'])
def report():
    results = perform_audit()
    pdf_filename = generate_pdf_report(results)
    return send_file(pdf_filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)