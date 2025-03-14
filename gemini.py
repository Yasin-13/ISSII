

from flask import Flask, jsonify, send_file
from flask_cors import CORS
import subprocess
import socket
from fpdf import FPDF
import os
import google.generativeai as genai

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure Gemini API
GENAI_API_KEY = "AIzaSyB7aHEwumP-zI8f1TYCxjK_o3deLRxK0Ik"

genai.configure(api_key=GENAI_API_KEY)

def run_powershell_command(command):
    try:
        result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return str(e)

def get_system_info():
    pc_name = socket.gethostname()
    ip_address = socket.gethostbyname(pc_name)
    os_version = run_powershell_command("(Get-CimInstance Win32_OperatingSystem).Caption")
    return {
        "PC Name": pc_name,
        "IP Address": ip_address,
        "OS Version": os_version
    }

def perform_audit():
    audit_results = {}
    
    system_info = get_system_info()
    audit_results["System Information"] = system_info

    firewall_status = "Enabled" if "True" in run_powershell_command("Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled") else "Disabled"
    audit_results["Firewall Status"] = firewall_status
    
    defender_status = "Enabled" if "True" in run_powershell_command("Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled") else "Disabled"
    audit_results["Windows Defender"] = defender_status
    
    updates_status = "Enabled" if any(x in run_powershell_command("Get-WindowsUpdateSetting | Select-Object -ExpandProperty AutomaticUpdateOption") for x in ["3", "4"]) else "Disabled"
    audit_results["Automatic Updates"] = updates_status
    
    uac_status = "Enabled" if "1" in run_powershell_command("(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA).EnableLUA") else "Disabled"
    audit_results["UAC Status"] = uac_status
    
    guest_account_status = "Enabled" if "True" in run_powershell_command("(Get-LocalUser -Name 'Guest').Enabled") else "Disabled"
    audit_results["Guest Account Status"] = guest_account_status
    
    bitlocker_status = run_powershell_command("Get-BitLockerVolume | Select-Object VolumeStatus")
    audit_results["BitLocker Status"] = bitlocker_status

    audit_results["Shared Folders"] = run_powershell_command("Get-SmbShare | Select-Object -ExpandProperty Name")
    audit_results["User Accounts"] = run_powershell_command("Get-LocalUser | Select-Object Name,Enabled")
    audit_results["Installed Antivirus"] = run_powershell_command("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName")
    audit_results["Running Services"] = run_powershell_command("Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name")
    audit_results["Audit Policies"] = run_powershell_command("auditpol /get /category:*")
    audit_results["Listening Ports"] = run_powershell_command("Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Select-Object LocalAddress,LocalPort")
    audit_results["Admin Users"] = run_powershell_command("Get-LocalGroupMember -Group 'Administrators'")

    return audit_results

def analyze_with_gemini(audit_results):
    try:
        model = genai.GenerativeModel("gemini-pro")
        response = model.generate_content(f"Analyze the following security audit results and provide recommendations: {audit_results}")
        return response.text
    except Exception as e:
        return f"Error analyzing with Gemini: {str(e)}"

def generate_pdf_report(results, analysis):
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
    
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Security Analysis & Recommendations', 0, 1, 'C')
    pdf.ln(5)
    pdf.set_font('Arial', '', 12)
    pdf.multi_cell(0, 8, analysis, 0, 1)
    
    pdf_filename = "security_audit_report.pdf"
    pdf.output(pdf_filename)
    return pdf_filename

@app.route('/audit', methods=['GET'])
def audit():
    results = perform_audit()
    analysis = analyze_with_gemini(results)
    return jsonify({"audit_results": results, "analysis": analysis})

@app.route('/generate_report', methods=['GET'])
def report():
    results = perform_audit()
    analysis = analyze_with_gemini(results)
    pdf_filename = generate_pdf_report(results, analysis)
    return send_file(pdf_filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
