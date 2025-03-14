import paramiko
import re
import requests
from datetime import datetime

# Function to connect to the router via SSH
def ssh_connect(host, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, username=username, password=password)
        return ssh
    except paramiko.AuthenticationException:
        print("Authentication failed.")
        return None

# Function to execute a command on the router
def execute_command(ssh, command):
    stdin, stdout, stderr = ssh.exec_command(command)
    return stdout.read().decode()

# Function to check for default credentials
def check_default_credentials(ssh, host):
    default_users = ["admin", "root", "user"]
    default_passwords = ["admin", "password", "1234", "root"]
    for user in default_users:
        for pwd in default_passwords:
            if ssh_connect(host, user, pwd):
                print(f"Default credentials found: {user}/{pwd}")
                return True
    print("No default credentials found.")
    return False

# Function to check for open ports
def check_open_ports(ssh):
    open_ports = execute_command(ssh, "netstat -tuln")
    print("Open ports:\n", open_ports)

# Function to check firmware version
def check_firmware_version(ssh):
    firmware_version = execute_command(ssh, "show version")
    print("Firmware version:\n", firmware_version)

# Function to check for configured firewalls
def check_firewall(ssh):
    firewall_status = execute_command(ssh, "show firewall status")
    print("Firewall status:\n", firewall_status)

# Function to check for active devices
def check_active_devices(ssh):
    active_devices = execute_command(ssh, "show arp")
    print("Active devices:\n", active_devices)

# Function to check for strong passwords
def check_password_policy(ssh):
    password_policy = execute_command(ssh, "show password policy")
    print("Password policy:\n", password_policy)

# Function to check for unused services
def check_unused_services(ssh):
    services = execute_command(ssh, "show services")
    unused_services = [service for service in services.split('\n') if "inactive" in service]
    print("Unused services:\n", "\n".join(unused_services))

# Function to check for SSL/TLS configurations
def check_ssl_tls_config(host):
    try:
        response = requests.get(f"https://{host}", verify=False)
        print(f"SSL/TLS configuration for {host}:\n", response.headers)
    except requests.exceptions.SSLError as e:
        print(f"SSL/TLS configuration error for {host}:\n", e)

# Function to check for outdated firmware
def check_outdated_firmware(ssh):
    firmware_version = execute_command(ssh, "show version")
    # Here, we compare the current firmware version with the latest version from the vendor's website
    latest_firmware_version = "1.2.3"  # This would be fetched from the vendor's website
    if firmware_version.strip() < latest_firmware_version:
        print(f"Outdated firmware detected. Current version: {firmware_version.strip()}, Latest version: {latest_firmware_version}")
    else:
        print(f"Firmware is up-to-date. Version: {firmware_version.strip()}")

# Function to review router configuration for insecure settings
def review_router_config(ssh):
    config = execute_command(ssh, "show running-config")
    insecure_patterns = ["no password", "telnet", "http server"]
    for pattern in insecure_patterns:
        if re.search(pattern, config, re.IGNORECASE):
            print(f"Insecure setting found: {pattern}")

# Function to collect logs from the router
def collect_logs(ssh):
    logs = execute_command(ssh, "show log")
    log_file = f"router_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(log_file, "w") as file:
        file.write(logs)
    print(f"Logs collected and saved to {log_file}")

# Function to perform the security audit
def perform_security_audit(host, username, password):
    ssh = ssh_connect(host, username, password)
    if ssh is None:
        return

    print("Performing security audit...")
    check_default_credentials(ssh, host)
    check_open_ports(ssh)
    check_firmware_version(ssh)
    check_firewall(ssh)
    check_active_devices(ssh)
    check_password_policy(ssh)
    check_unused_services(ssh)
    check_ssl_tls_config(host)
    check_outdated_firmware(ssh)
    review_router_config(ssh)
    collect_logs(ssh)

    ssh.close()
    print("Security audit completed.")

if __name__ == "__main__":
    host = input("Enter router IP address: ")
    username = input("Enter SSH username: ")
    password = input("Enter SSH password: ")

    perform_security_audit(host, username, password)