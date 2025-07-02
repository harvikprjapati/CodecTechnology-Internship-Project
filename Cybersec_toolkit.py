import re
import socket

# Password Strength Checker
def check_password_strength(password):
    length = len(password)
    if length < 8:
        return "Weak: Too short"
    score = 0
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[@$!%*?&]', password):
        score += 1

    if score == 4 and length >= 12:
        return "Very Strong"
    elif score >= 3:
        return "Strong"
    elif score == 2:
        return "Medium"
    else:
        return "Weak"

# Basic Network Scanner
def scan_ports(ip, ports=[22, 80, 443]):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except socket.error:
            pass
        finally:
            sock.close()
    return open_ports

# Vulnerability Scanner (simple example)
def simple_vuln_scan(ip):
    open_ports = scan_ports(ip)
    vulnerabilities = []
    if 22 in open_ports:
        vulnerabilities.append("SSH port open - check for weak/default credentials")
    if 80 in open_ports:
        vulnerabilities.append("HTTP port open - check for outdated web server")
    if 443 in open_ports:
        vulnerabilities.append("HTTPS port open - check SSL/TLS configuration")
    return vulnerabilities

# Simple Firewall Simulation
class SimpleFirewall:
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_ports = set()

    def block_ip(self, ip):
        self.blocked_ips.add(ip)

    def unblock_ip(self, ip):
        self.blocked_ips.discard(ip)

    def block_port(self, port):
        self.blocked_ports.add(port)

    def unblock_port(self, port):
        self.blocked_ports.discard(port)

    def is_allowed(self, ip, port):
        if ip in self.blocked_ips or port in self.blocked_ports:
            return False
        return True

def main():
    firewall = SimpleFirewall()

    while True:
        print("\n--- Cybersecurity Toolkit ---")
        print("1. Password Strength Checker")
        print("2. Basic Network Scanner")
        print("3. Vulnerability Scanner")
        print("4. Simple Firewall")
        print("5. Exit")
        choice = input("Choose a tool (1-5): ")

        if choice == '1':
            pwd = input("Enter password to check: ")
            print("Password strength:", check_password_strength(pwd))

        elif choice == '2':
            ip = input("Enter IP to scan: ")
            ports_input = input("Enter ports to scan (comma separated, default 22,80,443): ")
            if ports_input.strip():
                try:
                    ports = [int(p.strip()) for p in ports_input.split(',')]
                except ValueError:
                    print("Invalid ports input, using default ports.")
                    ports = [22, 80, 443]
            else:
                ports = [22, 80, 443]
            open_ports = scan_ports(ip, ports)
            print(f"Open ports on {ip}: {open_ports}")

        elif choice == '3':
            ip = input("Enter IP to scan for vulnerabilities: ")
            vulns = simple_vuln_scan(ip)
            if vulns:
                print("Vulnerabilities found:")
                for v in vulns:
                    print(f"- {v}")
            else:
                print("No vulnerabilities found.")

        elif choice == '4':
            while True:
                print("\n--- Simple Firewall Menu ---")
                print("1. Block IP")
                print("2. Unblock IP")
                print("3. Block Port")
                print("4. Unblock Port")
                print("5. Check if Allowed")
                print("6. Show Blocked IPs and Ports")
                print("7. Exit Firewall Menu")
                f_choice = input("Choose an option: ")

                if f_choice == '1':
                    ip = input("Enter IP to block: ")
                    firewall.block_ip(ip)
                    print(f"Blocked IP {ip}")

                elif f_choice == '2':
                    ip = input("Enter IP to unblock: ")
                    firewall.unblock_ip(ip)
                    print(f"Unblocked IP {ip}")

                elif f_choice == '3':
                    try:
                        port = int(input("Enter port to block: "))
                        firewall.block_port(port)
                        print(f"Blocked port {port}")
                    except ValueError:
                        print("Invalid port number.")

                elif f_choice == '4':
                    try:
                        port = int(input("Enter port to unblock: "))
                        firewall.unblock_port(port)
                        print(f"Unblocked port {port}")
                    except ValueError:
                        print("Invalid port number.")

                elif f_choice == '5':
                    ip = input("Enter IP to check: ")
                    try:
                        port = int(input("Enter port to check: "))
                        allowed = firewall.is_allowed(ip, port)
                        print("Allowed" if allowed else "Blocked")
                    except ValueError:
                        print("Invalid port number.")

                elif f_choice == '6':
                    print("Blocked IPs:", firewall.blocked_ips)
                    print("Blocked Ports:", firewall.blocked_ports)

                elif f_choice == '7':
                    break

                else:
                    print("Invalid option.")

        elif choice == '5':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please select 1-5.")

if __name__ == "__main__":
    main()
import re
import socket
import threading
import ipaddress
import time
import json
import os
from math import log2

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # colorama not installed, define dummy colors
    class Fore:
        RED = ''
        GREEN = ''
        YELLOW = ''
        CYAN = ''
        RESET = ''
    class Style:
        BRIGHT = ''
        RESET_ALL = ''

# --- Password Strength Checker with entropy and suggestions ---
def password_entropy(password):
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'\d', password):
        pool += 10
    if re.search(r'[@$!%*?&]', password):
        pool += 8  # common special chars
    if pool == 0:
        return 0
    return round(len(password) * log2(pool), 2)

def check_password_strength(password):
    entropy = password_entropy(password)
    suggestions = []
    if len(password) < 8:
        suggestions.append("Increase length to at least 8 characters.")
    if not re.search(r'[a-z]', password):
        suggestions.append("Add lowercase letters.")
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add uppercase letters.")
    if not re.search(r'\d', password):
        suggestions.append("Add digits.")
    if not re.search(r'[@$!%*?&]', password):
        suggestions.append("Add special characters like @$!%*?&.")

    if entropy < 28:
        strength = "Very Weak"
    elif entropy < 36:
        strength = "Weak"
    elif entropy < 60:
        strength = "Moderate"
    elif entropy < 128:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return strength, entropy, suggestions

# --- Network Scanner with threading and IP range support ---
def scan_port(ip, port, open_ports, timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
    except socket.error:
        pass
    finally:
        sock.close()

def scan_ports(ip, ports, timeout=0.5):
    open_ports = []
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(ip, port, open_ports, timeout))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return sorted(open_ports)

def scan_ip_range(start_ip, end_ip, ports, timeout=0.5):
    open_ports_per_ip = {}
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    for ip_int in range(int(start), int(end) + 1):
        ip = str(ipaddress.IPv4Address(ip_int))
        open_ports = scan_ports(ip, ports, timeout)
        if open_ports:
            open_ports_per_ip[ip] = open_ports
    return open_ports_per_ip

# --- Vulnerability Scanner with banner grabbing and simple CVE lookup ---
def grab_banner(ip, port, timeout=1):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode(errors='ignore')
        sock.close()
        return banner.strip()
    except Exception:
        return ""

# Static CVE-like database for demo
CVE_DB = {
    "OpenSSH 7.2p2": ["CVE-2016-0777", "CVE-2016-0778"],
    "Apache httpd 2.4.49": ["CVE-2021-41773"],
    "nginx 1.18.0": ["CVE-2019-20372"],
}

DEFAULT_CREDENTIALS = {
    22: [("root", "root"), ("admin", "admin")],
    80: [("admin", "admin"), ("user", "password")],
}

def simple_vuln_scan(ip, ports=[22, 80, 443]):
    vulns = []
    open_ports = scan_ports(ip, ports)
    for port in open_ports:
        banner = grab_banner(ip, port)
        if banner:
            for key in CVE_DB:
                if key.lower() in banner.lower():
                    vulns.append(f"Port {port} ({banner}): Known vulnerabilities {CVE_DB[key]}")
        # Check default creds warning
        if port in DEFAULT_CREDENTIALS:
            vulns.append(f"Port {port} open - check for default credentials {DEFAULT_CREDENTIALS[port]}")
    return vulns

# --- Simple Firewall with persistence and IP range blocking ---
class SimpleFirewall:
    def __init__(self, rules_file='firewall_rules.json'):
        self.rules_file = rules_file
        self.blocked_ips = set()
        self.blocked_ip_ranges = []
        self.blocked_ports = set()
        self.load_rules()

    def block_ip(self, ip):
        self.blocked_ips.add(ip)
        self.save_rules()

    def unblock_ip(self, ip):
        self.blocked_ips.discard(ip)
        self.save_rules()

    def block_ip_range(self, start_ip, end_ip):
        self.blocked_ip_ranges.append((start_ip, end_ip))
        self.save_rules()

    def unblock_ip_range(self, start_ip, end_ip):
        try:
            self.blocked_ip_ranges.remove((start_ip, end_ip))
            self.save_rules()
        except ValueError:
            pass

    def block_port(self, port):
        self.blocked_ports.add(port)
        self.save_rules()

    def unblock_port(self, port):
        self.blocked_ports.discard(port)
        self.save_rules()

    def is_ip_blocked(self, ip):
        if ip in self.blocked_ips:
            return True
        ip_addr = ipaddress.IPv4Address(ip)
        for start_ip, end_ip in self.blocked_ip_ranges:
            if ipaddress.IPv4Address(start_ip) <= ip_addr <= ipaddress.IPv4Address(end_ip):
                return True
        return False

    def is_allowed(self, ip, port):
        if self.is_ip_blocked(ip) or port in self.blocked_ports:
            return False
        return True

    def save_rules(self):
        data = {
            "blocked_ips": list(self.blocked_ips),
            "blocked_ip_ranges": self.blocked_ip_ranges,
            "blocked_ports": list(self.blocked_ports)
        }
        with open(self.rules_file, 'w') as f:
            json.dump(data, f, indent=2)

    def load_rules(self):
        if os.path.exists(self.rules_file):
            with open(self.rules_file, 'r') as f:
                data = json.load(f)
                self.blocked_ips = set(data.get("blocked_ips", []))
                self.blocked_ip_ranges = data.get("blocked_ip_ranges", [])
                self.blocked_ports = set(data.get("blocked_ports", []))
        else:
            self.blocked_ips = set()
            self.blocked_ip_ranges = []
            self.blocked_ports = set()

# --- Main UI ---
def main():
    firewall = SimpleFirewall()

    while True:
        print(Fore.CYAN + Style.BRIGHT + "\n--- Cybersecurity Toolkit ---")
        print("1. Password Strength Checker")
        print("2. Basic Network Scanner")
        print("3. Vulnerability Scanner")
        print("4. Simple Firewall")
        print("5. Exit")
        choice = input("Choose a tool (1-5): ").strip()

        if choice == '1':
            pwd = input("Enter password to check: ")
            strength, entropy, suggestions = check_password_strength(pwd)
            print(f"Strength: {Fore.GREEN if 'Strong' in strength or 'Very Strong' in strength else Fore.RED}{strength}{Fore.RESET}")
            print(f"Entropy: {entropy} bits")
            if suggestions:
                print(Fore.YELLOW + "Suggestions to improve your password:")
                for s in suggestions:
                    print(f"- {s}")

        elif choice == '2':
            ip_input = input("Enter IP or IP range (e.g. 192.168.1.1 or 192.168.1.1-192.168.1.10): ").strip()
            ports_input = input("Enter ports to scan (comma separated, default 22,80,443): ").strip()
            if ports_input:
                try:
                    ports = [int(p.strip()) for p in ports_input.split(',')]
                except ValueError:
                    print(Fore.RED + "Invalid ports input, using default ports.")
                    ports = [22, 80, 443]
            else:
                ports = [22, 80, 443]

            if '-' in ip_input:
                try:
                    start_ip, end_ip = ip_input.split('-')
                    print(Fore.CYAN + f"Scanning IP range {start_ip} to {end_ip} on ports {ports}...")
                    results = scan_ip_range(start_ip.strip(), end_ip.strip(), ports)
                    if results:
                        for ip, open_ports in results.items():
                            print(f"{ip}: Open ports {open_ports}")
                    else:
                        print("No open ports found in the range.")
                except Exception as e:
                    print(Fore.RED + f"Invalid IP range input: {e}")
            else:
                print(Fore.CYAN + f"Scanning {ip_input} on ports {ports}...")
                open_ports = scan_ports(ip_input, ports)
                if open_ports:
                    print(f"Open ports on {ip_input}: {open_ports}")
                else:
                    print("No open ports found.")

        elif choice == '3':
            ip = input("Enter IP to scan for vulnerabilities: ").strip()
            ports_input = input("Enter ports to scan (comma separated, default 22,80,443): ").strip()
            if ports_input:
                try:
                    ports = [int(p.strip()) for p in ports_input.split(',')]
                except ValueError:
                    print(Fore.RED + "Invalid ports input, using default ports.")
                    ports = [22, 80, 443]
            else:
                ports = [22, 80, 443]

            print(Fore.CYAN + f"Scanning {ip} for vulnerabilities on ports {ports}...")
            vulns = simple_vuln_scan(ip, ports)
            if vulns:
                print(Fore.RED + "Vulnerabilities found:")
                for v in vulns:
                    print(f"- {v}")
            else:
                print(Fore.GREEN + "No vulnerabilities found.")

        elif choice == '4':
            while True:
                print(Fore.CYAN + "\n--- Simple Firewall Menu ---")
                print("1. Block IP")
                print("2. Unblock IP")
                print("3. Block IP Range")
                print("4. Unblock IP Range")
                print("5. Block Port")
                print("6. Unblock Port")
                print("7. Check if Allowed")
                print("8. Show Blocked IPs and Ports")
                print("9. Exit Firewall Menu")
                f_choice = input("Choose an option: ").strip()

                if f_choice == '1':
                    ip = input("Enter IP to block: ").strip()
                    firewall.block_ip(ip)
                    print(Fore.GREEN + f"Blocked IP {ip}")

                elif f_choice == '2':
                    ip = input("Enter IP to unblock: ").strip()
                    firewall.unblock_ip(ip)
                    print(Fore.GREEN + f"Unblocked IP {ip}")

                elif f_choice == '3':
                    start_ip = input("Enter start IP of range to block: ").strip()
                    end_ip = input("Enter end IP of range to block: ").strip()
                    firewall.block_ip_range(start_ip, end_ip)
                    print(Fore.GREEN + f"Blocked IP range {start_ip} - {end_ip}")

                elif f_choice == '4':
                    start_ip = input("Enter start IP of range to unblock: ").strip()
                    end_ip = input("Enter end IP of range to unblock: ").strip()
                    firewall.unblock_ip_range(start_ip, end_ip)
                    print(Fore.GREEN + f"Unblocked IP range {start_ip} - {end_ip}")

                elif f_choice == '5':
                    try:
                        port = int(input("Enter port to block: ").strip())
                        firewall.block_port(port)
                        print(Fore.GREEN + f"Blocked port {port}")
                    except ValueError:
                        print(Fore.RED + "Invalid port number.")

                elif f_choice == '6':
                    try:
                        port = int(input("Enter port to unblock: ").strip())
                        firewall.unblock_port(port)
                        print(Fore.GREEN + f"Unblocked port {port}")
                    except ValueError:
                        print(Fore.RED + "Invalid port number.")

                elif f_choice == '7':
                    ip = input("Enter IP to check: ").strip()
                    try:
                        port = int(input("Enter port to check: ").strip())
                        allowed = firewall.is_allowed(ip, port)
                        print(Fore.GREEN + "Allowed" if allowed else Fore.RED + "Blocked")
                    except ValueError:
                        print(Fore.RED + "Invalid port number.")

                elif f_choice == '8':
                    print(Fore.YELLOW + "Blocked IPs:")
                    for ip in firewall.blocked_ips:
                        print(f"- {ip}")
                    print(Fore.YELLOW + "Blocked IP Ranges:")
                    for start_ip, end_ip in firewall.blocked_ip_ranges:
                        print(f"- {start_ip} - {end_ip}")
                    print(Fore.YELLOW + "Blocked Ports:")
                    for port in firewall.blocked_ports:
                        print(f"- {port}")

                elif f_choice == '9':
                    break

                else:
                    print(Fore.RED + "Invalid option.")

        elif choice == '5':
            print(Fore.CYAN + "Exiting...")
            break

        else:
            print(Fore.RED + "Invalid choice. Please select 1-5.")

if __name__ == "__main__":
    main()
