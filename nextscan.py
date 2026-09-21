#!/usr/bin/env python3
"""
NextScan - Complete Subdomain & Reverse IP Scanner
Features:
- Real subdomain enumeration via DNS
- Reverse IP lookup
- DNS A/AAAA/CNAME/MX record queries
- Nextscan.cc API integration
- Multi-threaded processing
"""

import sys
import os
import requests
import dns.resolver
import socket
import threading
import configparser
import json
import time
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from urllib.parse import urljoin

# Color support
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def color_print(text, color=Colors.WHITE):
    print(f"{color}{text}{Colors.RESET}")

# Configuration
CONFIG_FILE = "nextscan_config.ini"
NEXTSCAN_API_URL = "https://nextscan.cc/api.php"

def save_api_key(api_key):
    """Save API key to config file"""
    config = configparser.ConfigParser()
    config['nextscan'] = {'api_key': api_key}
    try:
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)
        color_print("[+] API key saved!", Colors.GREEN)
        return True
    except Exception as e:
        color_print(f"[-] Error saving API key: {e}", Colors.RED)
        return False

def load_api_key():
    """Load API key from config file"""
    config = configparser.ConfigParser()
    try:
        config.read(CONFIG_FILE)
        return config.get('nextscan', 'api_key', fallback='')
    except:
        return ''

def validate_api_key(api_key):
    """Validate API key with nextscan.cc"""
    try:
        params = {
            'key': api_key,
            'domain': 'example.com',
            'type': 'subdomains'
        }
        response = requests.get(NEXTSCAN_API_URL, params=params, timeout=10)
        data = response.json()
        return data.get('success', False) or 'data' in data
    except:
        return False

class NextScanAPI:
    """Nextscan.cc API integration"""   
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = NEXTSCAN_API_URL
    
    def get_subdomains(self, domain):
        """Get subdomains from nextscan.cc API"""
        try:
            params = {
                'key': self.api_key,
                'domain': domain,
                'type': 'subdomains'
            }
            response = requests.get(self.base_url, params=params, timeout=30)
            data = response.json()
            
            if data.get('success'):
                subdomains = data.get('data', {}).get('subdomains', [])
                return subdomains
            return []
        except Exception as e:
            color_print(f"[-] API Error: {e}", Colors.RED)
            return []
    
    def reverse_ip_lookup(self, ip):
        """Get domains hosted on specific IP"""
        try:
            params = {
                'key': self.api_key,
                'target': ip,
                'type': 'reverse_ip'
            }
            response = requests.get(self.base_url, params=params, timeout=30)
            data = response.json()
            
            if data.get('success'):
                domains = data.get('data', {}).get('domains', [])
                return domains
            return []
        except Exception as e:
            color_print(f"[-] API Error: {e}", Colors.RED)
            return []

class DNSScanner:
    """DNS-based subdomain enumeration"""   
    # Common subdomains to check
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
        'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
        'm', 'mobile', 'api', 'dev', 'staging', 'test', 'prod',
        'admin', 'console', 'dashboard', 'blog', 'shop', 'support',
        'cdn', 'static', 'assets', 'images', 'downloads', 'files'
    ]
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def check_subdomain(self, subdomain, domain):
        """Check if subdomain exists via DNS"""
        full_domain = f"{subdomain}.{domain}"
        try:
            answers = self.resolver.resolve(full_domain, 'A')
            ips = [rdata.address for rdata in answers]
            return True, ips
        except:
            return False, []
    
    def enumerate_subdomains(self, domain, threads=10):
        """Enumerate common subdomains"""
        results = []
        
        def worker(subdomain):
            exists, ips = self.check_subdomain(subdomain, domain)
            if exists:
                color_print(f"[+] Found: {subdomain}.{domain} -> {', '.join(ips)}", Colors.GREEN)
                results.append({
                    'subdomain': f"{subdomain}.{domain}",
                    'ips': ips
                })
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(worker, self.COMMON_SUBDOMAINS)
        
        return results
    
    def get_dns_records(self, domain):
        """Get various DNS records for domain"""
        records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                pass
        
        return records

class ReverseIPLookup:
    """Reverse IP lookup functionality"""   
    @staticmethod
    def get_hostname(ip):
        """Get hostname from IP"""   
        try:
            hostname = socket.gethostbyaddr(ip)
            return hostname[0]
        except:
            return None
    
    @staticmethod
    def get_ip(domain):
        """Get IP from domain"""   
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except:
            return None

class NextScan:
    """Main scanner class"""   
    def __init__(self, api_key=''):
        self.api_key = api_key
        self.api_client = NextScanAPI(api_key) if api_key else None
        self.dns_scanner = DNSScanner()
        self.reverse_lookup = ReverseIPLookup()
        self.results = []
    
    def scan_domain(self, domain):
        """Comprehensive domain scan"""
        color_print(f"\n[*] Scanning domain: {domain}", Colors.CYAN)
        color_print("=" * 60, Colors.GRAY)
        
        # Get basic DNS records
        color_print("\n[*] Fetching DNS records...", Colors.BLUE)
        dns_records = self.dns_scanner.get_dns_records(domain)
        for record_type, values in dns_records.items():
            for value in values:
                color_print(f"  [{record_type}] {value}", Colors.YELLOW)
        
        # Enumerate subdomains via DNS
        color_print("\n[*] Enumerating subdomains via DNS...", Colors.BLUE)
        dns_subs = self.dns_scanner.enumerate_subdomains(domain)
        
        # Get subdomains from API if available
        api_subs = []
        if self.api_client:
            color_print("\n[*] Fetching subdomains from Nextscan.cc API...", Colors.BLUE)
            api_subs = self.api_client.get_subdomains(domain)
            for sub in api_subs:
                subdomain_name = sub.get('subdomain', sub) if isinstance(sub, dict) else sub
                ip = sub.get('ip', '') if isinstance(sub, dict) else ''
                color_print(f"  [API] {subdomain_name} -> {ip}", Colors.GREEN)
        
        # Combine results
        all_subdomains = dns_subs + api_subs
        
        color_print(f"\n[+] Found {len(all_subdomains)} subdomains!", Colors.GREEN)
        
        # Save to file
        output_file = f"scan_{domain}_{int(time.time())}.txt"
        with open(output_file, 'w') as f:
            for sub in all_subdomains:
                if isinstance(sub, dict):
                    subdomain = sub.get('subdomain', sub.get('subdomain', ''))
                    ips = sub.get('ips', [])
                    f.write(f"{subdomain},{','.join(ips) if ips else ''}\n")
                else:
                    f.write(f"{sub}\n")
        
        color_print(f"[+] Results saved to {output_file}", Colors.GREEN)
        return all_subdomains
    
    def reverse_ip(self, ip):
        """Reverse IP lookup"""   
        color_print(f"\n[*] Reverse IP lookup: {ip}", Colors.CYAN)
        color_print("=" * 60, Colors.GRAY)
        
        if not self.api_client:
            color_print("[-] API key required for reverse IP lookup", Colors.RED)
            return
        
        domains = self.api_client.reverse_ip_lookup(ip)
        color_print(f"[+] Found {len(domains)} domains on {ip}", Colors.GREEN)
        
        for domain in domains:
            color_print(f"  - {domain}", Colors.YELLOW)
        
        # Save to file
        output_file = f"reverse_ip_{ip}_{int(time.time())}.txt"
        with open(output_file, 'w') as f:
            for domain in domains:
                f.write(f"{domain}\n")
        
        color_print(f"[+] Results saved to {output_file}", Colors.GREEN)
        return domains

def show_banner():
    """Display banner"""   
    banner = """
    ╔═══════════════════════════════════════╗
    ║         NEXTSCAN v2.0                 ║
    ║  Subdomain & Reverse IP Scanner       ║
    ╚═══════════════════════════════════════╝
    """
    color_print(banner, Colors.CYAN)

def main_menu():
    """Display main menu"""   
    show_banner()
    
    api_key = load_api_key()
    
    while True:
        print("\n[OPTIONS]")
        print("[1] Set API Key")
        print("[2] Scan Domain")
        print("[3] Reverse IP Lookup")
        print("[4] Scan from File")
        print("[0] Exit")
        
        choice = input("\n> ").strip()
        
        if choice == '1':
            api_key = input("Enter your Nextscan.cc API key: ").strip()
            if validate_api_key(api_key):
                save_api_key(api_key)
            else:
                color_print("[-] Invalid API key", Colors.RED)
        
        elif choice == '2':
            domain = input("Enter domain: ").strip()
            if domain:
                scanner = NextScan(api_key)
                scanner.scan_domain(domain)
        
        elif choice == '3':
            if not api_key:
                color_print("[-] API key required!", Colors.RED)
                continue
            ip = input("Enter IP address: ").strip()
            if ip:
                scanner = NextScan(api_key)
                scanner.reverse_ip(ip)
        
        elif choice == '4':
            file_path = input("Enter file path: ").strip()
            try:
                with open(file_path, 'r') as f:
                    domains = [line.strip() for line in f if line.strip()]
                
                scanner = NextScan(api_key)
                for domain in domains:
                    scanner.scan_domain(domain)
                    time.sleep(1)  # Rate limiting
            except Exception as e:
                color_print(f"[-] Error: {e}", Colors.RED)
        
        elif choice == '0':
            color_print("\n[*] Goodbye!", Colors.CYAN)
            break

if __name__ == '__main__':
    try:
        main_menu()
    except KeyboardInterrupt:
        color_print("\n\n[!] Interrupted by user", Colors.YELLOW)
    except Exception as e:
        color_print(f"[-] Error: {e}", Colors.RED)