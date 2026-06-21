#!/usr/bin/env python3
"""
Python Port Scanner - Advanced Edition
Features: Multithreading, banner grabbing, range scan, JSON/CSV export, colored output
Author: HackerAI
"""

import socket
import sys
import threading
import json
import csv
import signal
from datetime import datetime
from queue import Queue
try:
    from colorama import init, Fore, Style
    init()
    COLORS = True
except ImportError:
    COLORS = False

# Globals
print_lock = threading.Lock()
results = []
scan_active = True

# Banner colors
if COLORS:
    R, G, Y, B, M, C, RS = Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN, Style.RESET_ALL
else:
    R = G = Y = B = M = C = RS = ""

SERVICE_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 69: "TFTP", 80: "HTTP", 81: "HTTP-Alt", 88: "Kerberos",
    110: "POP3", 111: "RPC", 135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos-Pwd",
    465: "SMTPS", 500: "IPsec", 514: "Syslog", 587: "SMTP-Submit",
    593: "MSRPC-HTTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1025: "NFS", 1080: "SOCKS", 1194: "OpenVPN", 1352: "Lotus-Notes",
    1433: "MSSQL", 1521: "Oracle-DB", 1723: "PPTP", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel-SSL", 2096: "cPanel-Webmail",
    2483: "Oracle-DB2", 2484: "Oracle-DB2-SSL", 3128: "Squid-Proxy",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4333: "MySQL-Alt",
    4444: "Metasploit", 4500: "IPsec-NAT", 4848: "GlassFish",
    5000: "Flask/UPnP", 5432: "PostgreSQL", 5555: "Android-ADB",
    5632: "PCAnywhere", 5800: "VNC-HTTP", 5900: "VNC", 5901: "VNC-1",
    5902: "VNC-2", 5903: "VNC-3", 5984: "CouchDB", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6000: "X11", 6379: "Redis", 6667: "IRC",
    6668: "IRC-SSL", 7001: "WebLogic", 7002: "WebLogic-SSL",
    7777: "Teradata", 8000: "HTTP-Alt", 8001: "HTTP-Alt", 8080: "HTTP-Proxy",
    8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9000: "SonarQube",
    9090: "WebLogic-Admin", 9100: "JetDirect", 9200: "Elasticsearch",
    9300: "Elasticsearch-Transport", 9418: "Git", 9999: "Abyss-Web",
    10000: "Webmin", 11211: "Memcached", 27017: "MongoDB",
    27018: "MongoDB-Alt", 27019: "MongoDB-Config", 50000: "SAP",
    50070: "Hadoop-NN", 50075: "Hadoop-DN"
}

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    global scan_active
    print(f"\n{R}[!] Scan interrupted by user{RS}" if COLORS else "\n[!] Scan interrupted by user")
    scan_active = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def grab_banner(target, port, timeout=3):
    """Attempt to grab service banner from open port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        
        # Send probe for common services
        probes = {
            21: b"QUIT\r\n",
            22: b"",
            23: b"\r\n",
            25: b"EHLO test\r\n",
            80: b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
            110: b"QUIT\r\n",
            143: b"A01 LOGOUT\r\n",
            443: b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
            3306: b"",
            3389: b"",
        }
        
        probe = probes.get(port, b"\r\n")
        if probe:
            s.send(probe)
        
        banner = s.recv(1024)
        s.close()
        
        decoded = banner.decode("utf-8", errors="ignore").strip()[:100]
        return decoded if decoded else "No banner"
    except:
        return "No banner"

def scan_worker(target, port, grab_banners=False):
    """Worker thread for scanning a single port."""
    global scan_active
    if not scan_active:
        return
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        result = s.connect_ex((target, port))
        
        if result == 0:
            banner = ""
            if grab_banners:
                banner = grab_banner(target, port)
            
            service = SERVICE_PORTS.get(port, "Unknown")
            
            with print_lock:
                status = f"{G}[+] Port {port}/{service} is OPEN{RS}" if COLORS else f"[+] Port {port}/{service} is OPEN"
                if banner and banner != "No banner":
                    status += f" {C}-> {banner}{RS}" if COLORS else f" -> {banner}"
                print(status)
            
            results.append({
                "port": port,
                "service": service,
                "banner": banner.replace("\n", " | ").replace("\r", "") if banner else "",
                "state": "open"
            })
        
        s.close()
    except:
        pass

def scan_range(target, start_port, end_port, threads=100, grab_banners=False):
    """Scan a range of ports using multithreading."""
    global results, scan_active
    results = []
    scan_active = True
    
    print(f"\n{B}[*] Target: {target}{RS}" if COLORS else f"\n[*] Target: {target}")
    print(f"{B}[*] Port Range: {start_port}-{end_port} ({end_port - start_port + 1} ports){RS}" if COLORS else f"[*] Port Range: {start_port}-{end_port}")
    print(f"{B}[*] Threads: {threads}{RS}" if COLORS else f"[*] Threads: {threads}")
    print(f"{B}[*] Banner Grabbing: {'Enabled' if grab_banners else 'Disabled'}{RS}" if COLORS else f"[*] Banner Grabbing: {'Enabled' if grab_banners else 'Disabled'}")
    print(f"{B}[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RS}\n" if COLORS else f"[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    queue = Queue()
    
    for port in range(start_port, end_port + 1):
        queue.put(port)
    
    def worker():
        while not queue.empty() and scan_active:
            port = queue.get()
            scan_worker(target, port, grab_banners)
            queue.task_done()
    
    # Start threads
    thread_list = []
    for _ in range(min(threads, end_port - start_port + 1)):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)
    
    queue.join()
    
    # Sort results by port
    results.sort(key=lambda x: x["port"])
    
    print(f"\n{'='*60}")
    print(f"     Scan Complete - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    print(f"\n[+] Total Open Ports: {len(results)}")
    
    if results:
        print(f"\n   {'PORT':<8} {'SERVICE':<20} {'BANNER'}")
        print(f"   {'-'*8} {'-'*20} {'-'*30}")
        for r in results:
            banner_short = r['banner'][:50] if r.get('banner') else ""
            print(f"   {str(r['port']):<8} {r['service']:<20} {banner_short}")
    
    return results

def export_json(results, filename="scan_results.json"):
    """Export results to JSON."""
    data = {
        "scan_time": datetime.now().isoformat(),
        "total_open": len(results),
        "ports": results
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"{G}[+] Results exported to {filename}{RS}" if COLORS else f"[+] Results exported to {filename}")

def export_csv(results, filename="scan_results.csv"):
    """Export results to CSV."""
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "service", "banner", "state"])
        writer.writeheader()
        writer.writerows(results)
    print(f"{G}[+] Results exported to {filename}{RS}" if COLORS else f"[+] Results exported to {filename}")

def print_banner():
    """Display tool banner."""
    banner = f"""
{C}╔══════════════════════════════════════════════════════╗{RS}
{C}║{RS}{Y}         ADVANCED PORT SCANNER v2.0              {RS}{C}║{RS}
{C}║{RS}{M}       Multithreaded · Banner Grab · Reports       {RS}{C}║{RS}
{C}╚══════════════════════════════════════════════════════╝{RS}
"""
    print(banner)

def main():
    print_banner()
    
    target = input(f"{Y}[?] Enter target IP/hostname: {RS}").strip()
    if not target:
        print(f"{R}[!] No target specified{RS}" if COLORS else "[!] No target specified")
        sys.exit(1)
    
    print(f"\n{M}[1] Quick scan (common ports){RS}" if COLORS else "\n[1] Quick scan (common ports)")
    print(f"{M}[2] Custom range scan{RS}" if COLORS else "[2] Custom range scan")
    print(f"{M}[3] Full scan (1-65535){RS}" if COLORS else "[3] Full scan (1-65535)")
    
    choice = input(f"\n{Y}[?] Select option (1-3): {RS}").strip()
    
    grab_banners = input(f"{Y}[?] Enable banner grabbing? (y/N): {RS}").strip().lower() == "y"
    export_results = input(f"{Y}[?] Export results? (JSON/CSV/n): {RS}").strip().lower()
    threads_input = input(f"{Y}[?] Threads (default 100): {RS}").strip()
    threads = int(threads_input) if threads_input.isdigit() else 100
    
    if choice == "1":
        ports = list(SERVICE_PORTS.keys())
        start_port, end_port = min(ports), max(ports)
    elif choice == "2":
        try:
            port_range = input(f"{Y}[?] Port range (e.g., 1-1000): {RS}").strip()
            start_port, end_port = map(int, port_range.split("-"))
        except:
            print(f"{R}[!] Invalid range, using 1-1000{RS}" if COLORS else "[!] Invalid range, using 1-1000")
            start_port, end_port = 1, 1000
    else:
        start_port, end_port = 1, 65535
    
    results = scan_range(target, start_port, end_port, threads, grab_banners)
    
    if export_results == "json":
        export_json(results)
    elif export_results == "csv":
        export_csv(results)

if __name__ == "__main__":
    main()
