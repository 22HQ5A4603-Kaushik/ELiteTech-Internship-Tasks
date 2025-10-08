#!/usr/bin/env python3
"""
pentest_toolkit.py — Modular Penetration Testing Toolkit (educational)

Features:
 - portscan     : TCP connect port scanner (threaded)
 - banner       : simple banner grabbing
 - http-brute   : HTTP Basic Auth brute-force (safety-gated)
 - scan-all     : orchestration (port scan + banners)
 - auto-ports   : fast common ports mode (--auto-ports)
 - interactive  : if run with no args, prompts user with a menu

Safety:
 - Use ONLY on systems you own or are explicitly authorized to test.
 - Remote targets require explicit confirmation: environment ALLOW_PENTEST=1 or CLI flag --confirm.

Dependencies:
 - requests
Install: pip install requests
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket, argparse, sys, time, os, json
from typing import List, Dict, Tuple, Optional
import requests
from urllib.parse import urlparse

# Fast fallback common ports for --auto-ports
COMMON_PORTS = [
    20,21,22,23,25,53,67,68,69,80,88,110,111,123,135,137,138,139,143,161,162,
    179,194,389,443,445,465,514,515,587,631,636,665,989,990,993,995,1433,1434,
    1521,1723,2049,2082,2083,2086,2087,2095,2096,2161,2222,2302,2381,2483,2484,
    2557,3128,3306,3389,3690,3784,4369,4662,4899,5000,5060,5061,5432,5900,5984,
    6000,6665,6666,6667,6668,7000,8000,8008,8080,8081,8443,8888,9000,9090,9200,
    9300,27017
]

# -------------------------
# Helpers
# -------------------------
def parse_ports_string(s: str) -> List[int]:
    parts = [p.strip() for p in s.split(",") if p.strip()]
    ports = set()
    for part in parts:
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)

def load_ports_from_file(path: str) -> List[int]:
    ports = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "-" in line:
                    a,b = line.split("-",1)
                    try:
                        ports.extend(range(int(a), int(b)+1))
                    except Exception:
                        pass
                else:
                    try:
                        ports.append(int(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return sorted(set(p for p in ports if 0 < p < 65536))

def is_localhost(hostname: Optional[str]) -> bool:
    if not hostname: return False
    return hostname in ("localhost", "127.0.0.1", "::1")

def save_json_report(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Report saved to {path}")

def _confirm_action(target_host: str, allow_flag: bool) -> bool:
    """
    Safety gating: allow if ALLOW_PENTEST=1 or host is local.
    If allow_flag is True prompt user to type YES to confirm.
    """
    if os.environ.get("ALLOW_PENTEST") == "1":
        print("[*] ALLOW_PENTEST environment variable set -> proceeding.")
        return True
    if is_localhost(target_host):
        return True
    if allow_flag:
        print("WARNING: You are about to run pentest actions against a remote host:", target_host)
        print("Ensure you have WRITTEN authorization to test this target.")
        ans = input("Type YES to confirm you have permission (case-sensitive): ").strip()
        return ans == "YES"
    print("[!] Remote target detected and --confirm not provided. Aborting for safety.")
    return False

# -------------------------
# Network modules
# -------------------------
def _probe_port(host: str, port: int, timeout: float = 0.8) -> Tuple[int, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.shutdown(socket.SHUT_RDWR)
        s.close()
        return port, "open"
    except socket.timeout:
        return port, "filtered"
    except Exception:
        return port, "closed"

def port_scan(host: str, ports: List[int], timeout: float = 0.8, workers: int = 200) -> Dict[int, str]:
    results: Dict[int, str] = {}
    with ThreadPoolExecutor(max_workers=min(workers, max(4, len(ports)))) as ex:
        futures = {ex.submit(_probe_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            port, state = fut.result()
            results[port] = state
    return dict(sorted(results.items()))

def grab_banner(host: str, port: int, timeout: float = 1.0) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if port in (80, 8080, 8000, 443):
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            except Exception:
                pass
        try:
            data = s.recv(4096)
        except Exception:
            data = b""
        s.close()
        return data.decode(errors="replace").strip()
    except Exception:
        return ""

def http_bruteforce(target_url: str, username: str, wordlist_path: str,
                    threads: int = 8, timeout: float = 8.0, delay: float = 0.0,
                    allow_flag: bool = False) -> Dict[str, List[str]]:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    if not _confirm_action(host, allow_flag):
        print("[abort] Confirmation required for remote brute-force.")
        return {"success": []}

    if not os.path.isfile(wordlist_path):
        print(f"[error] Wordlist not found: {wordlist_path}")
        return {"success": []}

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        candidates = [line.strip() for line in f if line.strip()]

    session = requests.Session()
    session.headers.update({"User-Agent": "PentestToolkit/1.0"})
    successes: List[str] = []
    stop_flag = False

    def attempt(pw: str):
        nonlocal stop_flag
        if stop_flag:
            return None
        try:
            r = session.get(target_url, auth=(username, pw), timeout=timeout, allow_redirects=False)
            if r.status_code in (200, 201, 202) or (300 <= r.status_code < 400):
                stop_flag = True
                print(f"[found] {username}:{pw} -> HTTP {r.status_code}")
                return pw
        except Exception:
            return None
        finally:
            if delay:
                time.sleep(delay)
        return None

    with ThreadPoolExecutor(max_workers=max(2, threads)) as ex:
        futures = {ex.submit(attempt, pw): pw for pw in candidates}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                successes.append(res)
                break

    return {"success": successes}

def scan_all(host: str, ports_list: List[int], timeout: float = 0.8, workers: int = 200,
             do_banner: bool = True, allow_flag: bool = False) -> dict:
    if not _confirm_action(host, allow_flag):
        return {"error": "confirmation required for remote host"}

    print(f"[*] Scanning {len(ports_list)} ports on {host} ...")
    port_results = port_scan(host, ports_list, timeout=timeout, workers=workers)
    open_ports = [p for p, st in port_results.items() if st == "open"]

    banners = {}
    if do_banner and open_ports:
        print(f"[*] Grabbing banners for {len(open_ports)} open ports ...")
        with ThreadPoolExecutor(max_workers=min(64, len(open_ports))) as ex:
            futures = {ex.submit(grab_banner, host, p, timeout=1.2): p for p in open_ports}
            for fut in as_completed(futures):
                p = futures[fut]
                b = fut.result()
                banners[p] = b

    report = {
        "host": host,
        "ports_scanned": len(ports_list),
        "port_results": port_results,
        "open_ports": open_ports,
        "banners": banners,
        "timestamp": time.time()
    }
    return report

# -------------------------
# CLI and Interactive Menu
# -------------------------
def build_cli():
    parser = argparse.ArgumentParser(description="Pentest Toolkit — portscanner, banner grabber, http brute (educational)")
    sub = parser.add_subparsers(dest="cmd", required=False)

    p_scan = sub.add_parser("portscan", help="Threaded TCP port scan")
    p_scan.add_argument("host", help="Target host (IP or hostname)")
    p_scan.add_argument("--ports", default="1-1024", help="Ports list/ranges (e.g. 22,80,8000-8010)")
    p_scan.add_argument("--auto-ports", action="store_true", help="Use built-in fast common ports list (faster)")
    p_scan.add_argument("--top-ports-file", help="Path to file containing ports (one per line)")
    p_scan.add_argument("--timeout", type=float, default=0.8)
    p_scan.add_argument("--workers", type=int, default=200)
    p_scan.add_argument("--output", help="Save JSON report to file")
    p_scan.add_argument("--confirm", action="store_true", help="Confirm you have permission to scan remote hosts")

    p_banner = sub.add_parser("banner", help="Grab banner from a single host:port")
    p_banner.add_argument("host", help="Target host")
    p_banner.add_argument("port", type=int, help="Port number")
    p_banner.add_argument("--timeout", type=float, default=1.0)
    p_banner.add_argument("--output", help="Save banner to JSON file")
    p_banner.add_argument("--confirm", action="store_true")

    p_brute = sub.add_parser("http-brute", help="HTTP Basic Auth brute-force (requires --confirm for remote)")
    p_brute.add_argument("url", help="Target URL (include scheme)")
    p_brute.add_argument("username", help="Username to try")
    p_brute.add_argument("wordlist", help="Path to password wordlist (one password per line)")
    p_brute.add_argument("--threads", type=int, default=8)
    p_brute.add_argument("--timeout", type=float, default=8.0)
    p_brute.add_argument("--delay", type=float, default=0.0, help="Delay between attempts (seconds)")
    p_brute.add_argument("--output", help="Save JSON report to file")
    p_brute.add_argument("--confirm", action="store_true")

    p_all = sub.add_parser("scan-all", help="Run port scan then (optionally) banner-grab open ports")
    p_all.add_argument("host", help="Target host")
    p_all.add_argument("--ports", default="1-1024", help="Ports to scan")
    p_all.add_argument("--auto-ports", action="store_true", help="Use built-in fast common ports list (faster)")
    p_all.add_argument("--top-ports-file", help="Path to file containing a list of top ports (one per line)")
    p_all.add_argument("--timeout", type=float, default=0.8)
    p_all.add_argument("--workers", type=int, default=200)
    p_all.add_argument("--no-banner", action="store_true", help="Do not grab banners after scanning")
    p_all.add_argument("--output", help="Save JSON report to file")
    p_all.add_argument("--confirm", action="store_true")

    return parser

def choose_ports(args_ports: str, auto_flag: bool, top_file: Optional[str]) -> List[int]:
    if top_file and os.path.isfile(top_file):
        loaded = load_ports_from_file(top_file)
        if loaded:
            print(f"[*] Loaded {len(loaded)} ports from {top_file}")
            return loaded
        else:
            print(f"[!] Could not parse ports from {top_file}; falling back.")
    if auto_flag:
        print(f"[*] Using auto-ports (fast common ports: {len(COMMON_PORTS)} entries).")
        return COMMON_PORTS
    return parse_ports_string(args_ports)

def interactive_menu():
    print("\nPentest Toolkit — Interactive Menu")
    print("Use only on systems you own/have permission to test.")
    print("Choose an action:")
    print("1) Port scan")
    print("2) Banner grab")
    print("3) HTTP Basic brute-force")
    print("4) Scan all (port scan + banners)")
    print("5) Exit")
    choice = input("Enter number: ").strip()
    if choice == "1":
        host = input("Target host (IP/hostname) [127.0.0.1]: ").strip() or "127.0.0.1"
        auto = input("Use auto-ports? (y/N): ").strip().lower().startswith("y")
        topf = input("Top ports file (leave blank to skip): ").strip() or None
        ports_str = input("Ports (e.g. 1-1024) [1-1024]: ").strip() or "1-1024"
        timeout = float(input("Timeout seconds [0.8]: ").strip() or "0.8")
        workers = int(input("Workers [200]: ").strip() or "200")
        confirm = input("Confirm permission for remote host? (type YES to confirm) ").strip() == "YES"
        ports = choose_ports(ports_str, auto, topf)
        if not _confirm_action(host, confirm):
            print("Aborted.")
            return
        res = port_scan(host, ports, timeout=timeout, workers=workers)
        openp = [p for p,s in res.items() if s=="open"]
        print("Open ports:", openp)
    elif choice == "2":
        host = input("Target host [127.0.0.1]: ").strip() or "127.0.0.1"
        port = int(input("Port number [80]: ").strip() or "80")
        confirm = input("Confirm permission for remote host? (type YES to confirm) ").strip() == "YES"
        if not _confirm_action(host, confirm):
            print("Aborted.")
            return
        b = grab_banner(host, port)
        print("Banner:\n", b or "<no banner>")
    elif choice == "3":
        url = input("Target URL (include http/https) [http://127.0.0.1:8000]: ").strip() or "http://127.0.0.1:8000"
        username = input("Username to try [admin]: ").strip() or "admin"
        wordlist = input("Path to wordlist [wordlist.txt]: ").strip() or "wordlist.txt"
        threads = int(input("Threads [8]: ").strip() or "8")
        delay = float(input("Delay between attempts (s) [0]: ").strip() or "0")
        confirm = input("Confirm permission for remote host? (type YES to confirm) ").strip() == "YES"
        res = http_bruteforce(url, username, wordlist, threads=threads, delay=delay, allow_flag=confirm)
        print("Results:", res.get("success", []))
    elif choice == "4":
        host = input("Target host [127.0.0.1]: ").strip() or "127.0.0.1"
        auto = input("Use auto-ports? (y/N): ").strip().lower().startswith("y")
        topf = input("Top ports file (leave blank to skip): ").strip() or None
        ports_str = input("Ports (e.g. 1-1024) [1-1024]: ").strip() or "1-1024"
        workers = int(input("Workers [200]: ").strip() or "200")
        no_banner = input("Skip banner grab? (y/N): ").strip().lower().startswith("y")
        confirm = input("Confirm permission for remote host? (type YES to confirm) ").strip() == "YES"
        ports = choose_ports(ports_str, auto, topf)
        report = scan_all(host, ports, workers=workers, do_banner=not no_banner, allow_flag=confirm)
        if "error" in report:
            print("Error:", report["error"])
        else:
            print("Open ports:", report["open_ports"])
    else:
        print("Exit or invalid choice.")

def main():
    parser = build_cli()
    # If no args provided, enter interactive mode
    if len(sys.argv) == 1:
        interactive_menu()
        return

    args = parser.parse_args()

    if getattr(args, "cmd", None) == "portscan":
        parsed_host = args.host
        if not _confirm_action(parsed_host, args.confirm):
            sys.exit(1)
        ports = choose_ports(args.ports, args.auto_ports, getattr(args, "top_ports_file", None))
        start = time.time()
        results = port_scan(parsed_host, ports, timeout=args.timeout, workers=args.workers)
        elapsed = time.time() - start
        open_ports = [p for p, s in results.items() if s == "open"]
        print(f"[+] Scan complete in {elapsed:.2f}s — open ports: {open_ports}")
        out = {"host": parsed_host, "ports_scanned": len(ports), "results": results, "open_ports": open_ports, "elapsed": elapsed}
        if getattr(args, "output", None):
            save_json_report(args.output, out)
        else:
            print(json.dumps(out, indent=2))

    elif getattr(args, "cmd", None) == "banner":
        host = args.host
        port = args.port
        if not _confirm_action(host, args.confirm):
            sys.exit(1)
        b = grab_banner(host, port, timeout=args.timeout)
        print(f"Banner for {host}:{port}:\n{b or '<no banner>'}")
        if args.output:
            save_json_report(args.output, {"host": host, "port": port, "banner": b})

    elif getattr(args, "cmd", None) == "http-brute":
        parsed = urlparse(args.url)
        host = parsed.hostname or ""
        if not _confirm_action(host, args.confirm):
            sys.exit(1)
        print(f"[*] Starting HTTP brute-force against {args.url} with user '{args.username}'")
        res = http_bruteforce(args.url, args.username, args.wordlist, threads=args.threads,
                             timeout=args.timeout, delay=args.delay, allow_flag=True)
        print("[*] Results:", res.get("success", []))
        if args.output:
            save_json_report(args.output, {"target": args.url, "username": args.username, "success": res.get("success", [])})

    elif getattr(args, "cmd", None) == "scan-all":
        host = args.host
        if not _confirm_action(host, args.confirm):
            sys.exit(1)
        ports = choose_ports(args.ports, args.auto_ports, getattr(args, "top_ports_file", None))
        report = scan_all(host, ports, timeout=args.timeout, workers=args.workers, do_banner=not args.no_banner, allow_flag=True)
        if "error" in report:
            print("[!] ", report["error"])
            sys.exit(1)
        print(f"[+] scan-all finished: open ports = {report['open_ports']}")
        if args.output:
            save_json_report(args.output, report)
        else:
            print(json.dumps(report, indent=2))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
