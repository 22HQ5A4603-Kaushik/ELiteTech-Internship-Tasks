#!/usr/bin/env python3
# file: web_vuln_scanner.py
"""
Task-2: Web application vulnerability scanner (educational, non-destructive).

Usage examples:
  # Non-interactive (preferred)
  python web_vuln_scanner.py https://example.local/page?item=1 --confirm --debug

  # Interactive: paste URL + flags at the prompt
  python web_vuln_scanner.py
  Enter target (you may paste flags): https://example.local/page?item=1 --confirm --debug

Notes:
 - This tool is intentionally conservative: defaults target localhost and require --confirm for remote hosts.
 - For legal/ethical reasons, do NOT scan public sites without explicit written permission.
"""
from __future__ import annotations
import argparse
import shlex
import time
import json
import sys
import signal
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup

# --- Configuration (safe defaults) ---
DEFAULT_TIMEOUT = 8
DEFAULT_MAX_REQUESTS = 200
DEFAULT_DELAY = 0.2
SAFE_SQLI_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 -- "]
SAFE_XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
SQL_ERROR_KEYWORDS = [
    "sql syntax", "mysql", "syntax error", "unterminated string", "sqlite",
    "microsoft oledb", "ora-", "syntax error at or near", "pg_query", "sqlstate",
    "you have an error in your sql syntax"
]
LOCALHOST_SET = {"localhost", "127.0.0.1", "::1"}


# --- Utilities ---
def is_localhost_host(hostname: Optional[str]) -> bool:
    return (hostname or "").lower() in LOCALHOST_SET


def normalize_url(raw: str) -> str:
    p = urlparse(raw)
    if not p.scheme:  # add http if missing
        return "http://" + raw
    return raw


def detect_sql_error(text: str) -> Optional[str]:
    low = (text or "").lower()
    for kw in SQL_ERROR_KEYWORDS:
        if kw in low:
            return kw
    return None


def evidence_snippet(text: str, needle: str, ctx: int = 60) -> str:
    if not text or not needle:
        return ""
    idx = text.find(needle)
    if idx == -1:
        return ""
    start = max(0, idx - ctx)
    end = min(len(text), idx + len(needle) + ctx)
    return text[start:end].replace("\n", " ")


# --- Scanner implementation ---
class WebVulnScanner:
    def __init__(
        self,
        base_url: str,
        timeout: int = DEFAULT_TIMEOUT,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        delay: float = DEFAULT_DELAY,
        user_agent: str = "WebVulnScanner/1.0",
        verify_ssl: bool = True,
        retries: int = 1,
        backoff: float = 0.5,
        proxies: Optional[Dict[str, str]] = None,
        debug: bool = False,
    ):
        self.base_url = base_url
        self.timeout = timeout
        self.max_requests = max_requests
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.session.verify = verify_ssl
        if proxies:
            self.session.proxies.update(proxies)
        self.requests_sent = 0
        self.findings: List[Dict[str, Any]] = []
        self.debug = debug
        self.retries = max(1, int(retries))
        self.backoff = backoff
        self.last_error: Optional[str] = None

    def _log(self, *args):
        if self.debug:
            print("[DEBUG]", *args)

    def _request_with_retries(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        if self.requests_sent >= self.max_requests:
            self._log("max_requests reached")
            self.last_error = "max_requests reached"
            return None
        attempt = 0
        while attempt < self.retries:
            try:
                self._log(f"{method.upper()} attempt {attempt+1}/{self.retries} -> {url}")
                if method.lower() == "get":
                    r = self.session.get(url, timeout=self.timeout, allow_redirects=True, **kwargs)
                else:
                    r = self.session.post(url, timeout=self.timeout, allow_redirects=True, **kwargs)
                self.requests_sent += 1
                time.sleep(self.delay)
                self._log("status", r.status_code)
                self.last_error = None
                return r
            except RequestException as e:
                attempt += 1
                t = f"{type(e).__name__}: {e}"
                self.last_error = t
                self._log("request failed:", t)
                if attempt < self.retries:
                    sleep_for = self.backoff * (2 ** (attempt - 1))
                    self._log(f"retry in {sleep_for}s")
                    time.sleep(sleep_for)
                else:
                    self._log("retries exhausted")
                    return None
        return None

    def _send_get(self, url: str) -> Optional[requests.Response]:
        return self._request_with_retries("get", url)

    def _send_post(self, url: str, data: Dict[str, str]) -> Optional[requests.Response]:
        return self._request_with_retries("post", url, data=data)

    def _test_query_params(self, resp: requests.Response):
        parsed = urlparse(resp.url)
        qs = parse_qs(parsed.query)
        if not qs:
            return
        for param in qs.keys():
            for payload in (SAFE_SQLI_PAYLOADS + SAFE_XSS_PAYLOADS):
                if self.requests_sent >= self.max_requests:
                    return
                new_q = {k: (payload if k == param else (v[0] if isinstance(v, list) else v)) for k, v in qs.items()}
                new_query = urlencode(new_q, doseq=False)
                mod_url = urlunparse(parsed._replace(query=new_query))
                r = self._send_get(mod_url)
                if not r:
                    continue
                body = r.text or ""
                if detect_sql_error(body):
                    kw = detect_sql_error(body)
                    self.findings.append({
                        "type": "sqli",
                        "vector": "param",
                        "param": param,
                        "payload": payload,
                        "url": mod_url,
                        "evidence": kw,
                        "status_code": r.status_code
                    })
                if payload in body:
                    self.findings.append({
                        "type": "xss",
                        "vector": "param",
                        "param": param,
                        "payload": payload,
                        "url": mod_url,
                        "evidence": evidence_snippet(body, payload),
                        "status_code": r.status_code
                    })

    def _test_forms(self, resp: requests.Response):
        try:
            soup = BeautifulSoup(resp.text or "", "html.parser")
        except Exception:
            return
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action") or resp.url
            method = (form.get("method") or "get").lower()
            inputs = form.find_all(["input", "textarea", "select"])
            names: List[str] = []
            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                typ = (inp.get("type") or "").lower()
                if typ in ("submit", "button", "image"):
                    continue
                names.append(name)
            if not names:
                continue
            full_action = requests.compat.urljoin(resp.url, action)
            for payload in (SAFE_SQLI_PAYLOADS + SAFE_XSS_PAYLOADS):
                if self.requests_sent >= self.max_requests:
                    return
                data = {n: payload for n in names}
                if method == "post":
                    r = self._send_post(full_action, data)
                else:
                    url_with_q = full_action + ("?" + urlencode(data) if data else "")
                    r = self._send_get(url_with_q)
                if not r:
                    continue
                body = r.text or ""
                if detect_sql_error(body):
                    kw = detect_sql_error(body)
                    self.findings.append({
                        "type": "sqli",
                        "vector": "form",
                        "action": full_action,
                        "payload": payload,
                        "evidence": kw,
                        "status_code": r.status_code
                    })
                if payload in body:
                    self.findings.append({
                        "type": "xss",
                        "vector": "form",
                        "action": full_action,
                        "payload": payload,
                        "evidence": evidence_snippet(body, payload),
                        "status_code": r.status_code
                    })

    def scan(self) -> Dict[str, Any]:
        resp = self._send_get(self.base_url)
        if resp is None:
            return {"error": "failed to fetch base URL or max_requests reached", "last_error": self.last_error}
        # test query params and forms
        self._test_query_params(resp)
        self._test_forms(resp)
        return {
            "target": self.base_url,
            "resolved": resp.url,
            "requests_sent": self.requests_sent,
            "findings_count": len(self.findings),
            "findings": self.findings
        }


# --- CLI & flow ---
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Basic Web Vulnerability Scanner (SQLi & XSS, educational)")
    p.add_argument("url", nargs="?", help="Target URL (include http:// or https://)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout seconds")
    p.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS, help="Maximum requests to send")
    p.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay between requests (seconds)")
    p.add_argument("--user-agent", default="WebVulnScanner/1.0", help="User-Agent header")
    p.add_argument("--save", help="Save JSON report to file")
    p.add_argument("--confirm", action="store_true", help="Confirm you have permission to test non-local targets")
    p.add_argument("--debug", action="store_true", help="Enable debug output")
    p.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification (insecure)")
    p.add_argument("--retries", type=int, default=1, help="Retry count for requests")
    p.add_argument("--backoff", type=float, default=0.5, help="Backoff base (seconds) for retries")
    p.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080) to route requests")
    p.add_argument("--yes", action="store_true", help="Do not prompt for pre-scan confirmation in interactive mode")
    return p


def handle_sigint(signum, frame):
    print("\n[!] Interrupted by user (CTRL-C). Exiting.")
    sys.exit(1)


def parse_interactive_input(raw: str) -> List[str]:
    try:
        tokens = shlex.split(raw)
    except Exception:
        tokens = raw.split()
    # if user pasted a shell command like "python web_vuln_scanner.py <url> --confirm", remove leading tokens
    # keep only tokens starting from first URL-like token or tokens that are flags
    url_index = None
    for i, t in enumerate(tokens):
        if re.match(r"^https?://", t, flags=re.IGNORECASE) or re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,6}(:\d+)?(/.*)?$", t):
            url_index = i
            break
    if url_index is None:
        # no clear URL — just return tokens (argparse will report)
        return tokens
    # keep tokens from url_index onward; if tokens before url_index are options, ignore them
    return tokens[url_index:]


def main():
    signal.signal(signal.SIGINT, handle_sigint)
    parser = build_arg_parser()

    # parse CLI args or handle interactive paste
    if len(sys.argv) > 1:
        args = parser.parse_args()
    else:
        try:
            raw = input("Enter target (you may paste flags too, e.g. --confirm --debug): ").strip()
        except EOFError:
            print("[!] No input. Exiting.")
            sys.exit(1)
        if not raw:
            print("[!] No URL provided. Exiting.")
            sys.exit(1)
        tokens = parse_interactive_input(raw)
        try:
            args = parser.parse_args(tokens)
        except SystemExit:
            print("[!] Could not parse input. Example:")
            print("    https://example.local/page?item=1 --confirm --debug --retries 2")
            sys.exit(1)

    # ensure target present
    if not args.url:
        print("[!] No URL provided. Exiting.")
        sys.exit(1)

    target = normalize_url(args.url)
    parsed = urlparse(target)
    host = parsed.hostname
    if not host:
        print("[!] Could not determine hostname from URL. Exiting.")
        sys.exit(1)

    # safety guard
    if not is_localhost_host(host) and not args.confirm:
        print("WARNING: target host appears remote:", host)
        print("Remote targets require explicit confirmation. Re-run with --confirm when you have permission to test the target.")
        sys.exit(2)

    # interactive pre-scan summary and final confirm unless --yes provided
    if sys.stdin.isatty() and not args.yes:
        print("Pre-scan summary:")
        print("  Target:", target)
        print("  Max requests:", args.max_requests)
        print("  Delay (s):", args.delay)
        print("  Debug:", bool(args.debug))
        if not args.confirm:
            print("  (Local scan: confirmed implicitly)")
        if not args.yes:
            yn = input("Proceed? [y/N]: ").strip().lower()
            if yn not in ("y", "yes"):
                print("Aborted by user.")
                sys.exit(0)

    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    scanner = WebVulnScanner(
        base_url=target,
        timeout=args.timeout,
        max_requests=args.max_requests,
        delay=args.delay,
        user_agent=args.user_agent,
        verify_ssl=not args.insecure,
        retries=args.retries,
        backoff=args.backoff,
        proxies=proxies,
        debug=args.debug,
    )

    if not args.debug:
        print("[*] Starting scan:", target)
    result = scanner.scan()

    if "error" in result:
        print("[!] Error:", result["error"])
        if scanner.last_error:
            print("[!] Detailed:", scanner.last_error)
        sys.exit(1)

    # human summary
    print(f"Target: {result['target']}")
    print(f"Resolved: {result['resolved']}")
    print(f"Requests sent: {result['requests_sent']}")
    print(f"Findings: {result['findings_count']}")
    if result["findings_count"] > 0:
        print("\nDetailed findings:")
        for i, f in enumerate(result["findings"], start=1):
            typ = f.get("type", "unknown")
            vec = f.get("vector", "unknown")
            print(f"{i}. {typ.upper()} via {vec}")
            if vec == "param":
                print("   param:", f.get("param"))
                print("   url:", f.get("url"))
            if vec == "form":
                print("   action:", f.get("action"))
            print("   payload:", f.get("payload"))
            print("   status_code:", f.get("status_code"))
            print("   evidence:", (f.get("evidence") or "")[:300])
            print("-" * 60)
    else:
        print("No obvious issues found with these simple checks (not exhaustive).")

    if args.save:
        try:
            with open(args.save, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2)
            print(f"[+] JSON report saved to {args.save}")
        except Exception as e:
            print("[!] Failed to save report:", e)


if __name__ == "__main__":
    main()
