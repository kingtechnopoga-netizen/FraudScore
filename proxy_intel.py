#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║  PROXY INTELLIGENCE SUITE — Fraud Score • Rotation • Reputation   ║
║                                                                  ║
║  Author   : @astacbfw                                            ║
║  Tools    : Tools by Asta        -> https://t.me/ToolsByAsta     ║
║  Shop     : Asta Shop            -> https://t.me/+5KSKziT8millYjVh║
║                                                                  ║
║  Checks:                                                         ║
║    • IPQualityScore  — fraud score 0-100, proxy/VPN/Tor/bot      ║
║    • Scamalytics     — fraud score 0-100, proxy/VPN/Tor          ║
║    • AbuseIPDB       — abuse confidence, reports, blacklist      ║
║    • ProxyCheck.io   — risk score, proxy type (no key needed)    ║
║    • IP-API          — geo, ISP, ASN, hosting                    ║
║    • ipify            — exit IP confirmation                     ║
║                                                                  ║
║  Features:                                                       ║
║    • Validate proxy connectivity + latency                       ║
║    • Rotation testing (verifies IP changes)                      ║
║    • Anonymity classification (transparent/anonymous/elite)      ║
║    • Aggregate fraud score across all sources                    ║
║    • Blacklist detection (Spamhaus, DNSBL)                       ║
║    • Batch mode + threaded lookups                               ║
║    • JSON / CSV export                                           ║
║                                                                  ║
║  Requires : pip install requests dnspython                       ║
║  Usage    : python proxy_intel.py check 1.2.3.4:8080             ║
║             python proxy_intel.py rotate proxies.txt             ║
║             python proxy_intel.py batch proxies.txt              ║
║                                                                  ║
║  NOTE: Educational / authorized use only.                        ║
║        Only test proxies you own or have permission to use.      ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from typing import Optional

import requests
import dns.resolver
import dns.reversename
import dns.exception

# ── Attribution & Channels ─────────────────────────────────────────
AUTHOR     = "@astacbfw"
TOOLS_NAME = "Tools by Asta"
TOOLS_LINK = "https://t.me/ToolsByAsta"
SHOP_NAME  = "Asta Shop"
SHOP_LINK  = "https://t.me/+5KSKziT8millYjVh"
# ───────────────────────────────────────────────────────────────────

C = {
    "reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "orange": "\033[38;5;208m",
}
NO_COLOR = False


def col(t, c):
    if NO_COLOR or c not in C:
        return t
    return f"{C[c]}{t}{C['reset']}"


def banner(mode=""):
    if NO_COLOR:
        print("PROXY INTELLIGENCE SUITE")
        print(f"by {AUTHOR}")
        print(f"Tools -> {TOOLS_LINK}")
        print(f"Shop  -> {SHOP_LINK}")
        if mode:
            print(f"Mode  -> {mode}")
        return
    print(col("┌──────────────────────────────────────────────────────────────┐", "cyan"))
    print(col("│  ", "cyan") + col("PROXY INTELLIGENCE SUITE", "bold")
          + col("                         │", "cyan"))
    print(col("│  ", "cyan") + f"by {col(AUTHOR, 'magenta')}"
          + col("                                            │", "cyan"))
    print(col("│  ", "cyan") + col(f"Tools -> {TOOLS_LINK}", "blue")
          + col("              │", "cyan"))
    print(col("│  ", "cyan") + col(f"Shop  -> {SHOP_LINK}", "green")
          + col("    │", "cyan"))
    if mode:
        print(col("│  ", "cyan") + col(f"Mode  -> {mode}", "yellow")
              + col(" " * max(0, 47 - len(mode)) + "│", "cyan"))
    print(col("└──────────────────────────────────────────────────────────────┘", "cyan"))


def print_footer():
    print()
    print(col("─" * 66, "dim"))
    print(col(f"by {AUTHOR}", "dim"))
    print(col(f"Tools -> {TOOLS_LINK}", "dim"))
    print(col(f"Shop  -> {SHOP_LINK}", "dim"))
    print()
    print(col("⚠  Only test proxies you own or have permission to use.", "yellow"))


# ══════════════════════════════════════════════════════════════════
# DATA MODEL
# ══════════════════════════════════════════════════════════════════
@dataclass
class ProxyResult:
    proxy: str
    host: str = ""
    port: int = 0
    protocol: str = "http"
    username: Optional[str] = None
    password: Optional[str] = None

    # Connectivity
    alive: bool = False
    latency_ms: float = 0.0
    exit_ip: Optional[str] = None
    error: Optional[str] = None

    # Anonymity
    anonymity: str = "unknown"          # transparent | anonymous | elite
    real_ip_leaked: bool = False

    # Geo
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    hosting: bool = False
    timezone: Optional[str] = None

    # Fraud scores
    ipqs_fraud_score: Optional[int] = None
    ipqs_proxy: Optional[bool] = None
    ipqs_vpn: Optional[bool] = None
    ipqs_tor: Optional[bool] = None
    ipqs_bot: Optional[bool] = None
    ipqs_recent_abuse: Optional[bool] = None

    scamalytics_score: Optional[int] = None
    scamalytics_risk: Optional[str] = None

    abuseipdb_score: Optional[int] = None
    abuseipdb_reports: Optional[int] = None

    proxycheck_risk: Optional[int] = None
    proxycheck_proxy: Optional[bool] = None
    proxycheck_type: Optional[str] = None

    # Composite
    composite_score: Optional[int] = None
    composite_label: Optional[str] = None

    # Blacklists
    blacklisted: bool = False
    blacklist_sources: list = field(default_factory=list)

    # Sources used
    sources_ok: list = field(default_factory=list)
    sources_failed: list = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════
# CHECKERS
# ══════════════════════════════════════════════════════════════════
class ProxyIntelligence:
    def __init__(self, timeout: float = 12.0, ipqs_key: Optional[str] = None,
                 abuseipdb_key: Optional[str] = None):
        self.timeout = timeout
        self.ipqs_key = ipqs_key or os.environ.get("IPQS_API_KEY")
        self.abuseipdb_key = abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        })
        self._real_ip = None

    # ── Get our real IP (for leak detection) ───────────────────
    def _get_real_ip(self) -> Optional[str]:
        if self._real_ip:
            return self._real_ip
        try:
            r = self.session.get("https://api.ipify.org", timeout=5)
            self._real_ip = r.text.strip()
            return self._real_ip
        except Exception:
            return None

    # ── Parse proxy string ─────────────────────────────────────
    @staticmethod
    def parse_proxy(raw: str) -> Optional[ProxyResult]:
        raw = raw.strip()
        if not raw:
            return None

        protocol = "http"
        username = password = None

        # protocol:// prefix
        m = re.match(r"^(https?|socks4|socks5)://(.+)$", raw, re.I)
        if m:
            protocol = m.group(1).lower()
            raw = m.group(2)

        # user:pass@host:port
        m = re.match(r"^([^:@]+):([^@]+)@(.+)$", raw)
        if m:
            username, password, raw = m.group(1), m.group(2), m.group(3)

        # host:port
        m = re.match(r"^([\w.\-]+):(\d+)$", raw)
        if not m:
            return None

        host = m.group(1)
        port = int(m.group(2))

        return ProxyResult(
            proxy=raw, host=host, port=port, protocol=protocol,
            username=username, password=password,
        )

    def _proxies_dict(self, p: ProxyResult) -> dict:
        auth = f"{p.username}:{p.password}@" if p.username and p.password else ""
        url = f"{p.protocol}://{auth}{p.host}:{p.port}"
        return {"http": url, "https": url}

    # ── Step 1: Connectivity + exit IP ─────────────────────────
    def _check_connectivity(self, p: ProxyResult) -> bool:
        t0 = time.perf_counter()
        try:
            r = requests.get(
                "https://api.ipify.org?format=json",
                proxies=self._proxies_dict(p),
                timeout=self.timeout, verify=False,
            )
            p.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            data = r.json()
            p.exit_ip = data.get("ip")
            p.alive = bool(p.exit_ip)
            return p.alive
        except requests.exceptions.ProxyError:
            p.error = "proxy_error"
        except requests.exceptions.ConnectTimeout:
            p.error = "connect_timeout"
        except requests.exceptions.ReadTimeout:
            p.error = "read_timeout"
        except Exception as e:
            p.error = type(e).__name__
        p.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        return False

    # ── Step 2: Anonymity classification ───────────────────────
    def _check_anonymity(self, p: ProxyResult):
        try:
            r = requests.get(
                "http://httpbin.org/get",
                proxies=self._proxies_dict(p),
                timeout=self.timeout, verify=False,
            )
            headers = {k.lower(): str(v).lower() for k, v in r.headers.items()}
            body = r.text.lower()
            real = (self._real_ip or "").lower()

            leaks = False
            for h in ("via", "x-forwarded-for", "x-real-ip", "forwarded"):
                if h in headers and real and real in headers[h]:
                    leaks = True

            if real and real in body:
                leaks = True

            p.real_ip_leaked = leaks

            any_header_leak = any(h in headers for h in
                                   ("via", "x-forwarded-for", "x-real-ip", "forwarded"))
            if leaks:
                p.anonymity = "transparent"
            elif any_header_leak:
                p.anonymity = "anonymous"
            else:
                p.anonymity = "elite"

        except Exception:
            p.anonymity = "unknown"

    # ── Step 3: Geo + ASN (IP-API) ─────────────────────────────
    def _check_geo(self, p: ProxyResult):
        if not p.exit_ip:
            return
        try:
            r = requests.get(
                f"http://ip-api.com/json/{p.exit_ip}",
                timeout=self.timeout,
                params={"fields": "status,country,countryCode,city,isp,org,as,hosting,timezone"},
            )
            data = r.json()
            if data.get("status") == "success":
                p.country = data.get("country")
                p.country_code = data.get("countryCode")
                p.city = data.get("city")
                p.isp = data.get("isp")
                p.org = data.get("org")
                p.asn = data.get("as")
                p.hosting = bool(data.get("hosting"))
                p.timezone = data.get("timezone")
        except Exception:
            pass

    # ── Step 4: IPQualityScore ─────────────────────────────────
    def _check_ipqs(self, p: ProxyResult):
        if not self.ipqs_key or not p.exit_ip:
            return
        try:
            r = requests.get(
                f"https://ipqualityscore.com/api/json/ip/{self.ipqs_key}/{p.exit_ip}",
                timeout=self.timeout,
            )
            data = r.json()
            if data.get("success"):
                p.ipqs_fraud_score = data.get("fraud_score")
                p.ipqs_proxy = data.get("proxy")
                p.ipqs_vpn = data.get("vpn")
                p.ipqs_tor = data.get("tor")
                p.ipqs_bot = data.get("bot_status")
                p.ipqs_recent_abuse = data.get("recent_abuse")
                p.sources_ok.append("ipqualityscore")
            else:
                p.sources_failed.append("ipqualityscore")
        except Exception:
            p.sources_failed.append("ipqualityscore")

    # ── Step 5: Scamalytics (web scrape — no public API key) ────
    def _check_scamalytics(self, p: ProxyResult):
        if not p.exit_ip:
            return
        try:
            r = requests.get(
                f"https://scamalytics.com/ip/{p.exit_ip}",
                timeout=self.timeout,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
                },
            )
            text = r.text
            # Score
            m = re.search(r'"score"\s*:\s*"(\d+)"', text)
            if not m:
                m = re.search(r'Fraud Score[:\s]*(\d+)', text, re.I)
            if m:
                p.scamalytics_score = int(m.group(1))

            # Risk label
            m2 = re.search(r'"risk"\s*:\s*"(\w+)"', text)
            if m2:
                p.scamalytics_risk = m2.group(1)
            else:
                if p.scamalytics_score is not None:
                    if p.scamalytics_score >= 90:
                        p.scamalytics_risk = "very high"
                    elif p.scamalytics_score >= 60:
                        p.scamalytics_risk = "high"
                    elif p.scamalytics_score >= 20:
                        p.scamalytics_risk = "medium"
                    else:
                        p.scamalytics_risk = "low"

            p.sources_ok.append("scamalytics")
        except Exception:
            p.sources_failed.append("scamalytics")

    # ── Step 6: AbuseIPDB ──────────────────────────────────────
    def _check_abuseipdb(self, p: ProxyResult):
        if not self.abuseipdb_key or not p.exit_ip:
            return
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": self.abuseipdb_key,
                    "Accept": "application/json",
                },
                params={"ipAddress": p.exit_ip, "maxAgeInDays": 90},
                timeout=self.timeout,
            )
            data = r.json()
            if "data" in data:
                p.abuseipdb_score = data["data"].get("abuseConfidenceScore")
                p.abuseipdb_reports = data["data"].get("totalReports")
                p.sources_ok.append("abuseipdb")
            else:
                p.sources_failed.append("abuseipdb")
        except Exception:
            p.sources_failed.append("abuseipdb")

    # ── Step 7: ProxyCheck.io (no key needed) ──────────────────
    def _check_proxycheck(self, p: ProxyResult):
        if not p.exit_ip:
            return
        try:
            r = requests.get(
                f"https://proxycheck.io/v2/{p.exit_ip}",
                timeout=self.timeout,
                params={"vpn": 1, "asn": 1, "risk": 1},
            )
            data = r.json()
            entry = data.get(p.exit_ip, {})
            if entry:
                p.proxycheck_proxy = entry.get("proxy") == "yes"
                p.proxycheck_type = entry.get("type")
                risk = entry.get("risk")
                if risk is not None:
                    p.proxycheck_risk = int(risk)
                p.sources_ok.append("proxycheck")
            else:
                p.sources_failed.append("proxycheck")
        except Exception:
            p.sources_failed.append("proxycheck")

    # ── Step 8: Blacklist checks (Spamhaus DNSBL) ──────────────
    def _check_blacklists(self, p: ProxyResult):
        if not p.exit_ip:
            return
        try:
            ip = ipaddress.ip_address(p.exit_ip)
            if ip.version != 4:
                return

            reversed_ip = ".".join(reversed(p.exit_ip.split(".")))
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
            resolver.timeout = 3
            resolver.lifetime = 6

            zones = {
                "zen.spamhaus.org": "Spamhaus ZEN",
                "bl.spamcop.net":   "SpamCop",
                "b.barracudacentral.org": "Barracuda",
                "dnsbl.sorbs.net":  "SORBS",
                "spam.dnsbl.sorbs.net": "SORBS Spam",
                "cbl.abuseat.org":  "CBL",
            }

            for zone, label in zones.items():
                try:
                    resolver.resolve(f"{reversed_ip}.{zone}", "A")
                    p.blacklisted = True
                    p.blacklist_sources.append(label)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.exception.Timeout, dns.resolver.NoNameservers):
                    pass
        except Exception:
            pass

    # ── Step 9: Composite score ────────────────────────────────
    def _compute_composite(self, p: ProxyResult):
        scores = []
        weights = []

        if p.ipqs_fraud_score is not None:
            scores.append(p.ipqs_fraud_score)
            weights.append(1.0)
        if p.scamalytics_score is not None:
            scores.append(p.scamalytics_score)
            weights.append(1.0)
        if p.abuseipdb_score is not None:
            scores.append(p.abuseipdb_score)
            weights.append(1.0)
        if p.proxycheck_risk is not None:
            scores.append(p.proxycheck_risk)
            weights.append(0.8)

        if not scores:
            p.composite_score = None
            p.composite_label = "unknown"
            return

        # Weighted average
        total_w = sum(weights)
        p.composite_score = round(sum(s * w for s, w in zip(scores, weights)) / total_w)

        # Adjust for flags
        bonus = 0
        if p.ipqs_proxy:
            bonus += 10
        if p.ipqs_vpn:
            bonus += 10
        if p.ipqs_tor:
            bonus += 20
        if p.ipqs_bot:
            bonus += 15
        if p.ipqs_recent_abuse:
            bonus += 10
        if p.blacklisted:
            bonus += 15
        if p.hosting:
            bonus += 5

        p.composite_score = min(100, p.composite_score + bonus)

        if p.composite_score >= 85:
            p.composite_label = "HIGH"
        elif p.composite_score >= 60:
            p.composite_label = "MEDIUM"
        elif p.composite_score >= 30:
            p.composite_label = "LOW"
        else:
            p.composite_label = "CLEAN"

    # ── Full check ─────────────────────────────────────────────
    def check(self, proxy_raw: str, full: bool = True) -> ProxyResult:
        p = self.parse_proxy(proxy_raw)
        if not p:
            return ProxyResult(proxy=proxy_raw, error="Invalid format")

        # Make sure we have our real IP for leak detection
        if full:
            self._get_real_ip()

        # Step 1: connectivity
        if not self._check_connectivity(p):
            return p

        # Steps 2-9 in parallel (all depend only on exit_ip)
        tasks = [
            self._check_anonymity,
            self._check_geo,
            self._check_ipqs,
            self._check_scamalytics,
            self._check_abuseipdb,
            self._check_proxycheck,
            self._check_blacklists,
        ]

        with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
            futures = [ex.submit(t, p) for t in tasks]
            for f in futures:
                try:
                    f.result(timeout=30)
                except Exception:
                    pass

        self._compute_composite(p)
        return p

    # ── Batch ──────────────────────────────────────────────────
    def check_many(self, proxies: list, threads: int = 10,
                   full: bool = True) -> list:
        print(col(f"[*] Checking {len(proxies)} proxy(ies) "
                  f"({threads} threads) ...", "yellow"))
        results = []
        done = 0
        t0 = time.perf_counter()

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(self.check, p, full): p for p in proxies}
            for fut in as_completed(futures):
                done += 1
                try:
                    results.append(fut.result())
                except Exception as e:
                    results.append(ProxyResult(
                        proxy=futures[fut],
                        error=f"{type(e).__name__}: {e}",
                    ))
                if done % 5 == 0 or done == len(proxies):
                    rate = done / max(0.001, time.perf_counter() - t0)
                    print(col(f"    [{done}/{len(proxies)}] "
                              f"({rate:.1f}/s)", "dim"))

        elapsed = round(time.perf_counter() - t0, 2)
        print(col(f"[✓] Done in {elapsed}s", "green"))
        return results


# ══════════════════════════════════════════════════════════════════
# ROTATION TESTER
# ══════════════════════════════════════════════════════════════════
class RotationTester:
    """
    Tests whether a rotating proxy endpoint actually rotates IPs.
    Makes N requests through the same proxy and counts distinct exit IPs.
    """

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
        self.session = requests.Session()

    def test(self, proxy_raw: str, hits: int = 10) -> dict:
        parsed = ProxyIntelligence.parse_proxy(proxy_raw)
        if not parsed:
            return {"error": "Invalid proxy format"}

        proxies = parsed.__class__(
            proxy=proxy_raw, host=parsed.host, port=parsed.port,
            protocol=parsed.protocol, username=parsed.username,
            password=parsed.password,
        )
        proxies_dict = {
            "http": f"{parsed.protocol}://{parsed.host}:{parsed.port}",
            "https": f"{parsed.protocol}://{parsed.host}:{parsed.port}",
        }

        print(col(f"[*] Making {hits} requests through rotating endpoint ...", "yellow"))

        ip_history = []
        latencies = []
        errors = 0

        for i in range(1, hits + 1):
            try:
                t0 = time.perf_counter()
                r = self.session.get(
                    "https://api.ipify.org?format=json",
                    proxies=proxies_dict,
                    timeout=self.timeout,
                )
                latency = round((time.perf_counter() - t0) * 1000, 1)
                ip = r.json().get("ip")
                ip_history.append(ip)
                latencies.append(latency)
                print(col(f"    [{i}/{hits}] {ip}  ({latency}ms)", "dim"))
            except Exception as e:
                errors += 1
                print(col(f"    [{i}/{hits}] ERROR: {type(e).__name__}", "red"))

        unique_ips = list(dict.fromkeys([ip for ip in ip_history if ip]))

        return {
            "proxy": proxy_raw,
            "hits": hits,
            "successful": len(ip_history),
            "errors": errors,
            "unique_ips": len(unique_ips),
            "ip_history": ip_history,
            "unique_ip_list": unique_ips,
            "rotating": len(unique_ips) > 1,
            "avg_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0,
            "min_latency_ms": min(latencies) if latencies else 0,
            "max_latency_ms": max(latencies) if latencies else 0,
        }


# ══════════════════════════════════════════════════════════════════
# RENDERING
# ══════════════════════════════════════════════════════════════════
RISK_COLORS = {
    "CLEAN": "green", "LOW": "green",
    "MEDIUM": "yellow", "HIGH": "red",
    "unknown": "dim",
}

ANON_COLORS = {
    "elite": "green", "anonymous": "yellow",
    "transparent": "red", "unknown": "dim",
}


def render_single(r: ProxyResult):
    print()
    print(col("━" * 66, "cyan"))
    print(col(f" {r.proxy}", "bold"))
    print(col("━" * 66, "cyan"))

    if r.error:
        print(col(f" ✗ {r.error}", "red"))
        return

    # ── Connectivity ──────────────────────────────────────────
    print()
    print(col(" 🔌 CONNECTIVITY", "bold"))
    print(col(" " + "─" * 60, "dim"))
    alive = col("✓ ALIVE", "green") if r.alive else col("✗ DEAD", "red")
    print(f"   {col('Status', 'dim'):<16} {alive}")
    if r.exit_ip:
        print(f"   {col('Exit IP', 'dim'):<16} {col(r.exit_ip, 'cyan')}")
    if r.latency_ms:
        print(f"   {col('Latency', 'dim'):<16} {col(f'{r.latency_ms}ms', 'dim')}")

    # ── Anonymity ─────────────────────────────────────────────
    print()
    print(col(" 🥷 ANONYMITY", "bold"))
    print(col(" " + "─" * 60, "dim"))
    anon_c = ANON_COLORS.get(r.anonymity, "dim")
    print(f"   {col('Class', 'dim'):<16} {col(r.anonymity.upper(), anon_c)}")
    leak = col("YES ⚠", "red") if r.real_ip_leaked else col("no", "green")
    print(f"   {col('Real IP leaked', 'dim'):<16} {leak}")

    # ── Geo ───────────────────────────────────────────────────
    if r.country:
        print()
        print(col(" 🌍 GEO", "bold"))
        print(col(" " + "─" * 60, "dim"))
        flag = ""
        if r.country_code:
            flag = "".join(chr(0x1F1E6 + ord(c) - ord("A"))
                           for c in r.country_code.upper() if c.isalpha())
        print(f"   {col('Country', 'dim'):<16} {col(r.country, 'yellow')} {flag}")
        if r.city:
            print(f"   {col('City', 'dim'):<16} {col(r.city, 'yellow')}")
        if r.isp:
            print(f"   {col('ISP', 'dim'):<16} {col(r.isp, 'magenta')}")
        if r.asn:
            print(f"   {col('ASN', 'dim'):<16} {col(r.asn, 'dim')}")
        if r.hosting is not None:
            host_type = col("datacenter", "cyan") if r.hosting else col("residential", "green")
            print(f"   {col('Type', 'dim'):<16} {host_type}")

    # ── Fraud scores ──────────────────────────────────────────
    print()
    print(col(" ⚠  FRAUD SCORES", "bold"))
    print(col(" " + "─" * 60, "dim"))

    def score_line(name, score, extra=""):
        if score is None:
            print(f"   {col(name, 'dim'):<18} {col('N/A', 'dim')}")
            return
        if score >= 85:
            c = "red"
        elif score >= 60:
            c = "yellow"
        elif score >= 30:
            c = "green"
        else:
            c = "green"
        print(f"   {col(name, 'dim'):<18} {col(f'{score}/100', c)}  {col(extra, 'dim')}")

    score_line("IPQS", r.ipqs_fraud_score)
    score_line("Scamalytics", r.scamalytics_score, r.scamalytics_risk or "")
    score_line("AbuseIPDB", r.abuseipdb_score,
               f"{r.abuseipdb_reports} reports" if r.abuseipdb_reports else "")
    score_line("ProxyCheck", r.proxycheck_risk, r.proxycheck_type or "")

    # ── Flags ─────────────────────────────────────────────────
    flags = []
    if r.ipqs_proxy:       flags.append(col("PROXY", "red"))
    if r.ipqs_vpn:         flags.append(col("VPN", "red"))
    if r.ipqs_tor:         flags.append(col("TOR", "red"))
    if r.ipqs_bot:         flags.append(col("BOT", "red"))
    if r.ipqs_recent_abuse: flags.append(col("RECENT_ABUSE", "red"))
    if r.proxycheck_proxy: flags.append(col("PROXYCHECK_FLAG", "red"))

    if flags:
        print()
        print(f"   {col('Flags', 'dim'):<18} {' '.join(flags)}")

    # ── Blacklists ────────────────────────────────────────────
    if r.blacklisted:
        print()
        print(col(" 🚫 BLACKLISTS", "bold"))
        print(col(" " + "─" * 60, "dim"))
        for b in r.blacklist_sources:
            print(col(f"   • {b}", "red"))

    # ── Composite ─────────────────────────────────────────────
    print()
    print(col(" 📊 COMPOSITE SCORE", "bold"))
    print(col(" " + "─" * 60, "dim"))

    if r.composite_score is not None:
        c = RISK_COLORS.get(r.composite_label, "dim")
        filled = int((r.composite_score / 100) * 40)
        bar = col("█" * filled, c) + col("░" * (40 - filled), "dim")
        print(f"   {col(f'{r.composite_score}/100', 'bold')}  {col(r.composite_label, c)}")
        print(f"   {bar}")
    else:
        print(col("   No scores available", "dim"))

    # ── Sources ───────────────────────────────────────────────
    print()
    print(col(" ℹ  SOURCES", "bold"))
    print(col(" " + "─" * 60, "dim"))
    print(f"   {col('Succeeded', 'dim'):<16} {', '.join(r.sources_ok) or 'none'}")
    if r.sources_failed:
        print(f"   {col('Failed', 'dim'):<16} {', '.join(r.sources_failed)}")


def render_many(results: list):
    print()
    print(col("── Bulk Results ──────────────────────────────────────────", "dim"))
    print(col(f"  {'#':<4} {'PROXY':<28} {'EXIT IP':<16} "
              f"{'ANON':<12} {'CC':<4} {'SCORE':<7} {'LABEL'}", "bold"))
    print(col("─" * 96, "dim"))

    for i, r in enumerate(results, 1):
        if r.error:
            print(f"  {i:<4} {col(r.proxy[:28], 'red'):<28} {col(r.error, 'red')}")
            continue

        anon_c = ANON_COLORS.get(r.anonymity, "dim")
        score_c = RISK_COLORS.get(r.composite_label, "dim")

        proxy_s = r.proxy[:26]
        exit_ip = r.exit_ip or "-"

        print(
            f"  {i:<4} "
            f"{col(proxy_s, 'white'):<28} "
            f"{col(exit_ip, 'cyan'):<16} "
            f"{col(r.anonymity[:10], anon_c):<12} "
            f"{col(r.country_code or '-', 'yellow'):<4} "
            f"{col(str(r.composite_score or '-'), score_c):<7} "
            f"{col(r.composite_label or '-', score_c)}"
        )


def render_rotation(data: dict):
    print()
    if "error" in data:
        print(col(f"✗ {data['error']}", "red"))
        return

    print(col("━" * 66, "cyan"))
    print(col(f" {data['proxy']}", "bold"))
    print(col("━" * 66, "cyan"))

    print()
    print(col(" 🔄 ROTATION TEST", "bold"))
    print(col(" " + "─" * 60, "dim"))
    print(f"   {col('Requests', 'dim'):<18} {data['hits']}")
    print(f"   {col('Successful', 'dim'):<18} {data['successful']}")
    print(f"   {col('Errors', 'dim'):<18} {data['errors']}")

    rotating = data['rotating']
    status = col("✓ ROTATING", "green") if rotating else col("✗ STATIC", "red")
    print(f"   {col('Behavior', 'dim'):<18} {status}")
    print(f"   {col('Unique IPs', 'dim'):<18} {data['unique_ips']} / {data['hits']}")

    print()
    print(col(" 📊 LATENCY", "bold"))
    print(col(" " + "─" * 60, "dim"))
    print(f"   {col('Average', 'dim'):<18} {data['avg_latency_ms']} ms")
    print(f"   {col('Min', 'dim'):<18} {data['min_latency_ms']} ms")
    print(f"   {col('Max', 'dim'):<18} {data['max_latency_ms']} ms")

    if data['unique_ip_list']:
        print()
        print(col(" 🌐 UNIQUE EXIT IPs", "bold"))
        print(col(" " + "─" * 60, "dim"))
        for ip in data['unique_ip_list']:
            print(f"   • {col(ip, 'cyan')}")


# ══════════════════════════════════════════════════════════════════
# EXPORT
# ══════════════════════════════════════════════════════════════════
def export_json(results: list, path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(r) for r in results], fh, indent=2)


def export_csv(results: list, path: str):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([
            "proxy", "host", "port", "protocol", "alive", "exit_ip",
            "latency_ms", "anonymity", "country", "country_code", "city",
            "isp", "asn", "hosting",
            "ipqs_fraud_score", "ipqs_proxy", "ipqs_vpn", "ipqs_tor",
            "scamalytics_score", "abuseipdb_score", "abuseipdb_reports",
            "proxycheck_risk", "proxycheck_proxy",
            "composite_score", "composite_label",
            "blacklisted", "blacklist_sources", "error",
        ])
        for r in results:
            w.writerow([
                r.proxy, r.host, r.port, r.protocol, r.alive, r.exit_ip or "",
                r.latency_ms, r.anonymity,
                r.country or "", r.country_code or "", r.city or "",
                r.isp or "", r.asn or "", r.hosting,
                r.ipqs_fraud_score if r.ipqs_fraud_score is not None else "",
                r.ipqs_proxy, r.ipqs_vpn, r.ipqs_tor,
                r.scamalytics_score if r.scamalytics_score is not None else "",
                r.abuseipdb_score if r.abuseipdb_score is not None else "",
                r.abuseipdb_reports if r.abuseipdb_reports is not None else "",
                r.proxycheck_risk if r.proxycheck_risk is not None else "",
                r.proxycheck_proxy,
                r.composite_score if r.composite_score is not None else "",
                r.composite_label or "",
                r.blacklisted, ";".join(r.blacklist_sources), r.error or "",
            ])


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════
def load_proxies(path: str) -> list:
    with open(path, "r", encoding="utf-8") as fh:
        return [ln.strip() for ln in fh
                if ln.strip() and not ln.startswith("#")]


def cmd_check(args):
    banner("CHECK")

    intel = ProxyIntelligence(
        timeout=args.timeout,
        ipqs_key=args.ipqs_key,
        abuseipdb_key=args.abuseipdb_key,
    )

    result = intel.check(args.proxy, full=True)

    if args.json:
        print(json.dumps(asdict(result), indent=2))
    else:
        render_single(result)
        print_footer()

    if args.output:
        ext = os.path.splitext(args.output)[1].lower().lstrip(".")
        if ext == "json":
            export_json([result], args.output)
        else:
            export_csv([result], args.output)
        if not args.json:
            print(col(f"[✓] Written to {args.output}", "green"))


def cmd_batch(args):
    banner("BATCH")

    if not os.path.exists(args.file):
        print(col(f"[!] File not found: {args.file}", "red"))
        sys.exit(1)

    proxies = load_proxies(args.file)
    if not proxies:
        print(col("[!] No proxies in file", "red"))
        sys.exit(1)

    print(col(f"[*] Loaded {len(proxies)} proxies", "green"))
    print()

    intel = ProxyIntelligence(
        timeout=args.timeout,
        ipqs_key=args.ipqs_key,
        abuseipdb_key=args.abuseipdb_key,
    )

    results = intel.check_many(proxies, threads=args.threads, full=True)

    # Sort: clean first, then by composite score
    results.sort(key=lambda r: (r.composite_score if r.composite_score is not None else 999))

    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        render_many(results)
        print_footer()

    if args.output:
        ext = os.path.splitext(args.output)[1].lower().lstrip(".")
        if ext == "json":
            export_json(results, args.output)
        else:
            export_csv(results, args.output)
        if not args.json:
            print(col(f"[✓] Written to {args.output}", "green"))


def cmd_rotate(args):
    banner("ROTATE")

    tester = RotationTester(timeout=args.timeout)
    data = tester.test(args.proxy, hits=args.hits)

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        render_rotation(data)
        print_footer()


def main():
    global NO_COLOR

    p = argparse.ArgumentParser(
        description=f"Proxy Intelligence Suite — by {AUTHOR}",
        epilog=f"Tools: {TOOLS_LINK}   |   Shop: {SHOP_LINK}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("--ipqs-key", default=os.environ.get("IPQS_API_KEY"),
                   help="IPQualityScore API key (or IPQS_API_KEY env var)")
    p.add_argument("--abuseipdb-key", default=os.environ.get("ABUSEIPDB_API_KEY"),
                   help="AbuseIPDB API key (or ABUSEIPDB_API_KEY env var)")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--no-color", action="store_true")

    sub = p.add_subparsers(dest="cmd")

    # check
    c = sub.add_parser("check", help="check a single proxy")
    c.add_argument("proxy", help="proxy in host:port or user:pass@host:port")
    c.add_argument("--json", action="store_true")
    c.add_argument("-o", "--output")
    c.set_defaults(func=cmd_check)

    # batch
    b = sub.add_parser("batch", help="check a file of proxies")
    b.add_argument("file", help="file with one proxy per line")
    b.add_argument("--threads", type=int, default=10)
    b.add_argument("--json", action="store_true")
    b.add_argument("-o", "--output")
    b.set_defaults(func=cmd_batch)

    # rotate
    r = sub.add_parser("rotate", help="test rotating proxy endpoint")
    r.add_argument("proxy", help="rotating proxy endpoint")
    r.add_argument("--hits", type=int, default=10)
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_rotate)

    args = p.parse_args()
    NO_COLOR = args.no_color or getattr(args, "json", False) \
               or not sys.stdout.isatty()

    if not args.cmd:
        banner()
        print()
        p.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()